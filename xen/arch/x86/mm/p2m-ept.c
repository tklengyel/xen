/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * ept-p2m.c: use the EPT page table as p2m
 * Copyright (c) 2007, Intel Corporation.
 */

#include <xen/domain_page.h>
#include <xen/sched.h>
#include <public/hvm/dm_op.h>
#include <asm/altp2m.h>
#include <asm/current.h>
#include <asm/iocap.h>
#include <asm/paging.h>
#include <asm/domain.h>
#include <asm/p2m.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>
#include <asm/hvm/nestedhvm.h>
#include <xen/iommu.h>
#include <asm/mtrr.h>
#include <asm/hvm/cacheattr.h>
#include <xen/keyhandler.h>
#include <xen/softirq.h>

#include "mm-locks.h"
#include "p2m.h"

#define atomic_read_ept_entry(__pepte)                              \
    ( (ept_entry_t) { .epte = read_atomic(&(__pepte)->epte) } )

#define is_epte_present(ept_entry)      ((ept_entry)->epte & 0x7)
#define is_epte_superpage(ept_entry)    ((ept_entry)->sp)
static inline bool_t is_epte_valid(ept_entry_t *e)
{
    /* suppress_ve alone is not considered valid, so mask it off */
    return ((e->epte & ~(1ul << 63)) != 0 && e->sa_p2mt != p2m_invalid);
}

/* returns : 0 for success, -errno otherwise */
static int atomic_write_ept_entry(struct p2m_domain *p2m,
                                  ept_entry_t *entryptr, ept_entry_t new,
                                  int level)
{
    int rc = p2m_entry_modify(p2m, new.sa_p2mt, entryptr->sa_p2mt,
                              _mfn(new.mfn), _mfn(entryptr->mfn), level + 1);

    if ( rc )
        return rc;

    write_atomic(&entryptr->epte, new.epte);

    /*
     * The recalc field on the EPT is used to signal either that a
     * recalculation of the EMT field is required (which doesn't effect the
     * IOMMU), or a type change. Type changes can only be between ram_rw,
     * logdirty and ioreq_server: changes to/from logdirty won't work well with
     * an IOMMU anyway, as IOMMU #PFs are not synchronous and will lead to
     * aborts, and changes to/from ioreq_server are already fully flushed
     * before returning to guest context (see
     * XEN_DMOP_map_mem_type_to_ioreq_server).
     */
    if ( !new.recalc && iommu_use_hap_pt(p2m->domain) )
        iommu_sync_cache(entryptr, sizeof(*entryptr));

    return 0;
}

static void ept_p2m_type_to_flags(const struct p2m_domain *p2m,
                                  ept_entry_t *entry)
{
    /*
     * First apply type permissions.
     *
     * A/D bits are also manually set to avoid overhead of MMU having to set
     * them later. Both A/D bits are safe to be updated directly as they are
     * ignored by processor if EPT A/D bits is not turned on.
     *
     * A bit is set for all present p2m types in middle and leaf EPT entries.
     * D bit is set for all writable types in EPT leaf entry, except for
     * log-dirty type with PML.
     */
    switch ( entry->sa_p2mt )
    {
        case p2m_invalid:
        case p2m_mmio_dm:
        case p2m_populate_on_demand:
        case p2m_ram_paging_out:
        case p2m_ram_paged:
        case p2m_ram_paging_in:
        default:
            entry->r = entry->w = entry->x = 0;
            break;
        case p2m_ram_rw:
            entry->r = entry->w = entry->x = 1;
            entry->a = entry->d = !!cpu_has_vmx_ept_ad;
            break;
        case p2m_ioreq_server:
            entry->r = 1;
            entry->w = !(p2m->ioreq.flags & XEN_DMOP_IOREQ_MEM_ACCESS_WRITE);
            entry->x = 0;
            entry->a = !!cpu_has_vmx_ept_ad;
            entry->d = entry->w && entry->a;
            break;
        case p2m_mmio_direct:
            entry->r = entry->x = 1;
            entry->w = !rangeset_contains_singleton(mmio_ro_ranges,
                                                    entry->mfn);
            ASSERT(entry->w || !is_epte_superpage(entry));
            entry->a = !!cpu_has_vmx_ept_ad;
            entry->d = entry->w && cpu_has_vmx_ept_ad;
            break;
        case p2m_ram_logdirty:
            entry->r = entry->x = 1;
            /*
             * In case of PML, we don't have to write protect 4K page, but
             * only need to clear D-bit for it, but we still need to write
             * protect super page in order to split it to 4K pages in EPT
             * violation.
             */
            if ( vmx_domain_pml_enabled(p2m->domain) &&
                 !is_epte_superpage(entry) )
                entry->w = 1;
            else
                entry->w = 0;
            entry->a = !!cpu_has_vmx_ept_ad;
            /* For both PML or non-PML cases we clear D bit anyway */
            entry->d = 0;
            break;
        case p2m_ram_ro:
        case p2m_ram_shared:
            entry->r = entry->x = 1;
            entry->w = 0;
            entry->a = !!cpu_has_vmx_ept_ad;
            entry->d = 0;
            break;
        case p2m_grant_map_rw:
        case p2m_map_foreign:
            entry->r = entry->w = 1;
            entry->x = 0;
            entry->a = entry->d = !!cpu_has_vmx_ept_ad;
            break;
        case p2m_grant_map_ro:
            entry->r = 1;
            entry->w = entry->x = 0;
            entry->a = !!cpu_has_vmx_ept_ad;
            entry->d = 0;
            break;
    }

    /* Then restrict with access permissions */
    switch ( entry->access )
    {
        case p2m_access_n:
        case p2m_access_n2rwx:
            entry->r = entry->w = entry->x = 0;
            break;
        case p2m_access_r:
            entry->w = entry->x = 0;
            break;
        case p2m_access_w:
            entry->r = entry->x = 0;
            break;
        case p2m_access_x:
            entry->r = entry->w = 0;
            break;
        case p2m_access_rx:
        case p2m_access_rx2rw:
            entry->w = 0;
            break;
        case p2m_access_wx:
            entry->r = 0;
            break;
        case p2m_access_rw:
            entry->x = 0;
            break;           
        case p2m_access_rwx:
            break;
    }
    
    /*
     * Don't create executable superpages if we need to shatter them to
     * protect against CVE-2018-12207.
     */
    if ( !p2m->domain->arch.hvm.vmx.exec_sp && is_epte_superpage(entry) )
        entry->x = 0;
}

#define GUEST_TABLE_MAP_FAILED  0
#define GUEST_TABLE_NORMAL_PAGE 1
#define GUEST_TABLE_SUPER_PAGE  2
#define GUEST_TABLE_POD_PAGE    3

/* Fill in middle level of ept table; return pointer to mapped new table. */
static ept_entry_t *ept_set_middle_entry(struct p2m_domain *p2m,
                                         ept_entry_t *ept_entry)
{
    mfn_t mfn;
    ept_entry_t *table;
    unsigned int i;

    mfn = p2m_alloc_ptp(p2m, 0);
    if ( mfn_eq(mfn, INVALID_MFN) )
        return NULL;

    table = map_domain_page(mfn);

    for ( i = 0; i < EPT_PAGETABLE_ENTRIES; i++ )
        table[i].suppress_ve = 1;

    ept_entry->epte = 0;
    ept_entry->mfn = mfn_x(mfn);
    ept_entry->access = p2m->default_access;

    ept_entry->r = ept_entry->w = ept_entry->x = 1;
    /* Manually set A bit to avoid overhead of MMU having to write it later. */
    ept_entry->a = !!cpu_has_vmx_ept_ad;

    ept_entry->suppress_ve = 1;

    return table;
}

/* free ept sub tree behind an entry */
static void ept_free_entry(struct p2m_domain *p2m, ept_entry_t *ept_entry, int level)
{
    /* End if the entry is a leaf entry. */
    if ( level == 0 || !is_epte_present(ept_entry) ||
         is_epte_superpage(ept_entry) )
        return;

    if ( level > 1 )
    {
        ept_entry_t *epte = map_domain_page(_mfn(ept_entry->mfn));
        for ( int i = 0; i < EPT_PAGETABLE_ENTRIES; i++ )
            ept_free_entry(p2m, epte + i, level - 1);
        unmap_domain_page(epte);
    }

    p2m_free_ptp(p2m, mfn_to_page(_mfn(ept_entry->mfn)));
}

static bool_t ept_split_super_page(struct p2m_domain *p2m,
                                   ept_entry_t *ept_entry,
                                   unsigned int level, unsigned int target)
{
    ept_entry_t new_ept, *table;
    uint64_t trunk;
    unsigned int i;
    bool_t rv = 1;

    /* End if the entry is a leaf entry or reaches the target level. */
    if ( level <= target )
        return 1;

    ASSERT(is_epte_superpage(ept_entry));

    table = ept_set_middle_entry(p2m, &new_ept);
    if ( !table )
        return 0;

    trunk = 1UL << ((level - 1) * EPT_TABLE_ORDER);

    for ( i = 0; i < EPT_PAGETABLE_ENTRIES; i++ )
    {
        ept_entry_t *epte = table + i;

        *epte = *ept_entry;
        epte->sp = (level > 1);
        epte->mfn += i * trunk;
        epte->snp = is_iommu_enabled(p2m->domain) && iommu_snoop;

        ept_p2m_type_to_flags(p2m, epte);

        if ( (level - 1) == target )
            continue;

        ASSERT(is_epte_superpage(epte));

        if ( !(rv = ept_split_super_page(p2m, epte, level - 1, target)) )
            break;
    }

    if ( iommu_use_hap_pt(p2m->domain) )
        iommu_sync_cache(table, EPT_PAGETABLE_ENTRIES * sizeof(ept_entry_t));

    unmap_domain_page(table);

    /* Even failed we should install the newly allocated ept page. */
    *ept_entry = new_ept;

    return rv;
}

/* Take the currently mapped table, find the corresponding gfn entry,
 * and map the next table, if available.  If the entry is empty
 * and read_only is set, 
 * Return values:
 *  GUEST_TABLE_MAP_FAILED: Failed to map.  Either read_only was set and the
 *   entry was empty, or allocating a new page failed.
 *  GUEST_TABLE_NORMAL_PAGE: next level mapped normally
 *  GUEST_TABLE_SUPER_PAGE:
 *   The next entry points to a superpage, and caller indicates
 *   that they are going to the superpage level, or are only doing
 *   a read.
 *  GUEST_TABLE_POD:
 *   The next entry is marked populate-on-demand.
 */
static int ept_next_level(struct p2m_domain *p2m, bool_t read_only,
                          ept_entry_t **table, unsigned long *gfn_remainder,
                          int next_level)
{
    ept_entry_t *ept_entry, *next = NULL, e;
    u32 shift, index;

    ASSERT(next_level);

    shift = next_level * EPT_TABLE_ORDER;

    index = *gfn_remainder >> shift;

    /* index must be falling into the page */
    ASSERT(index < EPT_PAGETABLE_ENTRIES);

    ept_entry = (*table) + index;

    /* ept_next_level() is called (sometimes) without a lock.  Read
     * the entry once, and act on the "cached" entry after that to
     * avoid races. */
    e = atomic_read_ept_entry(ept_entry);

    if ( !is_epte_present(&e) )
    {
        int rc;

        if ( p2m_is_pod(e.sa_p2mt) )
            return GUEST_TABLE_POD_PAGE;

        if ( read_only )
            return GUEST_TABLE_MAP_FAILED;

        next = ept_set_middle_entry(p2m, &e);
        if ( !next )
            return GUEST_TABLE_MAP_FAILED;

        if ( iommu_use_hap_pt(p2m->domain) )
            iommu_sync_cache(next, EPT_PAGETABLE_ENTRIES * sizeof(ept_entry_t));

        rc = atomic_write_ept_entry(p2m, ept_entry, e, next_level);
        ASSERT(rc == 0);
    }
    /* The only time sp would be set here is if we had hit a superpage */
    else if ( is_epte_superpage(&e) )
        return GUEST_TABLE_SUPER_PAGE;

    unmap_domain_page(*table);
    *table = next ?: map_domain_page(_mfn(e.mfn));
    *gfn_remainder &= (1UL << shift) - 1;
    return GUEST_TABLE_NORMAL_PAGE;
}

/*
 * Invalidate (via setting the EMT field to an invalid value) all valid
 * present entries in the given page table, optionally marking the entries
 * also for their subtrees needing P2M type re-calculation.
 */
static bool ept_invalidate_emt_subtree(struct p2m_domain *p2m, mfn_t mfn,
                                       bool recalc, unsigned int level)
{
    int rc;
    ept_entry_t *epte = map_domain_page(mfn);
    unsigned int i;
    bool changed = false;

    if ( !level )
    {
        ASSERT_UNREACHABLE();
        return false;
    }

    for ( i = 0; i < EPT_PAGETABLE_ENTRIES; i++ )
    {
        ept_entry_t e = atomic_read_ept_entry(&epte[i]);

        if ( !is_epte_valid(&e) || !is_epte_present(&e) ||
             (e.emt == MTRR_NUM_TYPES && (e.recalc || !recalc)) )
            continue;

        e.emt = MTRR_NUM_TYPES;
        if ( recalc )
            e.recalc = 1;
        rc = atomic_write_ept_entry(p2m, &epte[i], e, level - 1);
        ASSERT(rc == 0);
        changed = true;
    }

    unmap_domain_page(epte);

    return changed;
}

/*
 * Just like ept_invalidate_emt_subtree() except that
 * - not all entries at the targeted level may need processing,
 * - the re-calculation flag gets always set.
 * The passed in range is guaranteed to not cross a page (table)
 * boundary at the targeted level.
 */
static int ept_invalidate_emt_range(struct p2m_domain *p2m,
                                    unsigned int target,
                                    unsigned long first_gfn,
                                    unsigned long last_gfn)
{
    ept_entry_t *table;
    unsigned long gfn_remainder = first_gfn;
    unsigned int i, index;
    int wrc, rc = 0;

    table = map_domain_page(pagetable_get_mfn(p2m_get_pagetable(p2m)));
    for ( i = p2m->ept.wl; i > target; --i )
    {
        int ret = ept_next_level(p2m, 1, &table, &gfn_remainder, i);

        if ( ret == GUEST_TABLE_MAP_FAILED )
            goto out;
        if ( ret != GUEST_TABLE_NORMAL_PAGE )
            break;
    }

    if ( i > target )
    {
        /* We need to split the original page. */
        ept_entry_t split_ept_entry;

        index = gfn_remainder >> (i * EPT_TABLE_ORDER);
        split_ept_entry = atomic_read_ept_entry(&table[index]);
        ASSERT(is_epte_superpage(&split_ept_entry));
        if ( !ept_split_super_page(p2m, &split_ept_entry, i, target) )
        {
            ept_free_entry(p2m, &split_ept_entry, i);
            rc = -ENOMEM;
            goto out;
        }
        wrc = atomic_write_ept_entry(p2m, &table[index], split_ept_entry, i);
        ASSERT(wrc == 0);

        for ( ; i > target; --i )
            if ( ept_next_level(p2m, 1, &table, &gfn_remainder, i) !=
                 GUEST_TABLE_NORMAL_PAGE )
                break;
        /* We just installed the pages we need. */
        ASSERT(i == target);
    }

    index = gfn_remainder >> (i * EPT_TABLE_ORDER);
    i = (last_gfn >> (i * EPT_TABLE_ORDER)) & (EPT_PAGETABLE_ENTRIES - 1);
    for ( ; index <= i; ++index )
    {
        ept_entry_t e = atomic_read_ept_entry(&table[index]);

        if ( is_epte_valid(&e) && is_epte_present(&e) &&
             (e.emt != MTRR_NUM_TYPES || !e.recalc) )
        {
            e.emt = MTRR_NUM_TYPES;
            e.recalc = 1;
            wrc = atomic_write_ept_entry(p2m, &table[index], e, target);
            ASSERT(wrc == 0);
            rc = 1;
        }
    }

 out:
    unmap_domain_page(table);

    return rc;
}

int epte_get_entry_emt(struct domain *d, gfn_t gfn, mfn_t mfn,
                       unsigned int order, bool *ipat, p2m_type_t type)
{
    int gmtrr_mtype, hmtrr_mtype;
    struct vcpu *v = current;
    unsigned long i, special_pgs;

    *ipat = false;

    if ( v->domain != d )
        v = d->vcpu ? d->vcpu[0] : NULL;

    /* Mask, not add, for order so it works with INVALID_MFN on unmapping */
    if ( rangeset_overlaps_range(mmio_ro_ranges, mfn_x(mfn),
                                 mfn_x(mfn) | ((1UL << order) - 1)) )
    {
        if ( !order || rangeset_contains_range(mmio_ro_ranges, mfn_x(mfn),
                                               mfn_x(mfn) | ((1UL << order) - 1)) )
        {
            *ipat = true;
            return X86_MT_UC;
        }
        /* Force invalid memory type so resolve_misconfig() will split it */
        return -1;
    }

    if ( !mfn_valid(mfn) )
    {
        *ipat = true;
        return X86_MT_UC;
    }

    /*
     * Conditional must be kept in sync with the code in
     * {iomem,ioports}_{permit,deny}_access().
     */
    if ( type != p2m_mmio_direct && !is_iommu_enabled(d) &&
         !cache_flush_permitted(d) )
    {
        *ipat = true;
        return X86_MT_WB;
    }

    for ( special_pgs = i = 0; i < (1ul << order); i++ )
        if ( is_special_page(mfn_to_page(mfn_add(mfn, i))) )
            special_pgs++;

    if ( special_pgs )
    {
        if ( special_pgs != (1ul << order) )
            return -1;

        *ipat = true;
        return X86_MT_WB;
    }

    switch ( type )
    {
    case p2m_mmio_direct:
        return X86_MT_UC;

    case p2m_grant_map_ro:
    case p2m_grant_map_rw:
    case p2m_map_foreign:
        /*
         * Force WB type for grants and foreign pages. Those are usually mapped
         * over unpopulated physical ranges in the p2m, and those would usually
         * be UC in the MTRR state, which is unlikely to be the correct cache
         * attribute. It's also cumbersome (or even impossible) for the guest
         * to be setting the MTRR type for all those mappings as WB, as MTRR
         * ranges are finite.
         *
         * Note that on AMD we cannot force a cache attribute because of the
         * lack of ignore PAT equivalent, so the behavior here slightly
         * diverges. See p2m_type_to_flags for the AMD attributes.
         */
        *ipat = true;
        return X86_MT_WB;

    default:
        break;
    }

    gmtrr_mtype = hvm_get_mem_pinned_cacheattr(d, gfn, order);
    if ( gmtrr_mtype >= 0 )
    {
        *ipat = true;
        return gmtrr_mtype != X86_MT_UCM ? gmtrr_mtype : X86_MT_UC;
    }
    if ( gmtrr_mtype == -EADDRNOTAVAIL )
        return -1;

    gmtrr_mtype = v ? mtrr_get_type(&v->arch.hvm.mtrr,
                                    gfn_x(gfn) << PAGE_SHIFT, order)
                    : X86_MT_WB;
    hmtrr_mtype = mtrr_get_type(&mtrr_state, mfn_x(mfn) << PAGE_SHIFT,
                                order);
    if ( gmtrr_mtype < 0 || hmtrr_mtype < 0 )
        return -1;

    /* If both types match we're fine. */
    if ( likely(gmtrr_mtype == hmtrr_mtype) )
        return hmtrr_mtype;

    /* If either type is UC, we have to go with that one. */
    if ( gmtrr_mtype == X86_MT_UC ||
         hmtrr_mtype == X86_MT_UC )
        return X86_MT_UC;

    /* If either type is WB, we have to go with the other one. */
    if ( gmtrr_mtype == X86_MT_WB )
        return hmtrr_mtype;
    if ( hmtrr_mtype == X86_MT_WB )
        return gmtrr_mtype;

    /*
     * At this point we have disagreeing WC, WT, or WP types. The only
     * combination that can be cleanly resolved is WT:WP. The ones involving
     * WC need to be converted to UC, both due to the memory ordering
     * differences and because WC disallows reads to be cached (WT and WP
     * permit this), while WT and WP require writes to go straight to memory
     * (WC can buffer them).
     */
    if ( (gmtrr_mtype == X86_MT_WT &&
          hmtrr_mtype == X86_MT_WP) ||
         (gmtrr_mtype == X86_MT_WP &&
          hmtrr_mtype == X86_MT_WT) )
        return X86_MT_WP;

    return X86_MT_UC;
}

/*
 * Resolve deliberately mis-configured (EMT field set to an invalid value)
 * entries in the page table hierarchy for the given GFN:
 * - calculate the correct value for the EMT field,
 * - if marked so, re-calculate the P2M type,
 * - propagate EMT and re-calculation flag down to the next page table level
 *   for entries not involved in the translation of the given GFN.
 * Returns:
 * - negative errno values in error,
 * - zero if no adjustment was done,
 * - a positive value if at least one adjustment was done.
 */
static int cf_check resolve_misconfig(struct p2m_domain *p2m, unsigned long gfn)
{
    struct ept_data *ept = &p2m->ept;
    unsigned int level = ept->wl;
    unsigned long mfn = ept->mfn;
    ept_entry_t *epte;
    int wrc, rc = 0;

    if ( !mfn )
        return 0;

    for ( ; ; --level )
    {
        ept_entry_t e;
        unsigned int i;

        epte = map_domain_page(_mfn(mfn));
        i = (gfn >> (level * EPT_TABLE_ORDER)) & (EPT_PAGETABLE_ENTRIES - 1);
        e = atomic_read_ept_entry(&epte[i]);

        if ( level == 0 || is_epte_superpage(&e) )
        {
            bool ipat;

            if ( e.emt != MTRR_NUM_TYPES )
                break;

            if ( level == 0 )
            {
                for ( gfn -= i, i = 0; i < EPT_PAGETABLE_ENTRIES; ++i )
                {
                    p2m_type_t nt;

                    e = atomic_read_ept_entry(&epte[i]);
                    if ( e.emt == MTRR_NUM_TYPES )
                        e.emt = 0;
                    if ( !is_epte_valid(&e) || !is_epte_present(&e) )
                        continue;
                    e.emt = epte_get_entry_emt(p2m->domain, _gfn(gfn + i),
                                               _mfn(e.mfn), 0, &ipat,
                                               e.sa_p2mt);
                    e.ipat = ipat;

                    nt = p2m_recalc_type(e.recalc, e.sa_p2mt, p2m, gfn + i);
                    if ( nt != e.sa_p2mt )
                    {
                        e.sa_p2mt = nt;
                        ept_p2m_type_to_flags(p2m, &e);
                    }
                    e.recalc = 0;
                    wrc = atomic_write_ept_entry(p2m, &epte[i], e, level);
                    ASSERT(wrc == 0);
                }
            }
            else
            {
                int emt = epte_get_entry_emt(p2m->domain, _gfn(gfn),
                                             _mfn(e.mfn),
                                             level * EPT_TABLE_ORDER, &ipat,
                                             e.sa_p2mt);
                bool_t recalc = e.recalc;

                if ( recalc && p2m_is_changeable(e.sa_p2mt) )
                {
                    unsigned long mask = ~0UL << (level * EPT_TABLE_ORDER);

                    ASSERT(e.sa_p2mt != p2m_ioreq_server);
                    switch ( p2m_is_logdirty_range(p2m, gfn & mask,
                                                   gfn | ~mask) )
                    {
                    case 0:
                         e.sa_p2mt = p2m_ram_rw;
                         e.recalc = 0;
                         break;
                    case 1:
                         e.sa_p2mt = p2m_ram_logdirty;
                         e.recalc = 0;
                         break;
                    default: /* Force split. */
                         emt = -1;
                         break;
                    }
                }
                if ( unlikely(emt < 0) )
                {
                    if ( ept_split_super_page(p2m, &e, level, level - 1) )
                    {
                        wrc = atomic_write_ept_entry(p2m, &epte[i], e, level);
                        ASSERT(wrc == 0);
                        unmap_domain_page(epte);
                        mfn = e.mfn;
                        continue;
                    }
                    ept_free_entry(p2m, &e, level);
                    rc = -ENOMEM;
                    break;
                }
                e.emt = emt;
                e.ipat = ipat;
                e.recalc = 0;
                if ( recalc && p2m_is_changeable(e.sa_p2mt) )
                    ept_p2m_type_to_flags(p2m, &e);
                wrc = atomic_write_ept_entry(p2m, &epte[i], e, level);
                ASSERT(wrc == 0);
            }

            rc = 1;
            break;
        }

        if ( e.emt == MTRR_NUM_TYPES )
        {
            ASSERT(is_epte_present(&e));
            ept_invalidate_emt_subtree(p2m, _mfn(e.mfn), e.recalc, level);
            smp_wmb();
            e.emt = 0;
            e.recalc = 0;
            wrc = atomic_write_ept_entry(p2m, &epte[i], e, level);
            ASSERT(wrc == 0);
            unmap_domain_page(epte);
            rc = 1;
        }
        else if ( is_epte_present(&e) && !e.emt )
            unmap_domain_page(epte);
        else
            break;

        mfn = e.mfn;
    }

    unmap_domain_page(epte);
    if ( rc )
    {
        struct vcpu *v;

        for_each_vcpu ( p2m->domain, v )
            v->arch.hvm.vmx.ept_spurious_misconfig = 1;
    }

    return rc;
}

bool_t ept_handle_misconfig(uint64_t gpa)
{
    struct vcpu *curr = current;
    struct p2m_domain *p2m = p2m_get_hostp2m(curr->domain);
    bool_t spurious;
    int rc;

    if ( altp2m_active(curr->domain) )
        p2m = p2m_get_altp2m(curr);

    p2m_lock(p2m);

    spurious = curr->arch.hvm.vmx.ept_spurious_misconfig;
    rc = resolve_misconfig(p2m, PFN_DOWN(gpa));
    curr->arch.hvm.vmx.ept_spurious_misconfig = 0;

    p2m_unlock(p2m);

    return spurious ? (rc >= 0) : (rc > 0);
}

/*
 * ept_set_entry() computes 'need_modify_vtd_table' for itself,
 * by observing whether any gfn->mfn translations are modified.
 *
 * Returns: 0 for success, -errno for failure
 */
static int cf_check
ept_set_entry(struct p2m_domain *p2m, gfn_t gfn_, mfn_t mfn,
              unsigned int order, p2m_type_t p2mt, p2m_access_t p2ma,
              int sve)
{
    ept_entry_t *table, *ept_entry = NULL;
    unsigned long gfn = gfn_x(gfn_);
    unsigned long gfn_remainder = gfn;
    unsigned int i, target = order / EPT_TABLE_ORDER;
    unsigned long fn_mask = !mfn_eq(mfn, INVALID_MFN) ? (gfn | mfn_x(mfn)) : gfn;
    int ret, rc = 0;
    bool_t entry_written = 0;
    bool_t need_modify_vtd_table = 1;
    bool_t vtd_pte_present = 0;
    unsigned int iommu_flags = p2m_get_iommu_flags(p2mt, p2ma, mfn);
    bool_t needs_sync = 1;
    ept_entry_t old_entry = { .epte = 0 };
    ept_entry_t new_entry = { .epte = 0 };
    struct ept_data *ept = &p2m->ept;
    struct domain *d = p2m->domain;

    ASSERT(ept);

    /*
     * the caller must make sure:
     * 1. passing valid gfn and mfn at order boundary.
     * 2. gfn not exceeding guest physical address width.
     * 3. passing a valid order.
     */
    if ( (fn_mask & ((1UL << order) - 1)) ||
         ((u64)gfn >> ((ept->wl + 1) * EPT_TABLE_ORDER)) ||
         (order % EPT_TABLE_ORDER) )
        return -EINVAL;

    /* Carry out any eventually pending earlier changes first. */
    ret = resolve_misconfig(p2m, gfn);
    if ( ret < 0 )
        return ret;

    ASSERT((target == 2 && hap_has_1gb) ||
           (target == 1 && hap_has_2mb) ||
           (target == 0));
    ASSERT(!p2m_is_foreign(p2mt) || target == 0);

    table = map_domain_page(pagetable_get_mfn(p2m_get_pagetable(p2m)));

    ret = GUEST_TABLE_MAP_FAILED;
    for ( i = ept->wl; i > target; i-- )
    {
        ret = ept_next_level(p2m, 0, &table, &gfn_remainder, i);
        if ( ret == GUEST_TABLE_MAP_FAILED )
        {
            rc = -ENOMEM;
            goto out;
        }
        if ( ret != GUEST_TABLE_NORMAL_PAGE )
            break;
    }

    ASSERT(ret != GUEST_TABLE_POD_PAGE || i != target);

    ept_entry = table + (gfn_remainder >> (i * EPT_TABLE_ORDER));

    /* In case VT-d uses same page table, this flag is needed by VT-d */ 
    vtd_pte_present = is_epte_present(ept_entry);

    /*
     * If we're here with i > target, we must be at a leaf node, and
     * we need to break up the superpage.
     *
     * If we're here with i == target and i > 0, we need to check to see
     * if we're replacing a non-leaf entry (i.e., pointing to an N-1 table)
     * with a leaf entry (a 1GiB or 2MiB page), and handle things appropriately.
     */

    if ( i == target )
    {
        /* We reached the target level. */

        /* No need to flush if the old entry wasn't valid */
        if ( !is_epte_present(ept_entry) )
            needs_sync = 0;

        /* If we're replacing a non-leaf entry with a leaf entry (1GiB or 2MiB),
         * the intermediate tables will be freed below after the ept flush
         *
         * Read-then-write is OK because we hold the p2m lock. */
        old_entry = *ept_entry;
    }
    else
    {
        /* We need to split the original page. */
        ept_entry_t split_ept_entry;

        ASSERT(is_epte_superpage(ept_entry));

        split_ept_entry = atomic_read_ept_entry(ept_entry);

        if ( !ept_split_super_page(p2m, &split_ept_entry, i, target) )
        {
            ept_free_entry(p2m, &split_ept_entry, i);
            rc = -ENOMEM;
            goto out;
        }

        /* now install the newly split ept sub-tree */
        /* NB: please make sure domian is paused and no in-fly VT-d DMA. */
        rc = atomic_write_ept_entry(p2m, ept_entry, split_ept_entry, i);
        ASSERT(rc == 0);

        /* then move to the level we want to make real changes */
        for ( ; i > target; i-- )
            if ( ept_next_level(p2m, 0, &table, &gfn_remainder, i) !=
                 GUEST_TABLE_NORMAL_PAGE )
                break;
        /* We just installed the pages we need. */
        ASSERT(i == target);

        ept_entry = table + (gfn_remainder >> (i * EPT_TABLE_ORDER));
    }

    if ( mfn_valid(mfn) || p2m_allows_invalid_mfn(p2mt) )
    {
        bool ipat;
        int emt = epte_get_entry_emt(p2m->domain, _gfn(gfn), mfn,
                                     i * EPT_TABLE_ORDER, &ipat,
                                     p2mt);

        if ( emt >= 0 )
            new_entry.emt = emt;
        else /* ept_handle_misconfig() will need to take care of this. */
            new_entry.emt = MTRR_NUM_TYPES;

        new_entry.ipat = ipat;
        new_entry.sp = !!i;
        new_entry.sa_p2mt = p2mt;
        new_entry.access = p2ma;
        new_entry.snp = is_iommu_enabled(d) && iommu_snoop;

        /* the caller should take care of the previous page */
        new_entry.mfn = mfn_x(mfn);

        /* Safe to read-then-write because we hold the p2m lock */
        if ( ept_entry->mfn == new_entry.mfn &&
             p2m_get_iommu_flags(ept_entry->sa_p2mt, ept_entry->access,
                                 _mfn(ept_entry->mfn)) == iommu_flags )
            need_modify_vtd_table = 0;

        ept_p2m_type_to_flags(p2m, &new_entry);
    }

    if ( sve != -1 )
        new_entry.suppress_ve = !!sve;
    else
        new_entry.suppress_ve = is_epte_valid(&old_entry) ?
                                    old_entry.suppress_ve : 1;

    rc = atomic_write_ept_entry(p2m, ept_entry, new_entry, target);
    if ( unlikely(rc) )
        old_entry.epte = 0;
    else
    {
        entry_written = 1;

        if ( p2mt != p2m_invalid &&
             (gfn + (1UL << order) - 1 > p2m->max_mapped_pfn) )
            /* Track the highest gfn for which we have ever had a valid mapping */
            p2m->max_mapped_pfn = gfn + (1UL << order) - 1;
    }

out:
    if ( needs_sync )
        ept_sync_domain(p2m);

    /* For host p2m, may need to change VT-d page table.*/
    if ( rc == 0 && p2m_is_hostp2m(p2m) &&
         need_modify_vtd_table )
    {
        if ( iommu_use_hap_pt(d) && !this_cpu(iommu_dont_flush_iotlb) )
            rc = iommu_iotlb_flush(d, _dfn(gfn), 1ul << order,
                                   (iommu_flags ? IOMMU_FLUSHF_added : 0) |
                                   (vtd_pte_present ? IOMMU_FLUSHF_modified
                                                    : 0));
        else if ( need_iommu_pt_sync(d) )
            rc = iommu_flags ?
                iommu_legacy_map(d, _dfn(gfn), mfn, 1ul << order, iommu_flags) :
                iommu_legacy_unmap(d, _dfn(gfn), 1ul << order);
    }

    unmap_domain_page(table);

    /* Release the old intermediate tables, if any.  This has to be the
       last thing we do, after the ept_sync_domain() and removal
       from the iommu tables, so as to avoid a potential
       use-after-free. */
    if ( is_epte_present(&old_entry) )
        ept_free_entry(p2m, &old_entry, target);

    if ( entry_written && p2m_is_hostp2m(p2m) )
    {
        ret = p2m_altp2m_propagate_change(d, _gfn(gfn), mfn, order, p2mt, p2ma);
        if ( !rc )
            rc = ret;
    }

    return rc;
}

/* Read ept p2m entries */
static mfn_t cf_check ept_get_entry(
    struct p2m_domain *p2m, gfn_t gfn_, p2m_type_t *t, p2m_access_t *a,
    p2m_query_t q, unsigned int *page_order, bool *sve)
{
    ept_entry_t *table =
        map_domain_page(pagetable_get_mfn(p2m_get_pagetable(p2m)));
    unsigned long gfn = gfn_x(gfn_);
    unsigned long gfn_remainder = gfn;
    ept_entry_t *ept_entry;
    u32 index;
    int i;
    bool_t recalc = 0;
    mfn_t mfn = INVALID_MFN;
    struct ept_data *ept = &p2m->ept;

    *t = p2m_mmio_dm;
    *a = p2m_access_n;
    if ( sve )
        *sve = 1;

    /* This pfn is higher than the highest the p2m map currently holds */
    if ( gfn > p2m->max_mapped_pfn )
    {
        for ( i = ept->wl; i > 0; --i )
            if ( (gfn & ~((1UL << (i * EPT_TABLE_ORDER)) - 1)) >
                 p2m->max_mapped_pfn )
                break;
        goto out;
    }

    /* Should check if gfn obeys GAW here. */

    for ( i = ept->wl; i > 0; i-- )
    {
        int ret;

    retry:
        if ( table[gfn_remainder >> (i * EPT_TABLE_ORDER)].recalc )
            recalc = 1;
        ret = ept_next_level(p2m, 1, &table, &gfn_remainder, i);
        if ( ret == GUEST_TABLE_MAP_FAILED )
            goto out;
        if ( ret == GUEST_TABLE_POD_PAGE )
        {
            if ( !(q & P2M_ALLOC) )
            {
                *t = p2m_populate_on_demand;
                goto out;
            }

            /* Populate this superpage */
            ASSERT(i <= 2);

            index = gfn_remainder >> ( i * EPT_TABLE_ORDER);
            ept_entry = table + index;

            if ( p2m_pod_demand_populate(p2m, gfn_, i * EPT_TABLE_ORDER) )
                goto retry;
            goto out;
        }
        if ( ret == GUEST_TABLE_SUPER_PAGE )
            break;
    }

    index = gfn_remainder >> (i * EPT_TABLE_ORDER);
    ept_entry = table + index;

    if ( p2m_is_pod(ept_entry->sa_p2mt) )
    {
        if ( !(q & P2M_ALLOC) )
        {
            *t = p2m_populate_on_demand;
            goto out;
        }

        ASSERT(i == 0);
        
        if ( !p2m_pod_demand_populate(p2m, gfn_, PAGE_ORDER_4K) )
            goto out;
    }

    if ( is_epte_valid(ept_entry) )
    {
        *t = p2m_recalc_type(recalc || ept_entry->recalc,
                             ept_entry->sa_p2mt, p2m, gfn);
        *a = ept_entry->access;
        if ( sve )
            *sve = ept_entry->suppress_ve;

        mfn = _mfn(ept_entry->mfn);
        if ( i )
        {
            /* 
             * We may meet super pages, and to split into 4k pages
             * to emulate p2m table
             */
            unsigned long split_mfn = mfn_x(mfn) +
                (gfn_remainder &
                 ((1 << (i * EPT_TABLE_ORDER)) - 1));
            mfn = _mfn(split_mfn);
        }
    }

 out:
    if ( page_order )
        *page_order = i * EPT_TABLE_ORDER;

    unmap_domain_page(table);
    return mfn;
}

void ept_walk_table(struct domain *d, unsigned long gfn)
{
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    struct ept_data *ept = &p2m->ept;
    ept_entry_t *table =
        map_domain_page(pagetable_get_mfn(p2m_get_pagetable(p2m)));
    unsigned long gfn_remainder = gfn;

    int i;

    gprintk(XENLOG_ERR, "Walking EPT tables for GFN %lx:\n", gfn);

    /* This pfn is higher than the highest the p2m map currently holds */
    if ( gfn > p2m->max_mapped_pfn )
    {
        gprintk(XENLOG_ERR, " gfn exceeds max_mapped_pfn %lx\n",
                p2m->max_mapped_pfn);
        goto out;
    }

    for ( i = ept->wl; i >= 0; i-- )
    {
        ept_entry_t *ept_entry, *next;
        u32 index;

        /* Stolen from ept_next_level */
        index = gfn_remainder >> (i*EPT_TABLE_ORDER);
        ept_entry = table + index;

        gprintk(XENLOG_ERR, " epte %"PRIx64"\n", ept_entry->epte);

        if ( (i == 0) || !is_epte_present(ept_entry) ||
             is_epte_superpage(ept_entry) )
            goto out;
        else
        {
            gfn_remainder &= (1UL << (i*EPT_TABLE_ORDER)) - 1;

            next = map_domain_page(_mfn(ept_entry->mfn));

            unmap_domain_page(table);

            table = next;
        }
    }

out:
    unmap_domain_page(table);
    return;
}

static void cf_check ept_change_entry_type_global(
    struct p2m_domain *p2m, p2m_type_t ot, p2m_type_t nt)
{
    unsigned long mfn = p2m->ept.mfn;

    if ( !mfn )
        return;

    if ( ept_invalidate_emt_subtree(p2m, _mfn(mfn), 1, p2m->ept.wl) )
        ept_sync_domain(p2m);
}

static int cf_check ept_change_entry_type_range(
    struct p2m_domain *p2m, p2m_type_t ot, p2m_type_t nt,
    unsigned long first_gfn, unsigned long last_gfn)
{
    unsigned int i, wl = p2m->ept.wl;
    unsigned long mask = (1 << EPT_TABLE_ORDER) - 1;
    int rc = 0, sync = 0;

    if ( !p2m->ept.mfn )
        return -EINVAL;

    for ( i = 0; i <= wl; )
    {
        if ( first_gfn & mask )
        {
            unsigned long end_gfn = min(first_gfn | mask, last_gfn);

            rc = ept_invalidate_emt_range(p2m, i, first_gfn, end_gfn);
            sync |= rc;
            if ( rc < 0 || end_gfn >= last_gfn )
                break;
            first_gfn = end_gfn + 1;
        }
        else if ( (last_gfn & mask) != mask )
        {
            unsigned long start_gfn = max(first_gfn, last_gfn & ~mask);

            rc = ept_invalidate_emt_range(p2m, i, start_gfn, last_gfn);
            sync |= rc;
            if ( rc < 0 || start_gfn <= first_gfn )
                break;
            last_gfn = start_gfn - 1;
        }
        else
        {
            ++i;
            mask |= mask << EPT_TABLE_ORDER;
        }
    }

    if ( sync )
        ept_sync_domain(p2m);

    return rc < 0 ? rc : 0;
}

static void cf_check ept_memory_type_changed(struct p2m_domain *p2m)
{
    unsigned long mfn = p2m->ept.mfn;

    if ( !mfn )
        return;

    if ( ept_invalidate_emt_subtree(p2m, _mfn(mfn), 0, p2m->ept.wl) )
        ept_sync_domain(p2m);
}

static void ept_sync_domain_prepare(struct p2m_domain *p2m)
{
    struct domain *d = p2m->domain;
    struct ept_data *ept = &p2m->ept;

    if ( nestedhvm_enabled(d) )
    {
        if ( p2m_is_nestedp2m(p2m) )
            ept = &p2m_get_hostp2m(d)->ept;
        else if ( !p2m->defer_nested_flush )
            p2m_flush_nestedp2m(d);
    }

    /*
     * Need to invalidate on all PCPUs because either:
     *
     * a) A VCPU has run and some translations may be cached.
     * b) A VCPU has not run and and the initial invalidation in case
     *    of an EP4TA reuse is still needed.
     */
    cpumask_setall(ept->invalidate);
}

static void ept_sync_domain_mask(struct p2m_domain *p2m, const cpumask_t *mask)
{
    /* Invalidation will be done in vmx_vmenter_helper(). */
    on_selected_cpus(mask, NULL, NULL, 1);
}

void ept_sync_domain(struct p2m_domain *p2m)
{
    struct domain *d = p2m->domain;

    /* Only if using EPT and this domain has some VCPUs to dirty. */
    if ( !paging_mode_hap(d) || !d->vcpu || !d->vcpu[0] )
        return;

    ept_sync_domain_prepare(p2m);

    if ( p2m->defer_flush )
    {
        p2m->need_flush = 1;
        return;
    }

    ept_sync_domain_mask(p2m, d->dirty_cpumask);
}

static void cf_check ept_tlb_flush(struct p2m_domain *p2m)
{
    ept_sync_domain_mask(p2m, p2m->domain->dirty_cpumask);
}

static void ept_set_ad_sync(struct domain *d, bool value)
{
    struct p2m_domain *hostp2m = p2m_get_hostp2m(d);

    ASSERT(p2m_locked_by_me(hostp2m));

    hostp2m->ept.ad = value;

    if ( unlikely(altp2m_active(d)) )
    {
        unsigned int i;

        for ( i = 0; i < MAX_ALTP2M; i++ )
        {
            struct p2m_domain *p2m;

            if ( d->arch.altp2m_eptp[i] == mfn_x(INVALID_MFN) )
                continue;

            p2m = d->arch.altp2m_p2m[i];

            p2m_lock(p2m);
            p2m->ept.ad = value;
            p2m_unlock(p2m);
        }
    }
}

static void ept_enable_pml(struct p2m_domain *p2m)
{
    /* Domain must have been paused */
    ASSERT(atomic_read(&p2m->domain->pause_count));

    /*
     * No need to return whether vmx_domain_enable_pml has succeeded, as
     * ept_p2m_type_to_flags will do the check, and write protection will be
     * used if PML is not enabled.
     */
    if ( vmx_domain_enable_pml(p2m->domain) )
        return;

    /* Enable EPT A/D bit for PML */
    ept_set_ad_sync(p2m->domain, true);
    vmx_domain_update_eptp(p2m->domain);
}

static void ept_disable_pml(struct p2m_domain *p2m)
{
    /* Domain must have been paused */
    ASSERT(atomic_read(&p2m->domain->pause_count));

    vmx_domain_disable_pml(p2m->domain);

    /* Disable EPT A/D bit */
    ept_set_ad_sync(p2m->domain, false);
    vmx_domain_update_eptp(p2m->domain);
}

static void cf_check ept_enable_hardware_log_dirty(struct p2m_domain *p2m)
{
    struct p2m_domain *hostp2m = p2m_get_hostp2m(p2m->domain);

    p2m_lock(hostp2m);
    ept_enable_pml(hostp2m);
    p2m_unlock(hostp2m);
}

static void cf_check ept_disable_hardware_log_dirty(struct p2m_domain *p2m)
{
    struct p2m_domain *hostp2m = p2m_get_hostp2m(p2m->domain);

    p2m_lock(hostp2m);
    ept_disable_pml(hostp2m);
    p2m_unlock(hostp2m);
}

static void cf_check ept_flush_pml_buffers(struct p2m_domain *p2m)
{
    /* Domain must have been paused */
    ASSERT(atomic_read(&p2m->domain->pause_count));

    vmx_domain_flush_pml_buffers(p2m->domain);
}

#ifdef CONFIG_MEM_SHARING
static void cf_check ept_reset_dirty_memory(struct domain *d)
{
    /* Domain must have been paused */
    ASSERT(atomic_read(&d->pause_count));

    vmx_domain_reset_dirty_memory(d);
}
#endif

int ept_p2m_init(struct p2m_domain *p2m)
{
    struct ept_data *ept = &p2m->ept;

    p2m->set_entry = ept_set_entry;
    p2m->get_entry = ept_get_entry;
    p2m->recalc = resolve_misconfig;
    p2m->change_entry_type_global = ept_change_entry_type_global;
    p2m->change_entry_type_range = ept_change_entry_type_range;
    p2m->memory_type_changed = ept_memory_type_changed;
#if P2M_AUDIT
    p2m->audit_p2m = NULL;
#endif
    p2m->tlb_flush = ept_tlb_flush;

    /* Set the memory type used when accessing EPT paging structures. */
    ept->mt = EPT_DEFAULT_MT;

    /* set EPT page-walk length, now it's actual walk length - 1, i.e. 3 */
    ept->wl = 3;

    if ( cpu_has_vmx_pml )
    {
        p2m->enable_hardware_log_dirty = ept_enable_hardware_log_dirty;
        p2m->disable_hardware_log_dirty = ept_disable_hardware_log_dirty;
        p2m->flush_hardware_cached_dirty = ept_flush_pml_buffers;
#ifdef CONFIG_MEM_SHARING
        p2m->reset_dirty_memory = ept_reset_dirty_memory;
#endif
    }

    if ( !zalloc_cpumask_var(&ept->invalidate) )
        return -ENOMEM;

    /*
     * Assume an initial invalidation is required, in case an EP4TA is
     * reused.
     */
    cpumask_setall(ept->invalidate);

    return 0;
}

void ept_p2m_uninit(struct p2m_domain *p2m)
{
    struct ept_data *ept = &p2m->ept;
    free_cpumask_var(ept->invalidate);
}

static const char *memory_type_to_str(unsigned int x)
{
    static const char memory_types[8][3] = {
        [X86_MT_UC]      = "UC",
        [X86_MT_WC]      = "WC",
        [X86_MT_WT]      = "WT",
        [X86_MT_WP]      = "WP",
        [X86_MT_WB]      = "WB",
        [MTRR_NUM_TYPES] = "??",
    };

    ASSERT(x < ARRAY_SIZE(memory_types));
    return memory_types[x][0] ? memory_types[x] : "?";
}

static void cf_check ept_dump_p2m_table(unsigned char key)
{
    struct domain *d;
    ept_entry_t *table, *ept_entry;
    int order;
    int i;
    unsigned long gfn, gfn_remainder;
    unsigned long record_counter = 0;
    struct p2m_domain *p2m;
    struct ept_data *ept;

    rcu_read_lock(&domlist_read_lock);

    for_each_domain(d)
    {
        if ( !hap_enabled(d) )
            continue;

        p2m = p2m_get_hostp2m(d);
        ept = &p2m->ept;
        printk("\ndomain%d EPT p2m table:\n", d->domain_id);

        for ( gfn = 0; gfn <= p2m->max_mapped_pfn; gfn += 1UL << order )
        {
            char c = 0;
            int ret = GUEST_TABLE_MAP_FAILED;

            gfn_remainder = gfn;
            table = map_domain_page(pagetable_get_mfn(p2m_get_pagetable(p2m)));

            for ( i = ept->wl; i > 0; i-- )
            {
                ept_entry = table + (gfn_remainder >> (i * EPT_TABLE_ORDER));
                if ( ept_entry->emt == MTRR_NUM_TYPES )
                    c = '?';
                ret = ept_next_level(p2m, 1, &table, &gfn_remainder, i);
                if ( ret != GUEST_TABLE_NORMAL_PAGE )
                    break;
            }

            order = i * EPT_TABLE_ORDER;
            ept_entry = table + (gfn_remainder >> order);
            if ( ret != GUEST_TABLE_MAP_FAILED && is_epte_valid(ept_entry) )
            {
                if ( p2m_is_pod(ept_entry->sa_p2mt) )
                    printk("gfn: %13lx order: %2d PoD\n", gfn, order);
                else
                    printk("gfn: %13lx order: %2d mfn: %13lx %c%c%c %c%c%c\n",
                           gfn, order, ept_entry->mfn + 0UL,
                           ept_entry->r ? 'r' : ' ',
                           ept_entry->w ? 'w' : ' ',
                           ept_entry->x ? 'x' : ' ',
                           memory_type_to_str(ept_entry->emt)[0],
                           memory_type_to_str(ept_entry->emt)[1]
                           ?: ept_entry->emt + '0',
                           c ?: ept_entry->ipat ? '!' : ' ');

                if ( !(record_counter++ % 100) )
                    process_pending_softirqs();
            }
            unmap_domain_page(table);
        }
    }

    rcu_read_unlock(&domlist_read_lock);
}

void setup_ept_dump(void)
{
    register_keyhandler('D', ept_dump_p2m_table, "dump VT-x EPT tables", 0);
}

void p2m_init_altp2m_ept(struct domain *d, unsigned int i)
{
    struct p2m_domain *p2m = array_access_nospec(d->arch.altp2m_p2m, i);
    struct p2m_domain *hostp2m = p2m_get_hostp2m(d);
    struct ept_data *ept;

    p2m->ept.ad = hostp2m->ept.ad;
    ept = &p2m->ept;
    ept->mfn = pagetable_get_pfn(p2m_get_pagetable(p2m));
    d->arch.altp2m_eptp[array_index_nospec(i, MAX_EPTP)] = ept->eptp;
    d->arch.altp2m_visible_eptp[array_index_nospec(i, MAX_EPTP)] = ept->eptp;
}

unsigned int p2m_find_altp2m_by_eptp(struct domain *d, uint64_t eptp)
{
    struct p2m_domain *p2m;
    struct ept_data *ept;
    unsigned int i;

    altp2m_list_lock(d);

    for ( i = 0; i < MAX_ALTP2M; i++ )
    {
        if ( d->arch.altp2m_eptp[i] == mfn_x(INVALID_MFN) )
            continue;

        p2m = d->arch.altp2m_p2m[i];
        ept = &p2m->ept;

        if ( eptp == ept->eptp )
            goto out;
    }

    i = INVALID_ALTP2M;

 out:
    altp2m_list_unlock(d);
    return i;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
