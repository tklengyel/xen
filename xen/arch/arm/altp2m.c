/*
 * arch/arm/altp2m.c
 *
 * Alternate p2m
 * Copyright (c) 2016 Sergej Proskurin <proskurin@sec.in.tum.de>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License, version 2,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <asm/p2m.h>
#include <asm/altp2m.h>

struct p2m_domain *altp2m_get_altp2m(struct vcpu *v)
{
    unsigned int idx = v->arch.ap2m_idx;

    if ( idx == INVALID_ALTP2M )
        return NULL;

    BUG_ON(idx >= MAX_ALTP2M);

    return v->domain->arch.altp2m_p2m[idx];
}

static bool altp2m_switch_vcpu_altp2m_by_id(struct vcpu *v, unsigned int idx)
{
    struct domain *d = v->domain;
    bool rc = false;

    if ( unlikely(idx >= MAX_ALTP2M) )
        return rc;

    altp2m_lock(d);

    if ( d->arch.altp2m_p2m[idx] != NULL )
    {
        if ( idx != v->arch.ap2m_idx )
        {
            atomic_dec(&altp2m_get_altp2m(v)->active_vcpus);
            v->arch.ap2m_idx = idx;
            atomic_inc(&altp2m_get_altp2m(v)->active_vcpus);
        }
        rc = true;
    }

    altp2m_unlock(d);

    return rc;
}

void altp2m_check(struct vcpu *v, uint16_t idx)
{
    if ( altp2m_active(v->domain) )
        altp2m_switch_vcpu_altp2m_by_id(v, idx);
}

int altp2m_switch_domain_altp2m_by_id(struct domain *d, unsigned int idx)
{
    struct vcpu *v;
    int rc = -EINVAL;

    if ( idx >= MAX_ALTP2M )
        return rc;

    domain_pause_except_self(d);

    altp2m_lock(d);

    if ( d->arch.altp2m_p2m[idx] != NULL )
    {
        for_each_vcpu( d, v )
        {
            if ( idx == v->arch.ap2m_idx )
                continue;

            atomic_dec(&altp2m_get_altp2m(v)->active_vcpus);
            v->arch.ap2m_idx = idx;
            atomic_inc(&altp2m_get_altp2m(v)->active_vcpus);

            /*
             * ARM supports an external-only interface to the altp2m subsystem,
             * i.e, the guest does not have access to altp2m. Thus, we don't
             * have to consider that the current vcpu will not switch its
             * context in the function "p2m_restore_state".
             *
             * XXX: If the current guest access restriction to the altp2m
             * subsystem should change in the future, we have to update
             * VTTBR_EL2 directly.
             */
        }

        rc = 0;
    }

    altp2m_unlock(d);

    domain_unpause_except_self(d);

    return rc;
}

int altp2m_set_mem_access(struct domain *d,
                          struct p2m_domain *hp2m,
                          struct p2m_domain *ap2m,
                          p2m_access_t a,
                          gfn_t gfn)
{
    p2m_type_t p2mt;
    p2m_access_t old_a;
    mfn_t mfn, mfn_sp;
    gfn_t gfn_sp;
    unsigned int order;
    int rc;

    /* Check if entry is part of the altp2m view. */
    mfn = p2m_get_entry(ap2m, gfn, &p2mt, NULL, &order);

    /* Check host p2m if no valid entry in ap2m. */
    if ( mfn_eq(mfn, INVALID_MFN) )
    {
        /* Check if entry is part of the host p2m view. */
        mfn = p2m_get_entry(hp2m, gfn, &p2mt, &old_a, &order);
        if ( mfn_eq(mfn, INVALID_MFN) )
            return -ESRCH;

        /* If this is a superpage, copy that first. */
        if ( order != THIRD_ORDER )
        {
            /* Align the gfn and mfn to the given pager order. */
            gfn_sp = _gfn(gfn_x(gfn) & ~((1UL << order) - 1));
            mfn_sp = _mfn(mfn_x(mfn) & ~((1UL << order) - 1));

            rc = p2m_set_entry(ap2m, gfn_sp, (1UL << order), mfn_sp, p2mt, old_a);
            if ( rc )
                return rc;
        }
    }

    /* Align the gfn and mfn to the given pager order. */
    gfn = _gfn(gfn_x(gfn) & ~((1UL << THIRD_ORDER) - 1));
    mfn = _mfn(mfn_x(mfn) & ~((1UL << THIRD_ORDER) - 1));

    rc = p2m_set_entry(ap2m, gfn, (1UL << THIRD_ORDER), mfn, p2mt, a);

    return rc;
}

/*
 * The function altp2m_lazy_copy returns "false" on error.  The return value
 * "true" signals that either the mapping has been successfully lazy-copied
 * from the hostp2m to the currently active altp2m view or that the altp2m view
 * holds already a valid mapping. The latter is the case if multiple vcpus
 * using the same altp2m view generate a translation fault that is led back in
 * both cases to the same mapping and the first fault has been already handled.
 */
bool altp2m_lazy_copy(struct vcpu *v, gfn_t gfn)
{
    struct domain *d = v->domain;
    struct p2m_domain *hp2m = p2m_get_hostp2m(d), *ap2m = NULL;
    p2m_type_t p2mt;
    p2m_access_t p2ma;
    mfn_t mfn;
    unsigned int page_order;
    int rc;

    ap2m = altp2m_get_altp2m(v);
    if ( unlikely(!ap2m) )
        return false;

    /*
     * Lock hp2m to prevent the hostp2m to change a mapping before it is added
     * to the altp2m view.
     */
    p2m_read_lock(hp2m);
    p2m_write_lock(ap2m);

    /* Check if entry is part of the altp2m view. */
    mfn = p2m_get_entry(ap2m, gfn, NULL, NULL, NULL);

    /*
     * If multiple vcpus are using the same altp2m, it is likely that both
     * generate a translation fault, whereas the first one will be handled
     * successfully and the second will encounter a valid mapping that has
     * already been added as a result of the previous translation fault. In
     * this case, the 2nd vcpu needs to retry accessing the faulting address.
     */
    if ( !mfn_eq(mfn, INVALID_MFN) )
        goto out;

    /* Check if entry is part of the host p2m view. */
    mfn = p2m_get_entry(hp2m, gfn, &p2mt, &p2ma, &page_order);
    if ( mfn_eq(mfn, INVALID_MFN) )
        goto out;

    /* Align the gfn and mfn to the given pager order. */
    gfn = _gfn(gfn_x(gfn) & ~((1UL << page_order) - 1));
    mfn = _mfn(mfn_x(mfn) & ~((1UL << page_order) - 1));

    rc = p2m_set_entry(ap2m, gfn, (1UL << page_order), mfn, p2mt, p2ma);
    if ( rc )
    {
        gdprintk(XENLOG_ERR, "altp2m[%u] failed to set entry for %#"PRI_gfn" -> %#"PRI_mfn"\n",
                 v->arch.ap2m_idx, gfn_x(gfn), mfn_x(mfn));
        domain_crash(d);
    }

out:
    p2m_write_unlock(ap2m);
    p2m_read_unlock(hp2m);

    return true;
}

static inline void altp2m_reset(struct p2m_domain *p2m)
{
    p2m_write_lock(p2m);
    p2m_flush_table(p2m);
    p2m_write_unlock(p2m);
}

int altp2m_propagate_change(struct domain *d,
                            gfn_t sgfn,
                            unsigned int page_order,
                            mfn_t smfn,
                            p2m_type_t p2mt,
                            p2m_access_t p2ma)
{
    int rc = 0;
    unsigned int i;
    unsigned int reset_count = 0;
    unsigned int last_reset_idx = ~0;
    struct p2m_domain *p2m;
    mfn_t m;

    altp2m_lock(d);

    if ( !altp2m_active(d) )
        goto out;

    for ( i = 0; i < MAX_ALTP2M; i++ )
    {
        p2m = d->arch.altp2m_p2m[i];

        if ( p2m == NULL )
            continue;

        /*
         * Get the altp2m mapping. If the smfn has not been dropped, a valid
         * altp2m mapping needs to be changed/modified accordingly.
         */
        p2m_read_lock(p2m);
        m = p2m_get_entry(p2m, sgfn, NULL, NULL, NULL);
        p2m_read_unlock(p2m);

        /* Check for a dropped page that may impact this altp2m. */
        if ( mfn_eq(smfn, INVALID_MFN) &&
             (gfn_x(sgfn) >= gfn_x(p2m->lowest_mapped_gfn)) &&
             (gfn_x(sgfn) <= gfn_x(p2m->max_mapped_gfn)) )
        {
            if ( !reset_count++ )
            {
                altp2m_reset(p2m);
                last_reset_idx = i;
            }
            else
            {
                /* At least 2 altp2m's impacted, so reset everything. */
                for ( i = 0; i < MAX_ALTP2M; i++ )
                {
                    p2m = d->arch.altp2m_p2m[i];

                    if ( i == last_reset_idx || p2m == NULL )
                        continue;

                    altp2m_reset(p2m);
                }
                goto out;
            }
        }
        else if ( !mfn_eq(m, INVALID_MFN) )
        {
            /* Align the gfn and mfn to the given pager order. */
            sgfn = _gfn(gfn_x(sgfn) & ~((1UL << page_order) - 1));
            smfn = _mfn(mfn_x(smfn) & ~((1UL << page_order) - 1));

            p2m_write_lock(p2m);
            rc = p2m_set_entry(p2m, sgfn, (1UL << page_order), smfn, p2mt, p2ma);
            p2m_write_unlock(p2m);
        }
    }

out:
    altp2m_unlock(d);

    return rc;
}

static void altp2m_vcpu_reset(struct vcpu *v)
{
    v->arch.ap2m_idx = INVALID_ALTP2M;
}

void altp2m_vcpu_initialize(struct vcpu *v)
{
    /*
     * ARM supports an external-only interface to the altp2m subsystem, i.e.,
     * the guest does not have access to the altp2m subsystem. Thus, we can
     * simply pause the vcpu, as there is no scenario in which we initialize
     * altp2m on the current vcpu. That is, the vcpu must be paused every time
     * we initialize altp2m.
     */
    vcpu_pause(v);

    v->arch.ap2m_idx = 0;
    atomic_inc(&altp2m_get_altp2m(v)->active_vcpus);

    vcpu_unpause(v);
}

void altp2m_vcpu_destroy(struct vcpu *v)
{
    struct p2m_domain *p2m;

    if ( v != current )
        vcpu_pause(v);

    if ( (p2m = altp2m_get_altp2m(v)) )
        atomic_dec(&p2m->active_vcpus);

    altp2m_vcpu_reset(v);

    if ( v != current )
        vcpu_unpause(v);
}

static int altp2m_init_helper(struct domain *d, unsigned int idx)
{
    int rc;
    struct p2m_domain *p2m = d->arch.altp2m_p2m[idx];

    ASSERT(p2m == NULL);

    /* Allocate a new, zeroed altp2m view. */
    p2m = xzalloc(struct p2m_domain);
    if ( p2m == NULL)
        return -ENOMEM;

    p2m->p2m_class = p2m_alternate;

    /* Initialize the new altp2m view. */
    rc = p2m_init_one(d, p2m);
    if ( rc )
        goto err;

    d->arch.altp2m_p2m[idx] = p2m;

    return rc;

err:
    xfree(p2m);
    d->arch.altp2m_p2m[idx] = NULL;

    return rc;
}

int altp2m_init_by_id(struct domain *d, unsigned int idx)
{
    int rc = -EINVAL;

    if ( idx >= MAX_ALTP2M )
        return rc;

    altp2m_lock(d);

    if ( d->arch.altp2m_p2m[idx] == NULL )
        rc = altp2m_init_helper(d, idx);

    altp2m_unlock(d);

    return rc;
}

int altp2m_init_next_available(struct domain *d, uint16_t *idx)
{
    int rc = -EINVAL;
    uint16_t i;

    altp2m_lock(d);

    for ( i = 0; i < MAX_ALTP2M; i++ )
    {
        if ( d->arch.altp2m_p2m[i] != NULL )
            continue;

        rc = altp2m_init_helper(d, i);
        *idx = i;

        break;
    }

    altp2m_unlock(d);

    return rc;
}

int altp2m_init(struct domain *d)
{
    spin_lock_init(&d->arch.altp2m_lock);
    d->arch.altp2m_active = false;

    return 0;
}

void altp2m_flush_complete(struct domain *d)
{
    unsigned int i;
    struct p2m_domain *p2m;

    /*
     * If altp2m is active, we are not allowed to flush altp2m[0]. This special
     * view is considered as the hostp2m as long as altp2m is active.
     */
    ASSERT(!altp2m_active(d));

    altp2m_lock(d);

    for ( i = 0; i < MAX_ALTP2M; i++ )
    {
        p2m = d->arch.altp2m_p2m[i];

        if ( p2m == NULL )
            continue;

        ASSERT(!atomic_read(&p2m->active_vcpus));

        /* We do not need to lock the p2m, as altp2m is inactive. */
        p2m_teardown_one(p2m);

        xfree(p2m);
        d->arch.altp2m_p2m[i] = NULL;
    }

    altp2m_unlock(d);
}

int altp2m_destroy_by_id(struct domain *d, unsigned int idx)
{
    struct p2m_domain *p2m;
    int rc = -EBUSY;

    /*
     * The altp2m[0] is considered as the hostp2m and is used as a safe harbor
     * to which you can switch as long as altp2m is active. After deactivating
     * altp2m, the system switches back to the original hostp2m view. That is,
     * altp2m[0] should only be destroyed/flushed/freed, when altp2m is
     * deactivated.
     */
    if ( !idx || idx >= MAX_ALTP2M )
        return rc;

    domain_pause_except_self(d);

    altp2m_lock(d);

    if ( d->arch.altp2m_p2m[idx] != NULL )
    {
        p2m = d->arch.altp2m_p2m[idx];

        if ( !_atomic_read(p2m->active_vcpus) )
        {
            p2m_teardown_one(p2m);
            xfree(p2m);
            d->arch.altp2m_p2m[idx] = NULL;
            rc = 0;
        }
    }

    altp2m_unlock(d);

    domain_unpause_except_self(d);

    return rc;
}

void altp2m_teardown(struct domain *d)
{
    unsigned int i;
    struct p2m_domain *p2m;

    for ( i = 0; i < MAX_ALTP2M; i++ )
    {
        p2m = d->arch.altp2m_p2m[i];

        if ( !p2m )
            continue;

        p2m_teardown_one(p2m);
        xfree(p2m);
    }
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
