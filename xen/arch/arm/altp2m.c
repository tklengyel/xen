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
    unsigned int index = altp2m_vcpu(v).p2midx;

    if ( index == INVALID_ALTP2M )
        return NULL;

    BUG_ON(index >= MAX_ALTP2M);

    return v->domain->arch.altp2m_p2m[index];
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
            if ( idx != altp2m_vcpu(v).p2midx )
            {
                atomic_dec(&altp2m_get_altp2m(v)->active_vcpus);
                altp2m_vcpu(v).p2midx = idx;
                atomic_inc(&altp2m_get_altp2m(v)->active_vcpus);

                /*
                 * In case it is the guest domain, which indirectly called this
                 * function, the current vcpu will not switch its context
                 * within the function "p2m_restore_state". That is, changing
                 * the altp2m_vcpu(v).p2midx will not lead to the requested
                 * altp2m switch on that specific vcpu. To achieve the desired
                 * behavior, we write to VTTBR_EL2 directly.
                 */
                if ( v->domain == d && v == current )
                {
                    struct p2m_domain *ap2m = d->arch.altp2m_p2m[idx];

                    WRITE_SYSREG64(ap2m->vttbr, VTTBR_EL2);
                    isb();
                }
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
    mfn_t mfn;
    unsigned int page_order;
    int rc;

    altp2m_lock(d);
    p2m_read_lock(hp2m);

    /* Check if entry is part of the altp2m view. */
    mfn = p2m_lookup_attr(ap2m, gfn, &p2mt, NULL, &page_order);

    /* Check host p2m if no valid entry in ap2m. */
    if ( mfn_eq(mfn, INVALID_MFN) )
    {
        /* Check if entry is part of the host p2m view. */
        mfn = p2m_lookup_attr(hp2m, gfn, &p2mt, &old_a, &page_order);
        if ( mfn_eq(mfn, INVALID_MFN) ||
             ((p2mt != p2m_ram_rw) && (p2mt != p2m_ram_ro)) )
        {
            rc = -ESRCH;
            goto out;
        }

        /* If this is a superpage, copy that first. */
        if ( page_order != THIRD_ORDER )
        {
            rc = modify_altp2m_entry(ap2m, gfn, mfn, p2mt, old_a, page_order);
            if ( rc < 0 )
            {
                rc = -ESRCH;
                goto out;
            }
        }
    }

    /* Set mem access attributes - currently supporting only one (4K) page. */
    page_order = THIRD_ORDER;
    rc = modify_altp2m_entry(ap2m, gfn, mfn, p2mt, a, page_order);

out:
    p2m_read_unlock(hp2m);
    altp2m_unlock(d);

    return rc;
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
        if ( d->arch.altp2m_p2m[i] == NULL )
            continue;

        p2m = d->arch.altp2m_p2m[i];

        /*
         * Get the altp2m mapping. If the smfn has not been dropped, a valid
         * altp2m mapping needs to be changed/modified accordingly.
         */
        m = p2m_lookup_attr(p2m, sgfn, NULL, NULL, NULL);

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
                    if ( i == last_reset_idx ||
                         d->arch.altp2m_p2m[i] == NULL )
                        continue;

                    p2m = d->arch.altp2m_p2m[i];
                    altp2m_reset(p2m);
                }
                goto out;
            }
        }
        else if ( !mfn_eq(m, INVALID_MFN) )
            rc = modify_altp2m_entry(p2m, sgfn, smfn, p2mt, p2ma, page_order);
    }

out:
    altp2m_unlock(d);

    return rc;
}

static void altp2m_vcpu_reset(struct vcpu *v)
{
    struct altp2mvcpu *av = &altp2m_vcpu(v);

    av->p2midx = INVALID_ALTP2M;
}

void altp2m_vcpu_initialise(struct vcpu *v)
{
    if ( v != current )
        vcpu_pause(v);

    altp2m_vcpu(v).p2midx = 0;
    atomic_inc(&altp2m_get_altp2m(v)->active_vcpus);

    if ( v != current )
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
    {
        rc = -ENOMEM;
        goto err;
    }

    p2m->p2m_class = p2m_alternate;

    /* Initialize the new altp2m view. */
    rc = p2m_init_one(d, p2m);
    if ( rc )
        goto err;

    p2m->access_required = false;
    _atomic_set(&p2m->active_vcpus, 0);

    d->arch.altp2m_p2m[idx] = p2m;

    return rc;

err:
    if ( p2m )
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
    unsigned int i;

    spin_lock_init(&d->arch.altp2m_lock);

    for ( i = 0; i < MAX_ALTP2M; i++ )
        d->arch.altp2m_p2m[i] = NULL;

    d->arch.altp2m_active = false;

    return 0;
}

void altp2m_flush(struct domain *d)
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
        if ( d->arch.altp2m_p2m[i] == NULL )
            continue;

        p2m = d->arch.altp2m_p2m[i];

        p2m_write_lock(p2m);
        p2m_teardown_one(p2m);
        p2m_write_unlock(p2m);

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
            p2m_write_lock(p2m);
            p2m_teardown_one(p2m);
            p2m_write_unlock(p2m);

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
        if ( !d->arch.altp2m_p2m[i] )
            continue;

        p2m = d->arch.altp2m_p2m[i];
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
