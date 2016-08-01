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
