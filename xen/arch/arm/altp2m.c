/*
 * arch/arm/altp2m.c
 *
 * Alternate p2m HVM on ARM
 * Copyright (c) 2016 Sergej Proskurin (proskurin@sec.in.tum.de)
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
#include <asm/hvm/hvm.h>

void altp2m_vcpu_reset(struct vcpu *v)
{
    struct altp2mvcpu *av = &vcpu_altp2m(v);

    av->p2midx = INVALID_ALTP2M;
}

void altp2m_vcpu_initialise(struct vcpu *v)
{
    if ( v != current )
        vcpu_pause(v);

    altp2m_vcpu_reset(v);
    vcpu_altp2m(v).p2midx = 0;
    atomic_inc(&p2m_get_altp2m(v)->active_vcpus);

    if ( v != current )
        vcpu_unpause(v);
}

void altp2m_vcpu_destroy(struct vcpu *v)
{
    struct p2m_domain *p2m;

    if ( v != current )
        vcpu_pause(v);

    if ( (p2m = p2m_get_altp2m(v)) )
        atomic_dec(&p2m->active_vcpus);

    altp2m_vcpu_reset(v);

    if ( v != current )
        vcpu_unpause(v);
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
