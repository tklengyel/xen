/*
 * Alternate p2m
 *
 * Copyright (c) 2014, Intel Corporation.
 * Copyright (c) 2016, Sergej Proskurin <proskurin@sec.in.tum.de>.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __ASM_ARM_ALTP2M_H
#define __ASM_ARM_ALTP2M_H

#include <xen/sched.h>

#define INVALID_ALTP2M    0xffff

#define altp2m_vcpu(v)    ((v)->arch.avcpu)

#define altp2m_lock(d)    spin_lock(&(d)->arch.altp2m_lock)
#define altp2m_unlock(d)  spin_unlock(&(d)->arch.altp2m_lock)

/* Alternate p2m on/off per domain */
static inline bool_t altp2m_active(const struct domain *d)
{
    return d->arch.altp2m_active;
}

/* Alternate p2m VCPU */
static inline uint16_t altp2m_vcpu_idx(const struct vcpu *v)
{
    /* Not implemented on ARM, should not be reached. */
    BUG();
    return 0;
}

int altp2m_init(struct domain *d);
void altp2m_teardown(struct domain *d);

void altp2m_vcpu_initialise(struct vcpu *v);
void altp2m_vcpu_destroy(struct vcpu *v);

/* Get current alternate p2m table. */
struct p2m_domain *altp2m_get_altp2m(struct vcpu *v);

/* Switch alternate p2m for entire domain */
int altp2m_switch_domain_altp2m_by_id(struct domain *d,
                                      unsigned int idx);

/* Make a specific alternate p2m valid. */
int altp2m_init_by_id(struct domain *d,
                      unsigned int idx);

/* Find and initialize the next available alternate p2m. */
int altp2m_init_next_available(struct domain *d,
                               uint16_t *idx);

/* Flush all the alternate p2m's for a domain. */
void altp2m_flush(struct domain *d);

/* Make a specific alternate p2m invalid */
int altp2m_destroy_by_id(struct domain *d,
                         unsigned int idx);

#endif /* __ASM_ARM_ALTP2M_H */
