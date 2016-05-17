/*
 * include/asm-arm/hvm/hvm.h
 *
 * Copyright (c) 2005, Sergej Proskurin <proskurin@sec.in.tum.de>
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

#ifndef __ASM_ARM_HVM_HVM_H__
#define __ASM_ARM_HVM_HVM_H__

struct vttbr_data {
    union {
        struct {
            u64 vttbr_baddr :40, /* variable res0: from 0-(x-1) bit */
                res1        :8,
                vttbr_vmid  :8,
                res2        :8;
        };
        u64 vttbr;
    };
    /* TODO: Do we need an "invalidate" set of PCPUs? */
};

struct hvm_function_table {
    char *name;

    /* Necessary hardware support for alternate p2m's? */
    bool_t altp2m_supported;
};

extern struct hvm_function_table hvm_funcs;

/* returns true if hardware supports alternate p2m's */
static inline bool_t hvm_altp2m_supported(void)
{
    return hvm_funcs.altp2m_supported;
}

#endif /* __ASM_ARM_HVM_HVM_H__ */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
