/*
 * ipt.h: Intel Processor Trace virtualization for HVM domain.
 *
 * Copyright (c) 2018, Intel Corporation.
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
 *
 * Author: Luwei Kang <luwei.kang@intel.com>
 */

#ifndef __ASM_X86_HVM_IPT_H_
#define __ASM_X86_HVM_IPT_H_

#define IPT_MODE_OFF        0
#define IPT_MODE_GUEST      (1<<0)

#define IPT_CPUID           0x00000014

#define IPT_ADDR_RANGE_MASK         0x00000007
#define RTIT_OUTPUT_MASK_DEFAULT    0x0000007f

extern unsigned int ipt_mode;

enum ipt_cap {
    IPT_CAP_max_subleaf = 0,
    IPT_CAP_cr3_filter,
    IPT_CAP_psb_cyc,
    IPT_CAP_ip_filter,
    IPT_CAP_mtc,
    IPT_CAP_ptwrite,
    IPT_CAP_power_event,
    IPT_CAP_topa_output,
    IPT_CAP_topa_multi_entry,
    IPT_CAP_single_range_output,
    IPT_CAP_output_subsys,
    IPT_CAP_payloads_lip,
    IPT_CAP_addr_range,
    IPT_CAP_mtc_period,
    IPT_CAP_cycle_threshold,
    IPT_CAP_psb_freq,
};

struct ipt_ctx {
    uint64_t ctl;
    uint64_t status;
    uint64_t output_base;
    uint64_t output_mask;
    uint64_t cr3_match;
    uint64_t addr[0];
};

struct ipt_desc {
    unsigned int addr_range;
    struct ipt_ctx ipt_guest;
};

extern int ipt_do_rdmsr(unsigned int msr, uint64_t *pdata);
extern int ipt_do_wrmsr(unsigned int msr, uint64_t data);

extern void ipt_guest_enter(struct vcpu *v);
extern void ipt_guest_exit(struct vcpu *v);

extern int ipt_initialize(struct vcpu *v);
extern void ipt_destroy(struct vcpu *v);

#endif /* __ASM_X86_HVM_IPT_H_ */
