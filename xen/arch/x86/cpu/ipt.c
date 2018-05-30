/*
 * ipt.c: Support for Intel Processor Trace Virtualization.
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
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/string.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/ipt.h>
#include <asm/msr.h>

/* ipt: Flag to enable Intel Processor Trace (default off). */
unsigned int __read_mostly ipt_mode = IPT_MODE_OFF;
static int parse_ipt_params(const char *str);
custom_param("ipt", parse_ipt_params);

static int __init parse_ipt_params(const char *str)
{
    if ( !strcmp("guest", str) )
        ipt_mode = IPT_MODE_GUEST;
    else if ( str )
    {
        printk("Unknown Intel Processor Trace mode specified: '%s'\n", str);
        return -EINVAL;
    }

    return 0;
}

static inline void ipt_load_msr(const struct ipt_ctx *ctx,
                       unsigned int addr_range)
{
    unsigned int i;

    wrmsrl(MSR_IA32_RTIT_STATUS, ctx->status);
    wrmsrl(MSR_IA32_RTIT_OUTPUT_BASE, ctx->output_base);
    wrmsrl(MSR_IA32_RTIT_OUTPUT_MASK, ctx->output_mask);
    wrmsrl(MSR_IA32_RTIT_CR3_MATCH, ctx->cr3_match);
    for ( i = 0; i < addr_range; i++ )
    {
        wrmsrl(MSR_IA32_RTIT_ADDR_A(i), ctx->addr[i * 2]);
        wrmsrl(MSR_IA32_RTIT_ADDR_B(i), ctx->addr[i * 2 + 1]);
    }
}

static inline void ipt_save_msr(struct ipt_ctx *ctx, unsigned int addr_range)
{
    unsigned int i;

    rdmsrl(MSR_IA32_RTIT_STATUS, ctx->status);
    rdmsrl(MSR_IA32_RTIT_OUTPUT_BASE, ctx->output_base);
    rdmsrl(MSR_IA32_RTIT_OUTPUT_MASK, ctx->output_mask);
    rdmsrl(MSR_IA32_RTIT_CR3_MATCH, ctx->cr3_match);
    for ( i = 0; i < addr_range; i++ )
    {
        rdmsrl(MSR_IA32_RTIT_ADDR_A(i), ctx->addr[i * 2]);
        rdmsrl(MSR_IA32_RTIT_ADDR_B(i), ctx->addr[i * 2 + 1]);
    }
}

void ipt_guest_enter(struct vcpu *v)
{
    struct ipt_desc *ipt = v->arch.hvm_vmx.ipt_desc;

    if ( !ipt )
        return;

    /*
     * Need re-initialize the guest state of IA32_RTIT_CTL
     * When this vcpu be scheduled to another Physical CPU.
     * TBD: Performance optimization. Add a new item in
     * struct ipt_desc to record the last pcpu, and check
     * if this vcpu is scheduled to another pcpu here (like vpmu).
     */
    vmx_vmcs_enter(v);
    __vmwrite(GUEST_IA32_RTIT_CTL, ipt->ipt_guest.ctl);
    vmx_vmcs_exit(v);

    if ( ipt->ipt_guest.ctl & RTIT_CTL_TRACEEN )
        ipt_load_msr(&ipt->ipt_guest, ipt->addr_range);
}

void ipt_guest_exit(struct vcpu *v)
{
    struct ipt_desc *ipt = v->arch.hvm_vmx.ipt_desc;

    if ( !ipt )
        return;

    if ( ipt->ipt_guest.ctl & RTIT_CTL_TRACEEN )
        ipt_save_msr(&ipt->ipt_guest, ipt->addr_range);
}

int ipt_initialize(struct vcpu *v)
{
    struct ipt_desc *ipt = NULL;
    unsigned int eax, tmp, addr_range;

    if ( !cpu_has_ipt || (ipt_mode == IPT_MODE_OFF) ||
         !(v->arch.hvm_vmx.secondary_exec_control & SECONDARY_EXEC_PT_USE_GPA) )
        return 0;

    if ( cpuid_eax(IPT_CPUID) == 0 )
        return -EINVAL;

    cpuid_count(IPT_CPUID, 1, &eax, &tmp, &tmp, &tmp);
    addr_range = eax & IPT_ADDR_RANGE_MASK;
    ipt = _xzalloc(sizeof(struct ipt_desc) + sizeof(uint64_t) * addr_range * 2,
			__alignof(*ipt));
    if ( !ipt )
        return -ENOMEM;

    ipt->addr_range = addr_range;
    ipt->ipt_guest.output_mask = RTIT_OUTPUT_MASK_DEFAULT;
    v->arch.hvm_vmx.ipt_desc = ipt;

    return 0;
}

void ipt_destroy(struct vcpu *v)
{
    if ( v->arch.hvm_vmx.ipt_desc )
    {
        xfree(v->arch.hvm_vmx.ipt_desc);
        v->arch.hvm_vmx.ipt_desc = NULL;
    }
}
