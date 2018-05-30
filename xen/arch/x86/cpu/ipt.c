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

#define EAX 0
#define ECX 1
#define EDX 2
#define EBX 3
#define CPUID_REGS_NUM   4 /* number of regsters (eax, ebx, ecx, edx) */

#define MSR_IA32_RTIT_STATUS_MASK (~(RTIT_STATUS_FILTER_EN | \
               RTIT_STATUS_CONTEXT_EN | RTIT_STATUS_TRIGGER_EN | \
               RTIT_STATUS_ERROR | RTIT_STATUS_STOPPED | \
               RTIT_STATUS_BYTECNT))

#define MSR_IA32_RTIT_OUTPUT_BASE_MASK(maxphyaddr) \
               (~((1UL << (maxphyaddr)) - 1) | 0x7f)

/* ipt: Flag to enable Intel Processor Trace (default off). */
unsigned int __read_mostly ipt_mode = IPT_MODE_OFF;
static int parse_ipt_params(const char *str);
custom_param("ipt", parse_ipt_params);

#define IPT_CAP(_n, _l, _r, _m)                               \
    [IPT_CAP_ ## _n] = { .name = __stringify(_n), .leaf = _l, \
        .reg = _r, .mask = _m }

static struct ipt_cap_desc {
    const char    *name;
    unsigned int  leaf;
    unsigned char reg;
    unsigned int  mask;
} ipt_caps[] = {
    IPT_CAP(max_subleaf,            0, EAX, 0xffffffff),
    IPT_CAP(cr3_filter,             0, EBX, BIT(0, UL)),
    IPT_CAP(psb_cyc,                0, EBX, BIT(1, UL)),
    IPT_CAP(ip_filter,              0, EBX, BIT(2, UL)),
    IPT_CAP(mtc,                    0, EBX, BIT(3, UL)),
    IPT_CAP(ptwrite,                0, EBX, BIT(4, UL)),
    IPT_CAP(power_event,            0, EBX, BIT(5, UL)),
    IPT_CAP(topa_output,            0, ECX, BIT(0, UL)),
    IPT_CAP(topa_multi_entry,       0, ECX, BIT(1, UL)),
    IPT_CAP(single_range_output,    0, ECX, BIT(2, UL)),
    IPT_CAP(output_subsys,          0, ECX, BIT(3, UL)),
    IPT_CAP(payloads_lip,           0, ECX, BIT(31, UL)),
    IPT_CAP(addr_range,             1, EAX, 0x7),
    IPT_CAP(mtc_period,             1, EAX, 0xffff0000),
    IPT_CAP(cycle_threshold,        1, EBX, 0xffff),
    IPT_CAP(psb_freq,               1, EBX, 0xffff0000),
};

static unsigned int ipt_cap(const struct cpuid_leaf *cpuid_ipt, enum ipt_cap cap)
{
    const struct ipt_cap_desc *cd = &ipt_caps[cap];
    unsigned int shift = ffs(cd->mask) - 1;
    unsigned int val = 0;

    cpuid_ipt += cd->leaf;

    switch ( cd->reg )
    {
    case EAX:
        val = cpuid_ipt->a;
        break;
    case EBX:
        val = cpuid_ipt->b;
        break;
    case ECX:
        val = cpuid_ipt->c;
        break;
    case EDX:
        val = cpuid_ipt->d;
        break;
    }

    return (val & cd->mask) >> shift;
}

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

static int rtit_ctl_check(uint64_t new, uint64_t old)
{
    const struct cpuid_policy *p = current->domain->arch.cpuid;
    const struct ipt_desc *ipt_desc = current->arch.hvm.vmx.ipt_desc;
    uint64_t rtit_ctl_mask = ~((uint64_t)0);
    unsigned int addr_range = ipt_cap(p->ipt.raw, IPT_CAP_addr_range);
    unsigned int val, i;

    if  ( new == old )
        return 0;

    /* Clear no dependency bits */
    rtit_ctl_mask = ~(RTIT_CTL_TRACEEN | RTIT_CTL_OS |
                RTIT_CTL_USR | RTIT_CTL_TSC_EN | RTIT_CTL_DIS_RETC);

    /* If CPUID.(EAX=14H,ECX=0):EBX[0]=1 CR3Filter can be set */
    if ( ipt_cap(p->ipt.raw, IPT_CAP_cr3_filter) )
        rtit_ctl_mask &= ~RTIT_CTL_CR3_FILTER;

    /*
     * If CPUID.(EAX=14H,ECX=0):EBX[1]=1 CYCEn, CycThresh and
     * PSBFreq can be set
     */
    if ( ipt_cap(p->ipt.raw, IPT_CAP_psb_cyc) )
        rtit_ctl_mask &= ~(RTIT_CTL_CYCEN |
                RTIT_CTL_CYC_THRESH | RTIT_CTL_PSB_FREQ);
    /*
     * If CPUID.(EAX=14H,ECX=0):EBX[3]=1 MTCEn BranchEn and
     * MTCFreq can be set
     */
    if ( ipt_cap(p->ipt.raw, IPT_CAP_mtc) )
        rtit_ctl_mask &= ~(RTIT_CTL_MTC_EN |
                RTIT_CTL_BRANCH_EN | RTIT_CTL_MTC_FREQ);

    /* If CPUID.(EAX=14H,ECX=0):EBX[4]=1 FUPonPTW and PTWEn can be set */
    if ( ipt_cap(p->ipt.raw, IPT_CAP_ptwrite) )
        rtit_ctl_mask &= ~(RTIT_CTL_FUP_ON_PTW |
                                        RTIT_CTL_PTW_EN);

    /* If CPUID.(EAX=14H,ECX=0):EBX[5]=1 PwrEvEn can be set */
    if ( ipt_cap(p->ipt.raw, IPT_CAP_power_event) )
        rtit_ctl_mask &= ~RTIT_CTL_PWR_EVT_EN;

    /* If CPUID.(EAX=14H,ECX=0):ECX[0]=1 ToPA can be set */
    if ( ipt_cap(p->ipt.raw, IPT_CAP_topa_output) )
        rtit_ctl_mask &= ~RTIT_CTL_TOPA;
    /* If CPUID.(EAX=14H,ECX=0):ECX[3]=1 FabircEn can be set */
    if ( ipt_cap(p->ipt.raw, IPT_CAP_output_subsys))
        rtit_ctl_mask &= ~RTIT_CTL_FABRIC_EN;
    /* unmask address range configure area */
    for (i = 0; i < addr_range; i++)
        rtit_ctl_mask &= ~(0xf << (32 + i * 4));

    /*
     * Any MSR write that attempts to change bits marked reserved will
     * case a #GP fault.
     */
    if ( new & rtit_ctl_mask )
        return 1;

    /*
     * Any attempt to modify IA32_RTIT_CTL while TraceEn is set will
     * result in a #GP unless the same write also clears TraceEn.
     */
    if ( (ipt_desc->ipt_guest.ctl & RTIT_CTL_TRACEEN) &&
        ((ipt_desc->ipt_guest.ctl ^ new) & ~RTIT_CTL_TRACEEN) )
        return 1;

    /*
     * WRMSR to IA32_RTIT_CTL that sets TraceEn but clears this bit
     * and FabricEn would cause #GP, if
     * CPUID.(EAX=14H, ECX=0):ECX.SNGLRGNOUT[bit 2] = 0
     */
   if ( (new & RTIT_CTL_TRACEEN) && !(new & RTIT_CTL_TOPA) &&
        !(new & RTIT_CTL_FABRIC_EN) &&
        !ipt_cap(p->ipt.raw, IPT_CAP_single_range_output) )
        return 1;
    /*
     * MTCFreq, CycThresh and PSBFreq encodings check, any MSR write that
     * utilize encodings marked reserved will casue a #GP fault.
     */
    val = ipt_cap(p->ipt.raw, IPT_CAP_mtc_period);
    if ( ipt_cap(p->ipt.raw, IPT_CAP_mtc) &&
                !test_bit((new & RTIT_CTL_MTC_FREQ) >>
                RTIT_CTL_MTC_FREQ_OFFSET, &val) )
        return 1;
    val = ipt_cap(p->ipt.raw, IPT_CAP_cycle_threshold);
    if ( ipt_cap(p->ipt.raw, IPT_CAP_psb_cyc) &&
                !test_bit((new & RTIT_CTL_CYC_THRESH) >>
                RTIT_CTL_CYC_THRESH_OFFSET, &val) )
        return 1;
    val = ipt_cap(p->ipt.raw, IPT_CAP_psb_freq);
    if ( ipt_cap(p->ipt.raw, IPT_CAP_psb_cyc) &&
                !test_bit((new & RTIT_CTL_PSB_FREQ) >>
                RTIT_CTL_PSB_FREQ_OFFSET, &val) )
        return 1;

    /*
     * If ADDRx_CFG is reserved or the encodings is >2 will
     * cause a #GP fault.
     */
    for (i = 0; i < addr_range; i++)
        if ( ((new & RTIT_CTL_ADDR(i)) >> RTIT_CTL_ADDR_OFFSET(i)) > 2 )
            return 1;

    return 0;
}

int ipt_do_rdmsr(unsigned int msr, uint64_t *msr_content)
{
    const struct ipt_desc *ipt_desc = current->arch.hvm.vmx.ipt_desc;
    const struct cpuid_policy *p = current->domain->arch.cpuid;
    unsigned int index;

    if ( !ipt_desc )
        return 1;

    switch ( msr )
    {
    case MSR_IA32_RTIT_CTL:
        *msr_content = ipt_desc->ipt_guest.ctl;
        break;
    case MSR_IA32_RTIT_STATUS:
        *msr_content = ipt_desc->ipt_guest.status;
        break;
    case MSR_IA32_RTIT_OUTPUT_BASE:
        if ( !ipt_cap(p->ipt.raw, IPT_CAP_single_range_output) &&
             !ipt_cap(p->ipt.raw, IPT_CAP_topa_output) )
            return 1;
        *msr_content = ipt_desc->ipt_guest.output_base;
        break;
    case MSR_IA32_RTIT_OUTPUT_MASK:
        if ( !ipt_cap(p->ipt.raw, IPT_CAP_single_range_output) &&
             !ipt_cap(p->ipt.raw, IPT_CAP_topa_output) )
            return 1;
        *msr_content = ipt_desc->ipt_guest.output_mask |
                                    RTIT_OUTPUT_MASK_DEFAULT;
        break;
    case MSR_IA32_RTIT_CR3_MATCH:
        if ( !ipt_cap(p->ipt.raw, IPT_CAP_cr3_filter) )
            return 1;
        *msr_content = ipt_desc->ipt_guest.cr3_match;
        break;
    default:
	index = msr - MSR_IA32_RTIT_ADDR_A(0);
        if ( index >= ipt_cap(p->ipt.raw, IPT_CAP_addr_range) * 2 )
            return 1;
        *msr_content = ipt_desc->ipt_guest.addr[index];
    }

    return 0;
}

int ipt_do_wrmsr(unsigned int msr, uint64_t msr_content)
{
    struct ipt_desc *ipt_desc = current->arch.hvm.vmx.ipt_desc;
    const struct cpuid_policy *p = current->domain->arch.cpuid;
    unsigned int index;

    if ( !ipt_desc )
        return 1;

    switch ( msr )
    {
    case MSR_IA32_RTIT_CTL:
        if ( rtit_ctl_check(msr_content, ipt_desc->ipt_guest.ctl) )
            return 1;
        ipt_desc->ipt_guest.ctl = msr_content;
        __vmwrite(GUEST_IA32_RTIT_CTL, msr_content);
        break;
    case MSR_IA32_RTIT_STATUS:
        if ( (ipt_desc->ipt_guest.ctl & RTIT_CTL_TRACEEN) ||
             (msr_content & MSR_IA32_RTIT_STATUS_MASK) )
            return 1;
        ipt_desc->ipt_guest.status = msr_content;
        break;
    case MSR_IA32_RTIT_OUTPUT_BASE:
        if ( (ipt_desc->ipt_guest.ctl & RTIT_CTL_TRACEEN) ||
             (msr_content &
                 MSR_IA32_RTIT_OUTPUT_BASE_MASK(p->extd.maxphysaddr)) ||
             (!ipt_cap(p->ipt.raw, IPT_CAP_single_range_output) &&
              !ipt_cap(p->ipt.raw, IPT_CAP_topa_output)) )
            return 1;
        ipt_desc->ipt_guest.output_base = msr_content;
        break;
    case MSR_IA32_RTIT_OUTPUT_MASK:
        if ( (ipt_desc->ipt_guest.ctl & RTIT_CTL_TRACEEN) ||
             (!ipt_cap(p->ipt.raw, IPT_CAP_single_range_output) &&
              !ipt_cap(p->ipt.raw, IPT_CAP_topa_output)) )
            return 1;
        ipt_desc->ipt_guest.output_mask = msr_content |
                                RTIT_OUTPUT_MASK_DEFAULT;
        break;
    case MSR_IA32_RTIT_CR3_MATCH:
        if ( (ipt_desc->ipt_guest.ctl & RTIT_CTL_TRACEEN) ||
             !ipt_cap(p->ipt.raw, IPT_CAP_cr3_filter) )
            return 1;
        ipt_desc->ipt_guest.cr3_match = msr_content;
        break;
    default:
        index = msr - MSR_IA32_RTIT_ADDR_A(0);
        if ( index >= ipt_cap(p->ipt.raw, IPT_CAP_addr_range) * 2 )
            return 1;
        ipt_desc->ipt_guest.addr[index] = msr_content;
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
    struct ipt_desc *ipt = v->arch.hvm.vmx.ipt_desc;

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
    struct ipt_desc *ipt = v->arch.hvm.vmx.ipt_desc;

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
         !(v->arch.hvm.vmx.secondary_exec_control & SECONDARY_EXEC_PT_USE_GPA) )
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
    v->arch.hvm.vmx.ipt_desc = ipt;

    return 0;
}

void ipt_destroy(struct vcpu *v)
{
    if ( v->arch.hvm.vmx.ipt_desc )
    {
        xfree(v->arch.hvm.vmx.ipt_desc);
        v->arch.hvm.vmx.ipt_desc = NULL;
    }
}

