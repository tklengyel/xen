/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * vpmu_intel.c: CORE 2 specific PMU virtualization.
 *
 * Copyright (c) 2007, Intel Corporation.
 *
 * Author: Haitao Shan <haitao.shan@intel.com>
 */

#include <xen/err.h>
#include <xen/sched.h>
#include <xen/xenoprof.h>
#include <asm/system.h>
#include <asm/regs.h>
#include <asm/apic.h>
#include <asm/traps.h>
#include <asm/msr.h>
#include <asm/msr-index.h>
#include <asm/vpmu.h>
#include <asm/hvm/vlapic.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>
#include <public/sched.h>
#include <public/hvm/save.h>
#include <public/pmu.h>

/*
 * See Intel SDM Vol 2a Instruction Set Reference chapter 3 for CPUID
 * instruction.
 * cpuid 0xa - Architectural Performance Monitoring Leaf
 * Register eax
 */
#define PMU_VERSION_SHIFT        0  /* Version ID */
#define PMU_VERSION_BITS         8  /* 8 bits 0..7 */
#define PMU_VERSION_MASK         (((1 << PMU_VERSION_BITS) - 1) << PMU_VERSION_SHIFT)

#define PMU_GENERAL_NR_SHIFT     8  /* Number of general pmu registers */
#define PMU_GENERAL_NR_BITS      8  /* 8 bits 8..15 */
#define PMU_GENERAL_NR_MASK      (((1 << PMU_GENERAL_NR_BITS) - 1) << PMU_GENERAL_NR_SHIFT)

#define PMU_GENERAL_WIDTH_SHIFT 16  /* Width of general pmu registers */
#define PMU_GENERAL_WIDTH_BITS   8  /* 8 bits 16..23 */
#define PMU_GENERAL_WIDTH_MASK  (((1 << PMU_GENERAL_WIDTH_BITS) - 1) << PMU_GENERAL_WIDTH_SHIFT)
/* Register edx */
#define PMU_FIXED_NR_SHIFT       0  /* Number of fixed pmu registers */
#define PMU_FIXED_NR_BITS        5  /* 5 bits 0..4 */
#define PMU_FIXED_NR_MASK        (((1 << PMU_FIXED_NR_BITS) -1) << PMU_FIXED_NR_SHIFT)

#define PMU_FIXED_WIDTH_SHIFT    5  /* Width of fixed pmu registers */
#define PMU_FIXED_WIDTH_BITS     8  /* 8 bits 5..12 */
#define PMU_FIXED_WIDTH_MASK     (((1 << PMU_FIXED_WIDTH_BITS) -1) << PMU_FIXED_WIDTH_SHIFT)

/* Alias registers (0x4c1) for full-width writes to PMCs */
#define MSR_PMC_ALIAS_MASK       (~(MSR_IA32_PERFCTR0 ^ MSR_IA32_A_PERFCTR0))
static bool_t __read_mostly full_width_write;

/*
 * MSR_CORE_PERF_FIXED_CTR_CTRL contains the configuration of all fixed
 * counters. 4 bits for every counter.
 */
#define FIXED_CTR_CTRL_BITS 4
#define FIXED_CTR_CTRL_MASK ((1 << FIXED_CTR_CTRL_BITS) - 1)
#define FIXED_CTR_CTRL_ANYTHREAD_MASK 0x4

#define ARCH_CNTR_ENABLED   (1ULL << 22)
#define ARCH_CNTR_PIN_CONTROL (1ULL << 19)

/* Number of general-purpose and fixed performance counters */
static unsigned int __read_mostly arch_pmc_cnt, fixed_pmc_cnt;

/* Masks used for testing whether and MSR is valid */
#define ARCH_CTRL_MASK  (~((1ull << 32) - 1) | (1ull << 21) | ARCH_CNTR_PIN_CONTROL)
static uint64_t __read_mostly fixed_ctrl_mask, fixed_counters_mask;
static uint64_t __read_mostly global_ovf_ctrl_mask, global_ctrl_mask;

/* Total size of PMU registers block (copied to/from PV(H) guest) */
static unsigned int __read_mostly regs_sz;
/* Offset into context of the beginning of PMU register block */
static const unsigned int regs_off =
    sizeof_field(struct xen_pmu_intel_ctxt, fixed_counters) +
    sizeof_field(struct xen_pmu_intel_ctxt, arch_counters);

/*
 * QUIRK to workaround an issue on various family 6 cpus.
 * The issue leads to endless PMC interrupt loops on the processor.
 * If the interrupt handler is running and a pmc reaches the value 0, this
 * value remains forever and it triggers immediately a new interrupt after
 * finishing the handler.
 * A workaround is to read all flagged counters and if the value is 0 write
 * 1 (or another value != 0) into it.
 * There exist no errata and the real cause of this behaviour is unknown.
 */
static bool __ro_after_init pmc_quirk;

static void handle_pmc_quirk(u64 msr_content)
{
    int i;
    u64 val;

    if ( !pmc_quirk )
        return;

    val = msr_content;
    for ( i = 0; i < arch_pmc_cnt; i++ )
    {
        if ( val & 0x1 )
        {
            u64 cnt;
            rdmsrl(MSR_P6_PERFCTR(i), cnt);
            if ( cnt == 0 )
                wrmsrl(MSR_P6_PERFCTR(i), 1);
        }
        val >>= 1;
    }
    val = msr_content >> 32;
    for ( i = 0; i < fixed_pmc_cnt; i++ )
    {
        if ( val & 0x1 )
        {
            u64 cnt;
            rdmsrl(MSR_CORE_PERF_FIXED_CTR0 + i, cnt);
            if ( cnt == 0 )
                wrmsrl(MSR_CORE_PERF_FIXED_CTR0 + i, 1);
        }
        val >>= 1;
    }
}

/*
 * Read the number of general counters via CPUID.EAX[0xa].EAX[8..15]
 */
static int core2_get_arch_pmc_count(void)
{
    u32 eax;

    eax = cpuid_eax(0xa);
    return MASK_EXTR(eax, PMU_GENERAL_NR_MASK);
}

/*
 * Read the number of fixed counters via CPUID.EDX[0xa].EDX[0..4]
 */
static int core2_get_fixed_pmc_count(void)
{
    u32 edx = cpuid_edx(0xa);

    return MASK_EXTR(edx, PMU_FIXED_NR_MASK);
}

/* edx bits 5-12: Bit width of fixed-function performance counters  */
static int core2_get_bitwidth_fix_count(void)
{
    u32 edx;

    edx = cpuid_edx(0xa);
    return MASK_EXTR(edx, PMU_FIXED_WIDTH_MASK);
}

static int is_core2_vpmu_msr(u32 msr_index, int *type, int *index)
{
    u32 msr_index_pmc;

    switch ( msr_index )
    {
    case MSR_CORE_PERF_FIXED_CTR_CTRL:
    case MSR_IA32_DS_AREA:
    case MSR_IA32_PEBS_ENABLE:
        *type = MSR_TYPE_CTRL;
        return 1;

    case MSR_CORE_PERF_GLOBAL_CTRL:
    case MSR_CORE_PERF_GLOBAL_STATUS:
    case MSR_CORE_PERF_GLOBAL_OVF_CTRL:
        *type = MSR_TYPE_GLOBAL;
        return 1;

    default:

        if ( (msr_index >= MSR_CORE_PERF_FIXED_CTR0) &&
             (msr_index < MSR_CORE_PERF_FIXED_CTR0 + fixed_pmc_cnt) )
        {
            *index = msr_index - MSR_CORE_PERF_FIXED_CTR0;
            *type = MSR_TYPE_COUNTER;
            return 1;
        }

        if ( (msr_index >= MSR_P6_EVNTSEL(0)) &&
             (msr_index < MSR_P6_EVNTSEL(arch_pmc_cnt)) )
        {
            *index = msr_index - MSR_P6_EVNTSEL(0);
            *type = MSR_TYPE_ARCH_CTRL;
            return 1;
        }

        msr_index_pmc = msr_index & MSR_PMC_ALIAS_MASK;
        if ( (msr_index_pmc >= MSR_IA32_PERFCTR0) &&
             (msr_index_pmc < (MSR_IA32_PERFCTR0 + arch_pmc_cnt)) )
        {
            *type = MSR_TYPE_ARCH_COUNTER;
            *index = msr_index_pmc - MSR_IA32_PERFCTR0;
            return 1;
        }
        return 0;
    }
}

static void core2_vpmu_set_msr_bitmap(struct vcpu *v)
{
    unsigned int i;

    /* Allow Read/Write PMU Counters MSR Directly. */
    for ( i = 0; i < fixed_pmc_cnt; i++ )
        vmx_clear_msr_intercept(v, MSR_CORE_PERF_FIXED_CTR0 + i, VMX_MSR_RW);

    for ( i = 0; i < arch_pmc_cnt; i++ )
    {
        vmx_clear_msr_intercept(v, MSR_IA32_PERFCTR0 + i, VMX_MSR_RW);

        if ( full_width_write )
            vmx_clear_msr_intercept(v, MSR_IA32_A_PERFCTR0 + i, VMX_MSR_RW);
    }

    /* Allow Read PMU Non-global Controls Directly. */
    for ( i = 0; i < arch_pmc_cnt; i++ )
        vmx_clear_msr_intercept(v, MSR_P6_EVNTSEL(i), VMX_MSR_R);

    vmx_clear_msr_intercept(v, MSR_CORE_PERF_FIXED_CTR_CTRL, VMX_MSR_R);
    vmx_clear_msr_intercept(v, MSR_IA32_DS_AREA, VMX_MSR_R);
}

static void core2_vpmu_unset_msr_bitmap(struct vcpu *v)
{
    unsigned int i;

    for ( i = 0; i < fixed_pmc_cnt; i++ )
        vmx_set_msr_intercept(v, MSR_CORE_PERF_FIXED_CTR0 + i, VMX_MSR_RW);

    for ( i = 0; i < arch_pmc_cnt; i++ )
    {
        vmx_set_msr_intercept(v, MSR_IA32_PERFCTR0 + i, VMX_MSR_RW);

        if ( full_width_write )
            vmx_set_msr_intercept(v, MSR_IA32_A_PERFCTR0 + i, VMX_MSR_RW);
    }

    for ( i = 0; i < arch_pmc_cnt; i++ )
        vmx_set_msr_intercept(v, MSR_P6_EVNTSEL(i), VMX_MSR_R);

    vmx_set_msr_intercept(v, MSR_CORE_PERF_FIXED_CTR_CTRL, VMX_MSR_R);
    vmx_set_msr_intercept(v, MSR_IA32_DS_AREA, VMX_MSR_R);
}

static inline void __core2_vpmu_save(struct vcpu *v)
{
    int i;
    struct xen_pmu_intel_ctxt *core2_vpmu_cxt = vcpu_vpmu(v)->context;
    uint64_t *fixed_counters = vpmu_reg_pointer(core2_vpmu_cxt, fixed_counters);
    struct xen_pmu_cntr_pair *xen_pmu_cntr_pair =
        vpmu_reg_pointer(core2_vpmu_cxt, arch_counters);

    for ( i = 0; i < fixed_pmc_cnt; i++ )
        rdmsrl(MSR_CORE_PERF_FIXED_CTR0 + i, fixed_counters[i]);
    for ( i = 0; i < arch_pmc_cnt; i++ )
    {
        rdmsrl(MSR_IA32_PERFCTR0 + i, xen_pmu_cntr_pair[i].counter);
        rdmsrl(MSR_P6_EVNTSEL(i), xen_pmu_cntr_pair[i].control);
    }

    if ( !is_hvm_vcpu(v) )
        rdmsrl(MSR_CORE_PERF_GLOBAL_STATUS, core2_vpmu_cxt->global_status);
    /* Save MSR to private context to make it fork-friendly */
    else if ( mem_sharing_enabled(v->domain) )
        vmx_read_guest_msr(v, MSR_CORE_PERF_GLOBAL_CTRL,
                           &core2_vpmu_cxt->global_ctrl);
}

static int cf_check core2_vpmu_save(struct vcpu *v, bool to_guest)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( !is_hvm_vcpu(v) )
        wrmsrl(MSR_CORE_PERF_GLOBAL_CTRL, 0);

    if ( !vpmu_are_all_set(vpmu, VPMU_CONTEXT_SAVE | VPMU_CONTEXT_LOADED) )
        return 0;

    __core2_vpmu_save(v);

    /* Unset PMU MSR bitmap to trap lazy load. */
    if ( !vpmu_is_set(vpmu, VPMU_RUNNING) && is_hvm_vcpu(v) &&
         cpu_has_vmx_msr_bitmap )
        core2_vpmu_unset_msr_bitmap(v);

    if ( to_guest )
    {
        ASSERT(!has_vlapic(v->domain));
        memcpy((void *)(&vpmu->xenpmu_data->pmu.c.intel) + regs_off,
               vpmu->context + regs_off, regs_sz);
    }

    return 1;
}

static inline void __core2_vpmu_load(struct vcpu *v)
{
    unsigned int i, pmc_start;
    struct xen_pmu_intel_ctxt *core2_vpmu_cxt = vcpu_vpmu(v)->context;
    uint64_t *fixed_counters = vpmu_reg_pointer(core2_vpmu_cxt, fixed_counters);
    struct xen_pmu_cntr_pair *xen_pmu_cntr_pair =
        vpmu_reg_pointer(core2_vpmu_cxt, arch_counters);

    for ( i = 0; i < fixed_pmc_cnt; i++ )
        wrmsrl(MSR_CORE_PERF_FIXED_CTR0 + i, fixed_counters[i]);

    if ( full_width_write )
        pmc_start = MSR_IA32_A_PERFCTR0;
    else
        pmc_start = MSR_IA32_PERFCTR0;
    for ( i = 0; i < arch_pmc_cnt; i++ )
    {
        wrmsrl(pmc_start + i, xen_pmu_cntr_pair[i].counter);
        wrmsrl(MSR_P6_EVNTSEL(i), xen_pmu_cntr_pair[i].control);
    }

    wrmsrl(MSR_CORE_PERF_FIXED_CTR_CTRL, core2_vpmu_cxt->fixed_ctrl);
    if ( vpmu_is_set(vcpu_vpmu(v), VPMU_CPU_HAS_DS) )
        wrmsrl(MSR_IA32_DS_AREA, core2_vpmu_cxt->ds_area);

    if ( !is_hvm_vcpu(v) )
    {
        wrmsrl(MSR_CORE_PERF_GLOBAL_OVF_CTRL, core2_vpmu_cxt->global_ovf_ctrl);
        core2_vpmu_cxt->global_ovf_ctrl = 0;
        wrmsrl(MSR_CORE_PERF_GLOBAL_CTRL, core2_vpmu_cxt->global_ctrl);
    }
    /* Restore MSR from context when used with a fork */
    else if ( mem_sharing_is_fork(v->domain) )
        vmx_write_guest_msr(v, MSR_CORE_PERF_GLOBAL_CTRL,
                            core2_vpmu_cxt->global_ctrl);
}

static int core2_vpmu_verify(struct vcpu *v)
{
    unsigned int i;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct xen_pmu_intel_ctxt *core2_vpmu_cxt = vcpu_vpmu(v)->context;
    uint64_t *fixed_counters = vpmu_reg_pointer(core2_vpmu_cxt, fixed_counters);
    struct xen_pmu_cntr_pair *xen_pmu_cntr_pair =
        vpmu_reg_pointer(core2_vpmu_cxt, arch_counters);
    uint64_t fixed_ctrl;
    uint64_t *priv_context = vpmu->priv_context;
    uint64_t enabled_cntrs = 0;

    if ( core2_vpmu_cxt->global_ovf_ctrl & global_ovf_ctrl_mask )
        return -EINVAL;
    if ( core2_vpmu_cxt->global_ctrl & global_ctrl_mask )
        return -EINVAL;
    if ( core2_vpmu_cxt->pebs_enable )
        return -EINVAL;

    fixed_ctrl = core2_vpmu_cxt->fixed_ctrl;
    if ( fixed_ctrl & fixed_ctrl_mask )
        return -EINVAL;

    for ( i = 0; i < fixed_pmc_cnt; i++ )
    {
        if ( fixed_counters[i] & fixed_counters_mask )
            return -EINVAL;
        if ( (fixed_ctrl >> (i * FIXED_CTR_CTRL_BITS)) & 3 )
            enabled_cntrs |= (1ULL << i);
    }
    enabled_cntrs <<= 32;

    for ( i = 0; i < arch_pmc_cnt; i++ )
    {
        uint64_t control = xen_pmu_cntr_pair[i].control;

        if ( control & ARCH_CTRL_MASK )
            return -EINVAL;
        if ( control & ARCH_CNTR_ENABLED )
            enabled_cntrs |= (1ULL << i);
    }

    if ( vpmu_is_set(vpmu, VPMU_CPU_HAS_DS) &&
         !(is_hvm_vcpu(v)
           ? is_canonical_address(core2_vpmu_cxt->ds_area)
           : __addr_ok(core2_vpmu_cxt->ds_area)) )
        return -EINVAL;

    if ( (core2_vpmu_cxt->global_ctrl & enabled_cntrs) ||
         (core2_vpmu_cxt->ds_area != 0) )
        vpmu_set(vpmu, VPMU_RUNNING);
    else
        vpmu_reset(vpmu, VPMU_RUNNING);

    *priv_context = enabled_cntrs;

    return 0;
}

static int cf_check core2_vpmu_load(struct vcpu *v, bool from_guest)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    if ( vpmu_is_set(vpmu, VPMU_CONTEXT_LOADED) )
        return 0;

    if ( from_guest )
    {
        int ret;

        ASSERT(!has_vlapic(v->domain));

        memcpy(vpmu->context + regs_off,
               (void *)&v->arch.vpmu.xenpmu_data->pmu.c.intel + regs_off,
               regs_sz);

        ret = core2_vpmu_verify(v);
        if ( ret )
        {
            /*
             * Not necessary since we should never load the context until
             * guest provides valid values. But just to be safe.
             */
            memset(vpmu->context + regs_off, 0, regs_sz);
            return ret;
        }
    }

    vpmu_set(vpmu, VPMU_CONTEXT_LOADED);

    __core2_vpmu_load(v);

    return 0;
}

static int cf_check core2_vpmu_alloc_resource(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct xen_pmu_intel_ctxt *core2_vpmu_cxt = NULL;
    uint64_t *p = NULL;

    if ( !acquire_pmu_ownership(PMU_OWNER_HVM) )
        return 0;

    if ( is_hvm_vcpu(v) )
    {
        if ( vmx_add_host_load_msr(v, MSR_CORE_PERF_GLOBAL_CTRL, 0) )
            goto out_err;

        if ( vmx_add_guest_msr(v, MSR_CORE_PERF_GLOBAL_CTRL, 0) )
            goto out_err;
    }

    vpmu->priv_context_size = sizeof(uint64_t);
    vpmu->context_size = sizeof(struct xen_pmu_intel_ctxt) +
                         fixed_pmc_cnt * sizeof(uint64_t) +
                         arch_pmc_cnt * sizeof(struct xen_pmu_cntr_pair);
    /* Calculate and add the padding for alignment */
    vpmu->context_size += vpmu->context_size %
                          sizeof(struct xen_pmu_intel_ctxt);

    core2_vpmu_cxt = _xzalloc(vpmu->context_size,
                              sizeof(struct xen_pmu_intel_ctxt));
    p = xzalloc(uint64_t);

    if ( !core2_vpmu_cxt || !p )
        goto out_err;

    core2_vpmu_cxt->fixed_counters = sizeof(*core2_vpmu_cxt);
    core2_vpmu_cxt->arch_counters = core2_vpmu_cxt->fixed_counters +
                                    sizeof(uint64_t) * fixed_pmc_cnt;

    vpmu->context = core2_vpmu_cxt;
    vpmu->priv_context = p;

    if ( !has_vlapic(v->domain) )
    {
        /* Copy fixed/arch register offsets to shared area */
        ASSERT(vpmu->xenpmu_data);
        memcpy(&vpmu->xenpmu_data->pmu.c.intel, core2_vpmu_cxt, regs_off);
    }

    vpmu_set(vpmu, VPMU_CONTEXT_ALLOCATED);

    return 1;

out_err:
    release_pmu_ownership(PMU_OWNER_HVM);

    xfree(core2_vpmu_cxt);
    xfree(p);

    printk("Failed to allocate VPMU resources for domain %u vcpu %u\n",
           v->vcpu_id, v->domain->domain_id);

    return 0;
}

static int core2_vpmu_msr_common_check(u32 msr_index, int *type, int *index)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(current);

    if ( !is_core2_vpmu_msr(msr_index, type, index) )
        return 0;

    if ( unlikely(!vpmu_is_set(vpmu, VPMU_CONTEXT_ALLOCATED)) &&
         !core2_vpmu_alloc_resource(current) )
        return 0;

    /* Do the lazy load staff. */
    if ( !vpmu_is_set(vpmu, VPMU_CONTEXT_LOADED) )
    {
        __core2_vpmu_load(current);
        vpmu_set(vpmu, VPMU_CONTEXT_LOADED);

        if ( is_hvm_vcpu(current) && cpu_has_vmx_msr_bitmap )
            core2_vpmu_set_msr_bitmap(current);
    }
    return 1;
}

static int cf_check core2_vpmu_do_wrmsr(unsigned int msr, uint64_t msr_content)
{
    int i, tmp;
    int type = -1, index = -1;
    struct vcpu *v = current;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct xen_pmu_intel_ctxt *core2_vpmu_cxt;
    uint64_t *enabled_cntrs;

    if ( !core2_vpmu_msr_common_check(msr, &type, &index) )
        return -EINVAL;

    if ( (type == MSR_TYPE_COUNTER) && (msr_content & fixed_counters_mask) )
        /* Writing unsupported bits to a fixed counter */
        return -EINVAL;

    core2_vpmu_cxt = vpmu->context;
    enabled_cntrs = vpmu->priv_context;
    switch ( msr )
    {
    case MSR_CORE_PERF_GLOBAL_OVF_CTRL:
        if ( msr_content & global_ovf_ctrl_mask )
            return -EINVAL;
        core2_vpmu_cxt->global_status &= ~msr_content;
        wrmsrl(MSR_CORE_PERF_GLOBAL_OVF_CTRL, msr_content);
        return 0;
    case MSR_CORE_PERF_GLOBAL_STATUS:
        gdprintk(XENLOG_INFO, "Can not write readonly MSR: "
                 "MSR_PERF_GLOBAL_STATUS(0x38E)!\n");
        return -EINVAL;
    case MSR_IA32_PEBS_ENABLE:
        if ( vpmu_features & (XENPMU_FEATURE_IPC_ONLY |
                              XENPMU_FEATURE_ARCH_ONLY) )
            return -EINVAL;
        if ( msr_content )
            /* PEBS is reported as unavailable in MSR_IA32_MISC_ENABLE */
            return -EINVAL;
        return 0;
    case MSR_IA32_DS_AREA:
        if ( !(vpmu_features & XENPMU_FEATURE_INTEL_BTS) )
            return -EINVAL;
        if ( vpmu_is_set(vpmu, VPMU_CPU_HAS_DS) )
        {
            if ( !(is_hvm_vcpu(v) ? is_canonical_address(msr_content)
                                  : __addr_ok(msr_content)) )
            {
                gdprintk(XENLOG_WARNING,
                         "Illegal address for IA32_DS_AREA: %#" PRIx64 "x\n",
                         msr_content);
                return -EINVAL;
            }
            core2_vpmu_cxt->ds_area = msr_content;
            break;
        }
        gdprintk(XENLOG_WARNING, "Guest setting of DTS is ignored.\n");
        return 0;
    case MSR_CORE_PERF_GLOBAL_CTRL:
        if ( msr_content & global_ctrl_mask )
            return -EINVAL;
        core2_vpmu_cxt->global_ctrl = msr_content;
        break;
    case MSR_CORE_PERF_FIXED_CTR_CTRL:
        if ( msr_content & fixed_ctrl_mask )
            return -EINVAL;

        if ( is_hvm_vcpu(v) )
            vmx_read_guest_msr(v, MSR_CORE_PERF_GLOBAL_CTRL,
                               &core2_vpmu_cxt->global_ctrl);
        else
            rdmsrl(MSR_CORE_PERF_GLOBAL_CTRL, core2_vpmu_cxt->global_ctrl);
        *enabled_cntrs &= ~(((1ULL << fixed_pmc_cnt) - 1) << 32);
        if ( msr_content != 0 )
        {
            u64 val = msr_content;
            for ( i = 0; i < fixed_pmc_cnt; i++ )
            {
                if ( val & 3 )
                    *enabled_cntrs |= (1ULL << 32) << i;
                val >>= FIXED_CTR_CTRL_BITS;
            }
        }

        core2_vpmu_cxt->fixed_ctrl = msr_content;
        break;
    default:
        tmp = msr - MSR_P6_EVNTSEL(0);
        if ( tmp >= 0 && tmp < arch_pmc_cnt )
        {
            bool_t blocked = 0;
            uint64_t umaskevent = msr_content & MSR_IA32_CMT_EVTSEL_UE_MASK;
            struct xen_pmu_cntr_pair *xen_pmu_cntr_pair =
                vpmu_reg_pointer(core2_vpmu_cxt, arch_counters);

            if ( msr_content & ARCH_CTRL_MASK )
                return -EINVAL;

            /* PMC filters */
            if ( vpmu_features & (XENPMU_FEATURE_IPC_ONLY |
                                  XENPMU_FEATURE_ARCH_ONLY) )
            {
                blocked = 1;
                switch ( umaskevent )
                {
                /*
                 * See the Pre-Defined Architectural Performance Events table
                 * from the Intel 64 and IA-32 Architectures Software
                 * Developer's Manual, Volume 3B, System Programming Guide,
                 * Part 2.
                 */
                case 0x003c:	/* UnHalted Core Cycles */
                case 0x013c:	/* UnHalted Reference Cycles */
                case 0x00c0:	/* Instructions Retired */
                    blocked = 0;
                    break;
                }
            }

            if ( vpmu_features & XENPMU_FEATURE_ARCH_ONLY )
            {
                /* Additional counters beyond IPC only; blocked already set. */
                switch ( umaskevent )
                {
                case 0x4f2e:	/* Last Level Cache References */
                case 0x412e:	/* Last Level Cache Misses */
                case 0x00c4:	/* Branch Instructions Retired */
                case 0x00c5:	/* All Branch Mispredict Retired */
                    blocked = 0;
                    break;
               }
            }

            if ( blocked )
                return -EINVAL;

            if ( is_hvm_vcpu(v) )
                vmx_read_guest_msr(v, MSR_CORE_PERF_GLOBAL_CTRL,
                                   &core2_vpmu_cxt->global_ctrl);
            else
                rdmsrl(MSR_CORE_PERF_GLOBAL_CTRL, core2_vpmu_cxt->global_ctrl);

            if ( msr_content & ARCH_CNTR_ENABLED )
                *enabled_cntrs |= 1ULL << tmp;
            else
                *enabled_cntrs &= ~(1ULL << tmp);

            xen_pmu_cntr_pair[tmp].control = msr_content;
        }
    }

    if ( type != MSR_TYPE_GLOBAL )
        wrmsrl(msr, msr_content);
    else
    {
        if ( is_hvm_vcpu(v) )
            vmx_write_guest_msr(v, MSR_CORE_PERF_GLOBAL_CTRL, msr_content);
        else
            wrmsrl(MSR_CORE_PERF_GLOBAL_CTRL, msr_content);
    }

    if ( (core2_vpmu_cxt->global_ctrl & *enabled_cntrs) ||
         (core2_vpmu_cxt->ds_area != 0) )
        vpmu_set(vpmu, VPMU_RUNNING);
    else
        vpmu_reset(vpmu, VPMU_RUNNING);

    return 0;
}

static int cf_check core2_vpmu_do_rdmsr(unsigned int msr, uint64_t *msr_content)
{
    int type = -1, index = -1;
    struct vcpu *v = current;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct xen_pmu_intel_ctxt *core2_vpmu_cxt;

    if ( core2_vpmu_msr_common_check(msr, &type, &index) )
    {
        core2_vpmu_cxt = vpmu->context;
        switch ( msr )
        {
        case MSR_CORE_PERF_GLOBAL_OVF_CTRL:
            *msr_content = 0;
            break;
        case MSR_CORE_PERF_GLOBAL_STATUS:
            *msr_content = core2_vpmu_cxt->global_status;
            break;
        case MSR_CORE_PERF_GLOBAL_CTRL:
            if ( is_hvm_vcpu(v) )
                vmx_read_guest_msr(v, MSR_CORE_PERF_GLOBAL_CTRL, msr_content);
            else
                rdmsrl(MSR_CORE_PERF_GLOBAL_CTRL, *msr_content);
            break;
        default:
            rdmsrl(msr, *msr_content);
        }
    }
    else if ( msr == MSR_IA32_MISC_ENABLE )
    {
        /* Extension for BTS */
        if ( vpmu_is_set(vpmu, VPMU_CPU_HAS_BTS) )
            *msr_content &= ~MSR_IA32_MISC_ENABLE_BTS_UNAVAIL;
        *msr_content |= MSR_IA32_MISC_ENABLE_PEBS_UNAVAIL;
    }

    return 0;
}

/* Dump vpmu info on console, called in the context of keyhandler 'q'. */
static void cf_check core2_vpmu_dump(const struct vcpu *v)
{
    const struct vpmu_struct *vpmu = vcpu_vpmu(v);
    unsigned int i;
    const struct xen_pmu_intel_ctxt *core2_vpmu_cxt = vpmu->context;
    u64 val;
    uint64_t *fixed_counters;
    struct xen_pmu_cntr_pair *cntr_pair;

    if ( !core2_vpmu_cxt || !vpmu_is_set(vpmu, VPMU_CONTEXT_ALLOCATED) )
         return;

    if ( !vpmu_is_set(vpmu, VPMU_RUNNING) )
    {
        if ( vpmu_is_set(vpmu, VPMU_CONTEXT_LOADED) )
            printk("    vPMU loaded\n");
        else
            printk("    vPMU allocated\n");
        return;
    }

    printk("    vPMU running\n");

    cntr_pair = vpmu_reg_pointer(core2_vpmu_cxt, arch_counters);
    fixed_counters = vpmu_reg_pointer(core2_vpmu_cxt, fixed_counters);

    /* Print the contents of the counter and its configuration msr. */
    for ( i = 0; i < arch_pmc_cnt; i++ )
        printk("      general_%d: 0x%016lx ctrl: 0x%016lx\n",
            i, cntr_pair[i].counter, cntr_pair[i].control);

    /*
     * The configuration of the fixed counter is 4 bits each in the
     * MSR_CORE_PERF_FIXED_CTR_CTRL.
     */
    val = core2_vpmu_cxt->fixed_ctrl;
    for ( i = 0; i < fixed_pmc_cnt; i++ )
    {
        printk("      fixed_%d:   0x%016lx ctrl: %#lx\n",
               i, fixed_counters[i],
               val & FIXED_CTR_CTRL_MASK);
        val >>= FIXED_CTR_CTRL_BITS;
    }
}

static int cf_check core2_vpmu_do_interrupt(struct cpu_user_regs *regs)
{
    struct vcpu *v = current;
    u64 msr_content;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct xen_pmu_intel_ctxt *core2_vpmu_cxt = vpmu->context;

    rdmsrl(MSR_CORE_PERF_GLOBAL_STATUS, msr_content);
    if ( msr_content )
    {
        if ( pmc_quirk )
            handle_pmc_quirk(msr_content);

        core2_vpmu_cxt->global_status |= msr_content;
        msr_content &= ~global_ovf_ctrl_mask;
        wrmsrl(MSR_CORE_PERF_GLOBAL_OVF_CTRL, msr_content);
    }
    else
    {
        /* No PMC overflow but perhaps a Trace Message interrupt. */
        __vmread(GUEST_IA32_DEBUGCTL, &msr_content);
        if ( !(msr_content & IA32_DEBUGCTLMSR_TR) )
            return 0;
    }

    return 1;
}

static void cf_check core2_vpmu_destroy(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);

    xfree(vpmu->context);
    vpmu->context = NULL;
    xfree(vpmu->priv_context);
    vpmu->priv_context = NULL;
    if ( is_hvm_vcpu(v) && cpu_has_vmx_msr_bitmap )
        core2_vpmu_unset_msr_bitmap(v);
    release_pmu_ownership(PMU_OWNER_HVM);
    vpmu_clear(vpmu);
}

static int cf_check core2_vpmu_initialise(struct vcpu *v)
{
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    u64 msr_content;
    static bool_t ds_warned;

    if ( v->domain->arch.cpuid->basic.pmu_version <= 1 ||
         v->domain->arch.cpuid->basic.pmu_version >= 6 )
        return -EINVAL;

    if ( (arch_pmc_cnt + fixed_pmc_cnt) == 0 )
        return -EINVAL;

    if ( !(vpmu_features & XENPMU_FEATURE_INTEL_BTS) )
        goto func_out;
    /* Check the 'Debug Store' feature in the CPUID.EAX[1]:EDX[21] */
    while ( boot_cpu_has(X86_FEATURE_DS) )
    {
        if ( !boot_cpu_has(X86_FEATURE_DTES64) )
        {
            if ( !ds_warned )
                printk(XENLOG_G_WARNING "CPU doesn't support 64-bit DS Area"
                       " - Debug Store disabled for guests\n");
            break;
        }
        vpmu_set(vpmu, VPMU_CPU_HAS_DS);
        rdmsrl(MSR_IA32_MISC_ENABLE, msr_content);
        if ( msr_content & MSR_IA32_MISC_ENABLE_BTS_UNAVAIL )
        {
            /* If BTS_UNAVAIL is set reset the DS feature. */
            vpmu_reset(vpmu, VPMU_CPU_HAS_DS);
            if ( !ds_warned )
                printk(XENLOG_G_WARNING "CPU has set BTS_UNAVAIL"
                       " - Debug Store disabled for guests\n");
            break;
        }

        vpmu_set(vpmu, VPMU_CPU_HAS_BTS);
        if ( !ds_warned )
        {
            if ( !boot_cpu_has(X86_FEATURE_DSCPL) )
                printk(XENLOG_G_INFO
                       "vpmu: CPU doesn't support CPL-Qualified BTS\n");
            printk("******************************************************\n");
            printk("** WARNING: Emulation of BTS Feature is switched on **\n");
            printk("** Using this processor feature in a virtualized    **\n");
            printk("** environment is not 100%% safe.                    **\n");
            printk("** Setting the DS buffer address with wrong values  **\n");
            printk("** may lead to hypervisor hangs or crashes.         **\n");
            printk("** It is NOT recommended for production use!        **\n");
            printk("******************************************************\n");
        }
        break;
    }
    ds_warned = 1;
 func_out:

    /* PV domains can allocate resources immediately */
    if ( is_pv_vcpu(v) && !core2_vpmu_alloc_resource(v) )
        return -EIO;

    return 0;
}

static int cf_check core2_vpmu_get_msr(struct vcpu *v, unsigned int msr,
                                       uint64_t *val)
{
    int type, index, ret = 0;
    struct vpmu_struct *vpmu = vcpu_vpmu(v);
    struct xen_pmu_intel_ctxt *core2_vpmu_cxt = vpmu->context;
    uint64_t *fixed_counters = vpmu_reg_pointer(core2_vpmu_cxt, fixed_counters);
    struct xen_pmu_cntr_pair *xen_pmu_cntr_pair =
        vpmu_reg_pointer(core2_vpmu_cxt, arch_counters);

    if ( !is_core2_vpmu_msr(msr, &type, &index) )
        return -EINVAL;

    vcpu_pause(v);

    if ( msr == MSR_CORE_PERF_GLOBAL_OVF_CTRL )
        *val = core2_vpmu_cxt->global_ovf_ctrl;
    else if ( msr == MSR_CORE_PERF_GLOBAL_STATUS )
        *val = core2_vpmu_cxt->global_status;
    else if ( msr == MSR_CORE_PERF_GLOBAL_CTRL )
        *val = core2_vpmu_cxt->global_ctrl;
    else if ( msr >= MSR_CORE_PERF_FIXED_CTR0 &&
              msr < MSR_CORE_PERF_FIXED_CTR0 + fixed_pmc_cnt )
        *val = fixed_counters[msr - MSR_CORE_PERF_FIXED_CTR0];
    else if ( msr >= MSR_P6_PERFCTR(0) && msr < MSR_P6_PERFCTR(arch_pmc_cnt) )
        *val = xen_pmu_cntr_pair[msr - MSR_P6_PERFCTR(0)].counter;
    else if ( msr >= MSR_P6_EVNTSEL(0) && msr < MSR_P6_EVNTSEL(arch_pmc_cnt) )
        *val = xen_pmu_cntr_pair[msr - MSR_P6_EVNTSEL(0)].control;
    else
        ret = -EINVAL;

    vcpu_unpause(v);

    return ret;
}

static const struct arch_vpmu_ops __initconst_cf_clobber core2_vpmu_ops = {
    .initialise = core2_vpmu_initialise,
    .do_wrmsr = core2_vpmu_do_wrmsr,
    .do_rdmsr = core2_vpmu_do_rdmsr,
    .do_interrupt = core2_vpmu_do_interrupt,
    .arch_vpmu_destroy = core2_vpmu_destroy,
    .arch_vpmu_save = core2_vpmu_save,
    .arch_vpmu_load = core2_vpmu_load,
    .arch_vpmu_dump = core2_vpmu_dump,
    .get_msr = core2_vpmu_get_msr,

#ifdef CONFIG_MEM_SHARING
    .allocate_context = core2_vpmu_alloc_resource,
#endif
};

const struct arch_vpmu_ops *__init core2_vpmu_init(void)
{
    unsigned int version = 0;
    unsigned int i;

    if ( current_cpu_data.cpuid_level >= 0xa )
        version = MASK_EXTR(cpuid_eax(0xa), PMU_VERSION_MASK);

    switch ( version )
    {
    case 4:
    case 5:
        printk(XENLOG_INFO "VPMU: PMU version %u is not fully supported. "
               "Emulating version 3\n", version);
        /* FALLTHROUGH */

    case 2:
    case 3:
        break;

    default:
        printk(XENLOG_WARNING "VPMU: PMU version %u is not supported\n",
               version);
        return ERR_PTR(-EINVAL);
    }

    if ( current_cpu_data.x86 != 6 )
    {
        printk(XENLOG_WARNING "VPMU: only family 6 is supported\n");
        return ERR_PTR(-EINVAL);
    }

    arch_pmc_cnt = core2_get_arch_pmc_count();
    fixed_pmc_cnt = core2_get_fixed_pmc_count();

    if ( cpu_has_pdcm )
    {
        uint64_t caps;

        rdmsrl(MSR_IA32_PERF_CAPABILITIES, caps);
        full_width_write = (caps >> 13) & 1;
    }

    fixed_ctrl_mask = ~((1ull << (fixed_pmc_cnt * FIXED_CTR_CTRL_BITS)) - 1);
    /* mask .AnyThread bits for all fixed counters */
    for( i = 0; i < fixed_pmc_cnt; i++ )
       fixed_ctrl_mask |=
           (FIXED_CTR_CTRL_ANYTHREAD_MASK << (FIXED_CTR_CTRL_BITS * i));

    fixed_counters_mask = ~((1ull << core2_get_bitwidth_fix_count()) - 1);
    global_ctrl_mask = ~((((1ULL << fixed_pmc_cnt) - 1) << 32) |
                         ((1ULL << arch_pmc_cnt) - 1));
    global_ovf_ctrl_mask = ~(0xC000000000000000ULL |
                             (((1ULL << fixed_pmc_cnt) - 1) << 32) |
                             ((1ULL << arch_pmc_cnt) - 1));
    if ( version > 2 )
        /*
         * Even though we don't support Uncore counters guests should be
         * able to clear all available overflows.
         */
        global_ovf_ctrl_mask &= ~(1ULL << 61);

    regs_sz = (sizeof(struct xen_pmu_intel_ctxt) - regs_off) +
              sizeof(uint64_t) * fixed_pmc_cnt +
              sizeof(struct xen_pmu_cntr_pair) * arch_pmc_cnt;

    /* TODO: It's clearly incorrect for this to quirk all Intel Fam6 CPUs. */
    pmc_quirk = current_cpu_data.x86 == 6;

    if ( sizeof(struct xen_pmu_data) + sizeof(uint64_t) * fixed_pmc_cnt +
         sizeof(struct xen_pmu_cntr_pair) * arch_pmc_cnt > PAGE_SIZE )
    {
        printk(XENLOG_WARNING
               "VPMU: Register bank does not fit into VPMU share page\n");
        arch_pmc_cnt = fixed_pmc_cnt = 0;
        return ERR_PTR(-ENOSPC);
    }

    return &core2_vpmu_ops;
}

