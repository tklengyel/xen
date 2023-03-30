/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <xen/cache.h>
#include <xen/kernel.h>
#include <xen/sched.h>

#include <xen/lib/x86/cpu-policy.h>

#include <asm/cpu-policy.h>
#include <asm/msr-index.h>
#include <asm/setup.h>

struct cpu_policy __ro_after_init     raw_cpu_policy;
struct cpu_policy __ro_after_init    host_cpu_policy;
#ifdef CONFIG_PV
struct cpu_policy __ro_after_init  pv_max_cpu_policy;
struct cpu_policy __ro_after_init  pv_def_cpu_policy;
#endif
#ifdef CONFIG_HVM
struct cpu_policy __ro_after_init hvm_max_cpu_policy;
struct cpu_policy __ro_after_init hvm_def_cpu_policy;
#endif

int init_domain_cpu_policy(struct domain *d)
{
    struct cpu_policy *p = is_pv_domain(d)
        ? (IS_ENABLED(CONFIG_PV)  ?  &pv_def_cpu_policy : NULL)
        : (IS_ENABLED(CONFIG_HVM) ? &hvm_def_cpu_policy : NULL);

    if ( !p )
    {
        ASSERT_UNREACHABLE();
        return -EOPNOTSUPP;
    }

    p = xmemdup(p);
    if ( !p )
        return -ENOMEM;

    /* See comment in ctxt_switch_levelling() */
    if ( !opt_dom0_cpuid_faulting && is_control_domain(d) && is_pv_domain(d) )
        p->platform_info.cpuid_faulting = false;

    /*
     * Expose the "hardware speculation behaviour" bits of ARCH_CAPS to dom0,
     * so dom0 can turn off workarounds as appropriate.  Temporary, until the
     * domain policy logic gains a better understanding of MSRs.
     */
    if ( is_hardware_domain(d) && cpu_has_arch_caps )
    {
        uint64_t val;

        rdmsrl(MSR_ARCH_CAPABILITIES, val);

        p->arch_caps.raw = val &
            (ARCH_CAPS_RDCL_NO | ARCH_CAPS_IBRS_ALL | ARCH_CAPS_RSBA |
             ARCH_CAPS_SSB_NO | ARCH_CAPS_MDS_NO | ARCH_CAPS_IF_PSCHANGE_MC_NO |
             ARCH_CAPS_TAA_NO | ARCH_CAPS_SBDR_SSDP_NO | ARCH_CAPS_FBSDP_NO |
             ARCH_CAPS_PSDP_NO | ARCH_CAPS_FB_CLEAR | ARCH_CAPS_RRSBA |
             ARCH_CAPS_BHI_NO | ARCH_CAPS_PBRSB_NO);
    }

    d->arch.cpu_policy = p;

    recalculate_cpuid_policy(d);

    return 0;
}