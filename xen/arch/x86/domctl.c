/******************************************************************************
 * Arch-specific domctl.c
 *
 * Copyright (c) 2002-2006, K A Fraser
 */

#include <xen/types.h>
#include <xen/lib.h>
#include <xen/mm.h>
#include <xen/guest_access.h>
#include <xen/compat.h>
#include <xen/pci.h>
#include <public/domctl.h>
#include <xen/sched.h>
#include <xen/domain.h>
#include <xen/event.h>
#include <xen/domain_page.h>
#include <asm/msr.h>
#include <xen/trace.h>
#include <xen/console.h>
#include <xen/iocap.h>
#include <xen/paging.h>

#include <asm/gdbsx.h>
#include <asm/irq.h>
#include <asm/hvm/emulate.h>
#include <asm/hvm/hvm.h>
#include <asm/processor.h>
#include <asm/acpi.h> /* for hvm_acpi_power_button */
#include <xen/hypercall.h> /* for arch_do_domctl */
#include <xsm/xsm.h>
#include <xen/iommu.h>
#include <xen/vm_event.h>
#include <public/vm_event.h>
#include <asm/mem_sharing.h>
#include <asm/xstate.h>
#include <asm/psr.h>
#include <asm/cpu-policy.h>

static int update_domain_cpu_policy(struct domain *d,
                                    xen_domctl_cpu_policy_t *xdpc)
{
    struct cpu_policy *new;
    const struct cpu_policy *sys = is_pv_domain(d)
        ? (IS_ENABLED(CONFIG_PV)  ?  &pv_max_cpu_policy : NULL)
        : (IS_ENABLED(CONFIG_HVM) ? &hvm_max_cpu_policy : NULL);
    struct cpu_policy_errors err = INIT_CPU_POLICY_ERRORS;
    int ret = -ENOMEM;

    if ( !sys )
    {
        ASSERT_UNREACHABLE();
        return -EOPNOTSUPP;
    }

    /* Start by copying the domain's existing policy. */
    if ( !(new = xmemdup(d->arch.cpu_policy)) )
        goto out;

    /* Merge the toolstack provided data. */
    if ( (ret = x86_cpuid_copy_from_buffer(
              new, xdpc->leaves, xdpc->nr_leaves,
              &err.leaf, &err.subleaf)) ||
         (ret = x86_msr_copy_from_buffer(
              new, xdpc->msrs, xdpc->nr_msrs, &err.msr)) )
        goto out;

    /* Trim any newly-stale out-of-range leaves. */
    x86_cpu_policy_clear_out_of_range_leaves(new);

    /* Audit the combined dataset. */
    ret = x86_cpu_policies_are_compatible(sys, new, &err);
    if ( ret )
        goto out;

    /*
     * Audit was successful.  Replace the existing policy, leaving the old one
     * to be freed.
     */
    SWAP(new, d->arch.cpu_policy);

    /* TODO: Drop when x86_cpu_policies_are_compatible() is completed. */
    recalculate_cpuid_policy(d);

    /* Recalculate relevant dom/vcpu state now the policy has changed. */
    domain_cpu_policy_changed(d);

 out:
    /* Free whichever struct is not installed in struct domain. */
    xfree(new);

    if ( ret )
    {
        xdpc->err_leaf    = err.leaf;
        xdpc->err_subleaf = err.subleaf;
        xdpc->err_msr     = err.msr;
    }

    return ret;
}

static int vcpu_set_vmce(struct vcpu *v,
                         const struct xen_domctl_ext_vcpucontext *evc)
{
    /*
     * Sizes of vMCE parameters used by the current and past versions
     * of Xen in descending order. If vMCE parameters are extended,
     * remember to add the old size to this array by VMCE_SIZE().
     */
#define VMCE_SIZE(field) \
    (offsetof(typeof(evc->vmce), field) + sizeof(evc->vmce.field))

    static const unsigned int valid_sizes[] = {
        sizeof(evc->vmce),
        VMCE_SIZE(mci_ctl2_bank1),
        VMCE_SIZE(caps),
    };
#undef VMCE_SIZE

    struct hvm_vmce_vcpu vmce = { };
    unsigned int evc_vmce_size =
        min(evc->size - offsetof(typeof(*evc), vmce), sizeof(evc->vmce));
    unsigned int i = 0;

    BUILD_BUG_ON(offsetof(typeof(*evc), mcg_cap) !=
                 offsetof(typeof(*evc), vmce.caps));
    BUILD_BUG_ON(sizeof(evc->mcg_cap) != sizeof(evc->vmce.caps));

    while ( i < ARRAY_SIZE(valid_sizes) && evc_vmce_size < valid_sizes[i] )
        ++i;

    if ( i == ARRAY_SIZE(valid_sizes) )
        return 0;

    memcpy(&vmce, &evc->vmce, valid_sizes[i]);

    return vmce_restore_vcpu(v, &vmce);
}

void arch_get_domain_info(const struct domain *d,
                          struct xen_domctl_getdomaininfo *info)
{
    if ( paging_mode_hap(d) )
        info->flags |= XEN_DOMINF_hap;

    info->arch_config.emulation_flags = d->arch.emulation_flags;
    info->gpaddr_bits = hap_paddr_bits;
}

static int do_vmtrace_op(struct domain *d, struct xen_domctl_vmtrace_op *op,
                         XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    struct vcpu *v;
    int rc;

    if ( !d->vmtrace_size || d == current->domain /* No vcpu_pause() */ )
        return -EINVAL;

    ASSERT(is_hvm_domain(d)); /* Restricted by domain creation logic. */

    v = domain_vcpu(d, op->vcpu);
    if ( !v )
        return -ENOENT;

    vcpu_pause(v);
    switch ( op->cmd )
    {
    case XEN_DOMCTL_vmtrace_enable:
    case XEN_DOMCTL_vmtrace_disable:
    case XEN_DOMCTL_vmtrace_reset_and_enable:
        rc = hvm_vmtrace_control(
            v, op->cmd != XEN_DOMCTL_vmtrace_disable,
            op->cmd == XEN_DOMCTL_vmtrace_reset_and_enable);
        break;

    case XEN_DOMCTL_vmtrace_output_position:
        rc = hvm_vmtrace_output_position(v, &op->value);
        if ( rc >= 0 )
            rc = 0;
        break;

    case XEN_DOMCTL_vmtrace_get_option:
        rc = hvm_vmtrace_get_option(v, op->key, &op->value);
        break;

    case XEN_DOMCTL_vmtrace_set_option:
        rc = hvm_vmtrace_set_option(v, op->key, op->value);
        break;

    default:
        rc = -EOPNOTSUPP;
        break;
    }
    vcpu_unpause(v);

    return rc;
}

#define MAX_IOPORTS 0x10000

long arch_do_domctl(
    struct xen_domctl *domctl, struct domain *d,
    XEN_GUEST_HANDLE_PARAM(xen_domctl_t) u_domctl)
{
    struct vcpu *curr = current;
    struct domain *currd = curr->domain;
    long ret = 0;
    bool copyback = false;
    unsigned long i;

    switch ( domctl->cmd )
    {

    case XEN_DOMCTL_shadow_op:
        ret = paging_domctl(d, &domctl->u.shadow_op, u_domctl, 0);
        if ( ret == -ERESTART )
            return hypercall_create_continuation(
                       __HYPERVISOR_paging_domctl_cont, "h", u_domctl);
        copyback = true;
        break;

    case XEN_DOMCTL_ioport_permission:
    {
        unsigned int fp = domctl->u.ioport_permission.first_port;
        unsigned int np = domctl->u.ioport_permission.nr_ports;
        int allow = domctl->u.ioport_permission.allow_access;

        if ( (fp + np) <= fp || (fp + np) > MAX_IOPORTS )
            ret = -EINVAL;
        else if ( !ioports_access_permitted(currd, fp, fp + np - 1) ||
                  xsm_ioport_permission(XSM_HOOK, d, fp, fp + np - 1, allow) )
            ret = -EPERM;
        else if ( allow )
            ret = ioports_permit_access(d, fp, fp + np - 1);
        else
            ret = ioports_deny_access(d, fp, fp + np - 1);
        break;
    }

    case XEN_DOMCTL_getpageframeinfo3:
    {
        unsigned int num = domctl->u.getpageframeinfo3.num;
        unsigned int width = has_32bit_shinfo(currd) ? 4 : 8;

        /* Games to allow this code block to handle a compat guest. */
        void __user *guest_handle = domctl->u.getpageframeinfo3.array.p;

        if ( unlikely(num > 1024) ||
             unlikely(num != domctl->u.getpageframeinfo3.num) )
        {
            ret = -E2BIG;
            break;
        }

        for ( i = 0; i < num; ++i )
        {
            unsigned long gfn = 0, type = XEN_DOMCTL_PFINFO_NOTAB;
            struct page_info *page;
            p2m_type_t t;

            if ( raw_copy_from_guest(&gfn, guest_handle + (i * width), width) )
            {
                ret = -EFAULT;
                break;
            }

            page = get_page_from_gfn(d, gfn, &t, P2M_ALLOC);

            if ( unlikely(!page) ||
                 unlikely(is_special_page(page)) )
            {
                if ( unlikely(p2m_is_broken(t)) )
                    type = XEN_DOMCTL_PFINFO_BROKEN;
                else
                    type = XEN_DOMCTL_PFINFO_XTAB;
            }
            else
            {
                switch( page->u.inuse.type_info & PGT_type_mask )
                {
                case PGT_l1_page_table:
                    type = XEN_DOMCTL_PFINFO_L1TAB;
                    break;
                case PGT_l2_page_table:
                    type = XEN_DOMCTL_PFINFO_L2TAB;
                    break;
                case PGT_l3_page_table:
                    type = XEN_DOMCTL_PFINFO_L3TAB;
                    break;
                case PGT_l4_page_table:
                    type = XEN_DOMCTL_PFINFO_L4TAB;
                    break;
                }

                if ( page->u.inuse.type_info & PGT_pinned )
                    type |= XEN_DOMCTL_PFINFO_LPINTAB;
                else if ( !(page->u.inuse.type_info & PGT_validated) )
                    type = XEN_DOMCTL_PFINFO_NOTAB;

                if ( page->count_info & PGC_broken )
                    type = XEN_DOMCTL_PFINFO_BROKEN;
            }

            if ( page )
                put_page(page);

            if ( __raw_copy_to_guest(guest_handle + (i * width), &type, width) )
            {
                ret = -EFAULT;
                break;
            }

            /*
             * Avoid checking for preemption when the `hostp2m' lock isn't
             * involve, i.e. non-translated guest, and avoid preemption on
             * the last iteration.
             */
            if ( paging_mode_translate(d) &&
                 likely((i + 1) < num) && hypercall_preempt_check() )
            {
                domctl->u.getpageframeinfo3.num = num - i - 1;
                domctl->u.getpageframeinfo3.array.p =
                    guest_handle + ((i + 1) * width);
                if ( __copy_to_guest(u_domctl, domctl, 1) )
                {
                    ret = -EFAULT;
                    break;
                }
                return hypercall_create_continuation(__HYPERVISOR_domctl,
                                                     "h", u_domctl);
            }
        }

        break;
    }

    case XEN_DOMCTL_hypercall_init:
    {
        unsigned long gmfn = domctl->u.hypercall_init.gmfn;
        struct page_info *page;
        void *hypercall_page;

        page = get_page_from_gfn(d, gmfn, NULL, P2M_ALLOC);

        if ( !page || !get_page_type(page, PGT_writable_page) )
        {
            if ( page )
            {
                ret = -EPERM;
                put_page(page);
            }
            else
                ret = -EINVAL;
            break;
        }

        hypercall_page = __map_domain_page(page);
        init_hypercall_page(d, hypercall_page);
        unmap_domain_page(hypercall_page);

        put_page_and_type(page);
        break;
    }

    case XEN_DOMCTL_sethvmcontext:
    {
        struct hvm_domain_context c = { .size = domctl->u.hvmcontext.size };

        ret = -EINVAL;
        if ( (d == currd) || /* no domain_pause() */
             !is_hvm_domain(d) )
            goto sethvmcontext_out;

        ret = -ENOMEM;
        if ( (c.data = xmalloc_bytes(c.size)) == NULL )
            goto sethvmcontext_out;

        ret = -EFAULT;
        if ( copy_from_guest(c.data, domctl->u.hvmcontext.buffer, c.size) != 0 )
            goto sethvmcontext_out;

        domain_pause(d);
        ret = hvm_load(d, &c);
        domain_unpause(d);

    sethvmcontext_out:
        xfree(c.data);
        break;
    }

    case XEN_DOMCTL_gethvmcontext:
    {
        struct hvm_domain_context c = { 0 };

        ret = -EINVAL;
        if ( (d == currd) || /* no domain_pause() */
             !is_hvm_domain(d) )
            goto gethvmcontext_out;

        c.size = hvm_save_size(d);

        if ( guest_handle_is_null(domctl->u.hvmcontext.buffer) )
        {
            /* Client is querying for the correct buffer size */
            domctl->u.hvmcontext.size = c.size;
            ret = 0;
            goto gethvmcontext_out;
        }

        /* Check that the client has a big enough buffer */
        ret = -ENOSPC;
        if ( domctl->u.hvmcontext.size < c.size )
            goto gethvmcontext_out;

        /* Allocate our own marshalling buffer */
        ret = -ENOMEM;
        if ( (c.data = xmalloc_bytes(c.size)) == NULL )
            goto gethvmcontext_out;

        domain_pause(d);
        ret = hvm_save(d, &c);
        domain_unpause(d);

        domctl->u.hvmcontext.size = c.cur;
        if ( copy_to_guest(domctl->u.hvmcontext.buffer, c.data, c.cur) != 0 )
            ret = -EFAULT;

    gethvmcontext_out:
        copyback = true;
        xfree(c.data);
        break;
    }

    case XEN_DOMCTL_gethvmcontext_partial:
        ret = -EINVAL;
        if ( (d == currd) || /* no domain_pause() */
             !is_hvm_domain(d) )
            break;

        ret = hvm_save_one(d, domctl->u.hvmcontext_partial.type,
                           domctl->u.hvmcontext_partial.instance,
                           domctl->u.hvmcontext_partial.buffer,
                           &domctl->u.hvmcontext_partial.bufsz);

        if ( !ret )
            copyback = true;
        break;

    case XEN_DOMCTL_set_address_size:
        if ( is_hvm_domain(d) )
            ret = -EOPNOTSUPP;
        else if ( is_pv_domain(d) )
        {
            if ( ((domctl->u.address_size.size == 64) && !d->arch.pv.is_32bit) ||
                 ((domctl->u.address_size.size == 32) &&  d->arch.pv.is_32bit) )
                ret = 0;
            else if ( domctl->u.address_size.size == 32 )
                ret = switch_compat(d);
            else
                ret = -EINVAL;
        }
        else
            ASSERT_UNREACHABLE();
        break;

    case XEN_DOMCTL_get_address_size:
        if ( is_hvm_domain(d) )
            ret = -EOPNOTSUPP;
        else if ( is_pv_domain(d) )
        {
            domctl->u.address_size.size =
                is_pv_32bit_domain(d) ? 32 : BITS_PER_LONG;
            copyback = true;
        }
        else
            ASSERT_UNREACHABLE();
        break;

    case XEN_DOMCTL_sendtrigger:
    {
        struct vcpu *v;

        ret = -ESRCH;
        if ( domctl->u.sendtrigger.vcpu >= d->max_vcpus ||
             (v = d->vcpu[domctl->u.sendtrigger.vcpu]) == NULL )
            break;

        switch ( domctl->u.sendtrigger.trigger )
        {
        case XEN_DOMCTL_SENDTRIGGER_NMI:
            ret = 0;
            if ( !test_and_set_bool(v->arch.nmi_pending) )
                vcpu_kick(v);
            break;

        case XEN_DOMCTL_SENDTRIGGER_POWER:
            ret = -EINVAL;
            if ( is_hvm_domain(d) )
            {
                ret = 0;
                hvm_acpi_power_button(d);
            }
            break;

        case XEN_DOMCTL_SENDTRIGGER_SLEEP:
            ret = -EINVAL;
            if ( is_hvm_domain(d) )
            {
                ret = 0;
                hvm_acpi_sleep_button(d);
            }
            break;

        default:
            ret = -ENOSYS;
        }
        break;
    }

    case XEN_DOMCTL_bind_pt_irq:
    {
        struct xen_domctl_bind_pt_irq *bind = &domctl->u.bind_pt_irq;
        int irq;

        ret = -EINVAL;
        if ( !is_hvm_domain(d) )
            break;

        ret = xsm_bind_pt_irq(XSM_HOOK, d, bind);
        if ( ret )
            break;

        irq = domain_pirq_to_irq(d, bind->machine_irq);
        ret = -EPERM;
        if ( irq <= 0 || !irq_access_permitted(currd, irq) )
            break;

        ret = -ESRCH;
        if ( is_iommu_enabled(d) )
        {
            pcidevs_lock();
            ret = pt_irq_create_bind(d, bind);
            pcidevs_unlock();
        }
        if ( ret < 0 )
            printk(XENLOG_G_ERR "pt_irq_create_bind failed (%ld) for dom%d\n",
                   ret, d->domain_id);
        break;
    }

    case XEN_DOMCTL_unbind_pt_irq:
    {
        struct xen_domctl_bind_pt_irq *bind = &domctl->u.bind_pt_irq;
        int irq = domain_pirq_to_irq(d, bind->machine_irq);

        ret = -EINVAL;
        if ( !is_hvm_domain(d) )
            break;

        ret = -EPERM;
        if ( irq <= 0 || !irq_access_permitted(currd, irq) )
            break;

        ret = xsm_unbind_pt_irq(XSM_HOOK, d, bind);
        if ( ret )
            break;

        if ( is_iommu_enabled(d) )
        {
            pcidevs_lock();
            ret = pt_irq_destroy_bind(d, bind);
            pcidevs_unlock();
        }
        if ( ret < 0 )
            printk(XENLOG_G_ERR "pt_irq_destroy_bind failed (%ld) for dom%d\n",
                   ret, d->domain_id);
        break;
    }

    case XEN_DOMCTL_ioport_mapping:
    {
        unsigned int fgp = domctl->u.ioport_mapping.first_gport;
        unsigned int fmp = domctl->u.ioport_mapping.first_mport;
        unsigned int np = domctl->u.ioport_mapping.nr_ports;
        unsigned int add = domctl->u.ioport_mapping.add_mapping;
        struct hvm_domain *hvm;
        struct g2m_ioport *g2m_ioport;
        int found = 0;

        ret = -EOPNOTSUPP;
        if ( !is_hvm_domain(d) )
        {
            printk(XENLOG_G_ERR "ioport_map against non-HVM domain\n");
            break;
        }

        ret = -EINVAL;
        if ( ((fgp | fmp | (np - 1)) >= MAX_IOPORTS) ||
            ((fgp + np) > MAX_IOPORTS) || ((fmp + np) > MAX_IOPORTS) )
        {
            printk(XENLOG_G_ERR
                   "ioport_map:invalid:dom%d gport=%x mport=%x nr=%x\n",
                   domctl->domain, fgp, fmp, np);
            break;
        }

        ret = -EPERM;
        if ( !ioports_access_permitted(currd, fmp, fmp + np - 1) )
            break;

        ret = xsm_ioport_mapping(XSM_HOOK, d, fmp, fmp + np - 1, add);
        if ( ret )
            break;

        hvm = &d->arch.hvm;
        if ( add )
        {
            printk(XENLOG_G_INFO
                   "ioport_map:add: dom%d gport=%x mport=%x nr=%x\n",
                   d->domain_id, fgp, fmp, np);

            list_for_each_entry(g2m_ioport, &hvm->g2m_ioport_list, list)
                if (g2m_ioport->mport == fmp )
                {
                    g2m_ioport->gport = fgp;
                    g2m_ioport->np = np;
                    found = 1;
                    break;
                }
            if ( !found )
            {
                g2m_ioport = xmalloc(struct g2m_ioport);
                if ( !g2m_ioport )
                    ret = -ENOMEM;
            }
            if ( !found && !ret )
            {
                g2m_ioport->gport = fgp;
                g2m_ioport->mport = fmp;
                g2m_ioport->np = np;
                list_add_tail(&g2m_ioport->list, &hvm->g2m_ioport_list);
            }
            if ( !ret )
                ret = ioports_permit_access(d, fmp, fmp + np - 1);
            if ( ret && !found && g2m_ioport )
            {
                list_del(&g2m_ioport->list);
                xfree(g2m_ioport);
            }
        }
        else
        {
            printk(XENLOG_G_INFO
                   "ioport_map:remove: dom%d gport=%x mport=%x nr=%x\n",
                   d->domain_id, fgp, fmp, np);
            list_for_each_entry(g2m_ioport, &hvm->g2m_ioport_list, list)
                if ( g2m_ioport->mport == fmp )
                {
                    list_del(&g2m_ioport->list);
                    xfree(g2m_ioport);
                    break;
                }
            ret = ioports_deny_access(d, fmp, fmp + np - 1);
            if ( ret && is_hardware_domain(currd) )
                printk(XENLOG_ERR
                       "ioport_map: error %ld denying dom%d access to [%x,%x]\n",
                       ret, d->domain_id, fmp, fmp + np - 1);
        }
        break;
    }

    case XEN_DOMCTL_set_ext_vcpucontext:
    case XEN_DOMCTL_get_ext_vcpucontext:
    {
        struct xen_domctl_ext_vcpucontext *evc = &domctl->u.ext_vcpucontext;
        struct vcpu *v;

        ret = -ESRCH;
        if ( (evc->vcpu >= d->max_vcpus) ||
             ((v = d->vcpu[evc->vcpu]) == NULL) )
            break;

        if ( domctl->cmd == XEN_DOMCTL_get_ext_vcpucontext )
        {
            if ( v == curr ) /* no vcpu_pause() */
                break;

            evc->size = sizeof(*evc);

            vcpu_pause(v);

            if ( is_pv_domain(d) )
            {
                evc->sysenter_callback_cs      =
                    v->arch.pv.sysenter_callback_cs;
                evc->sysenter_callback_eip     =
                    v->arch.pv.sysenter_callback_eip;
                evc->sysenter_disables_events  =
                    v->arch.pv.sysenter_disables_events;
                evc->syscall32_callback_cs     =
                    v->arch.pv.syscall32_callback_cs;
                evc->syscall32_callback_eip    =
                    v->arch.pv.syscall32_callback_eip;
                evc->syscall32_disables_events =
                    v->arch.pv.syscall32_disables_events;
            }
            else
            {
                evc->sysenter_callback_cs      = 0;
                evc->sysenter_callback_eip     = 0;
                evc->sysenter_disables_events  = 0;
                evc->syscall32_callback_cs     = 0;
                evc->syscall32_callback_eip    = 0;
                evc->syscall32_disables_events = 0;
            }
            evc->vmce.caps = v->arch.vmce.mcg_cap;
            evc->vmce.mci_ctl2_bank0 = v->arch.vmce.bank[0].mci_ctl2;
            evc->vmce.mci_ctl2_bank1 = v->arch.vmce.bank[1].mci_ctl2;
            evc->vmce.mcg_ext_ctl = v->arch.vmce.mcg_ext_ctl;

            ret = 0;
            vcpu_unpause(v);
            copyback = true;
        }
        else
        {
            if ( d == currd ) /* no domain_pause() */
                break;
            ret = -EINVAL;
            if ( evc->size < offsetof(typeof(*evc), vmce) )
                break;
            if ( is_pv_domain(d) )
            {
                if ( !is_canonical_address(evc->sysenter_callback_eip) ||
                     !is_canonical_address(evc->syscall32_callback_eip) )
                    break;
                domain_pause(d);
                fixup_guest_code_selector(d, evc->sysenter_callback_cs);
                v->arch.pv.sysenter_callback_cs =
                    evc->sysenter_callback_cs;
                v->arch.pv.sysenter_callback_eip =
                    evc->sysenter_callback_eip;
                v->arch.pv.sysenter_disables_events =
                    evc->sysenter_disables_events;
                fixup_guest_code_selector(d, evc->syscall32_callback_cs);
                v->arch.pv.syscall32_callback_cs =
                    evc->syscall32_callback_cs;
                v->arch.pv.syscall32_callback_eip =
                    evc->syscall32_callback_eip;
                v->arch.pv.syscall32_disables_events =
                    evc->syscall32_disables_events;
            }
            else if ( (evc->sysenter_callback_cs & ~3) ||
                      evc->sysenter_callback_eip ||
                      (evc->syscall32_callback_cs & ~3) ||
                      evc->syscall32_callback_eip )
                break;
            else
                domain_pause(d);

            ret = vcpu_set_vmce(v, evc);

            domain_unpause(d);
        }
        break;
    }

    case XEN_DOMCTL_gettscinfo:
        if ( d == currd ) /* no domain_pause() */
            ret = -EINVAL;
        else
        {
            domain_pause(d);
            tsc_get_info(d, &domctl->u.tsc_info.tsc_mode,
                         &domctl->u.tsc_info.elapsed_nsec,
                         &domctl->u.tsc_info.gtsc_khz,
                         &domctl->u.tsc_info.incarnation);
            domain_unpause(d);
            copyback = true;
        }
        break;

    case XEN_DOMCTL_settscinfo:
        if ( d == currd ) /* no domain_pause() */
            ret = -EINVAL;
        else
        {
            domain_pause(d);
            ret = tsc_set_info(d, domctl->u.tsc_info.tsc_mode,
                               domctl->u.tsc_info.elapsed_nsec,
                               domctl->u.tsc_info.gtsc_khz,
                               domctl->u.tsc_info.incarnation);
            domain_unpause(d);
        }
        break;

#ifdef CONFIG_HVM
    case XEN_DOMCTL_debug_op:
    {
        struct vcpu *v;

        ret = -EINVAL;
        if ( (domctl->u.debug_op.vcpu >= d->max_vcpus) ||
             ((v = d->vcpu[domctl->u.debug_op.vcpu]) == NULL) )
            break;

        ret = -EINVAL;
        if ( (v == curr) || /* no vcpu_pause() */
             !is_hvm_domain(d) )
            break;

        ret = hvm_debug_op(v, domctl->u.debug_op.op);
        break;
    }
#endif

#ifdef CONFIG_GDBSX
    case XEN_DOMCTL_gdbsx_guestmemio:
        ret = gdbsx_guest_mem_io(d, &domctl->u.gdbsx_guest_memio);
        if ( !ret )
           copyback = true;
        break;

    case XEN_DOMCTL_gdbsx_pausevcpu:
    {
        struct vcpu *v;

        ret = -EBUSY;
        if ( !d->controller_pause_count )
            break;
        ret = -EINVAL;
        if ( domctl->u.gdbsx_pauseunp_vcpu.vcpu >= d->max_vcpus ||
             (v = d->vcpu[domctl->u.gdbsx_pauseunp_vcpu.vcpu]) == NULL )
            break;
        ret = vcpu_pause_by_systemcontroller(v);
        break;
    }

    case XEN_DOMCTL_gdbsx_unpausevcpu:
    {
        struct vcpu *v;

        ret = -EBUSY;
        if ( !d->controller_pause_count )
            break;
        ret = -EINVAL;
        if ( domctl->u.gdbsx_pauseunp_vcpu.vcpu >= d->max_vcpus ||
             (v = d->vcpu[domctl->u.gdbsx_pauseunp_vcpu.vcpu]) == NULL )
            break;
        ret = vcpu_unpause_by_systemcontroller(v);
        if ( ret == -EINVAL )
            printk(XENLOG_G_WARNING
                   "WARN: d%d attempting to unpause %pv which is not paused\n",
                   currd->domain_id, v);
        break;
    }

    case XEN_DOMCTL_gdbsx_domstatus:
    {
        struct vcpu *v;

        domctl->u.gdbsx_domstatus.vcpu_id = -1;
        domctl->u.gdbsx_domstatus.paused = d->controller_pause_count > 0;
        if ( domctl->u.gdbsx_domstatus.paused )
        {
            for_each_vcpu ( d, v )
            {
                if ( v->arch.gdbsx_vcpu_event )
                {
                    domctl->u.gdbsx_domstatus.vcpu_id = v->vcpu_id;
                    domctl->u.gdbsx_domstatus.vcpu_ev =
                        v->arch.gdbsx_vcpu_event;
                    v->arch.gdbsx_vcpu_event = 0;
                    break;
                }
            }
        }
        copyback = true;
        break;
    }
#endif

    case XEN_DOMCTL_setvcpuextstate:
    case XEN_DOMCTL_getvcpuextstate:
    {
        struct xen_domctl_vcpuextstate *evc = &domctl->u.vcpuextstate;
        struct vcpu *v;
        uint32_t offset = 0;

#define PV_XSAVE_HDR_SIZE (2 * sizeof(uint64_t))
#define PV_XSAVE_SIZE(xcr0) (PV_XSAVE_HDR_SIZE + xstate_ctxt_size(xcr0))

        ret = -ESRCH;
        if ( (evc->vcpu >= d->max_vcpus) ||
             ((v = d->vcpu[evc->vcpu]) == NULL) )
            goto vcpuextstate_out;

        ret = -EINVAL;
        if ( v == curr ) /* no vcpu_pause() */
            goto vcpuextstate_out;

        if ( domctl->cmd == XEN_DOMCTL_getvcpuextstate )
        {
            unsigned int size;

            ret = 0;

            if ( (!evc->size && !evc->xfeature_mask) ||
                 guest_handle_is_null(evc->buffer) )
            {
                /*
                 * A query for the size of buffer to use.  Must return the
                 * maximum size we ever might hand back to userspace, bearing
                 * in mind that the vcpu might increase its xcr0_accum between
                 * this query for size, and the following query for data.
                 */
                evc->xfeature_mask = xfeature_mask;
                evc->size = PV_XSAVE_SIZE(xfeature_mask);
                goto vcpuextstate_out;
            }

            vcpu_pause(v);
            size = PV_XSAVE_SIZE(v->arch.xcr0_accum);

            if ( evc->size < size || evc->xfeature_mask != xfeature_mask )
                ret = -EINVAL;

            if ( !ret && copy_to_guest_offset(evc->buffer, offset,
                                              (void *)&v->arch.xcr0,
                                              sizeof(v->arch.xcr0)) )
                ret = -EFAULT;

            offset += sizeof(v->arch.xcr0);
            if ( !ret && copy_to_guest_offset(evc->buffer, offset,
                                              (void *)&v->arch.xcr0_accum,
                                              sizeof(v->arch.xcr0_accum)) )
                ret = -EFAULT;

            offset += sizeof(v->arch.xcr0_accum);

            /* Serialise xsave state, if there is any. */
            if ( !ret && size > PV_XSAVE_HDR_SIZE )
            {
                unsigned int xsave_size = size - PV_XSAVE_HDR_SIZE;
                void *xsave_area = xmalloc_bytes(xsave_size);

                if ( !xsave_area )
                {
                    ret = -ENOMEM;
                    vcpu_unpause(v);
                    goto vcpuextstate_out;
                }

                expand_xsave_states(v, xsave_area, xsave_size);

                if ( copy_to_guest_offset(evc->buffer, offset, xsave_area,
                                          xsave_size) )
                     ret = -EFAULT;
                xfree(xsave_area);
           }

            vcpu_unpause(v);

            /* Specify how much data we actually wrote into the buffer. */
            if ( !ret )
                evc->size = size;
        }
        else
        {
            void *receive_buf;
            uint64_t _xcr0, _xcr0_accum;
            const struct xsave_struct *_xsave_area;

            ret = -EINVAL;
            if ( evc->size < PV_XSAVE_HDR_SIZE ||
                 evc->size > PV_XSAVE_SIZE(xfeature_mask) )
                goto vcpuextstate_out;

            receive_buf = xmalloc_bytes(evc->size);
            if ( !receive_buf )
            {
                ret = -ENOMEM;
                goto vcpuextstate_out;
            }
            if ( copy_from_guest_offset(receive_buf, domctl->u.vcpuextstate.buffer,
                                        offset, evc->size) )
            {
                ret = -EFAULT;
                xfree(receive_buf);
                goto vcpuextstate_out;
            }

            _xcr0 = *(uint64_t *)receive_buf;
            _xcr0_accum = *(uint64_t *)(receive_buf + sizeof(uint64_t));
            _xsave_area = receive_buf + PV_XSAVE_HDR_SIZE;

            if ( _xcr0_accum )
            {
                if ( evc->size >= PV_XSAVE_HDR_SIZE + XSTATE_AREA_MIN_SIZE )
                    ret = validate_xstate(d, _xcr0, _xcr0_accum,
                                          &_xsave_area->xsave_hdr);
            }
            else if ( !_xcr0 )
                ret = 0;
            if ( ret )
            {
                xfree(receive_buf);
                goto vcpuextstate_out;
            }

            if ( evc->size == PV_XSAVE_HDR_SIZE )
                ; /* Nothing to restore. */
            else if ( evc->size < PV_XSAVE_HDR_SIZE + XSTATE_AREA_MIN_SIZE )
                ret = -EINVAL; /* Can't be legitimate data. */
            else if ( xsave_area_compressed(_xsave_area) )
                ret = -EOPNOTSUPP; /* Don't support compressed data. */
            else if ( evc->size != PV_XSAVE_SIZE(_xcr0_accum) )
                ret = -EINVAL; /* Not legitimate data. */
            else
            {
                vcpu_pause(v);

                v->arch.xcr0 = _xcr0;
                v->arch.xcr0_accum = _xcr0_accum;
                v->arch.nonlazy_xstate_used = _xcr0_accum & XSTATE_NONLAZY;
                compress_xsave_states(v, _xsave_area,
                                      evc->size - PV_XSAVE_HDR_SIZE);

                if ( is_hvm_domain(d) )
                    hvmemul_cancel(v);

                vcpu_unpause(v);
            }

            xfree(receive_buf);
        }

#undef PV_XSAVE_HDR_SIZE
#undef PV_XSAVE_SIZE

    vcpuextstate_out:
        if ( domctl->cmd == XEN_DOMCTL_getvcpuextstate )
            copyback = true;
        break;
    }

#ifdef CONFIG_MEM_SHARING
    case XEN_DOMCTL_mem_sharing_op:
        ret = mem_sharing_domctl(d, &domctl->u.mem_sharing_op);
        break;
#endif

#if P2M_AUDIT
    case XEN_DOMCTL_audit_p2m:
        if ( d == currd )
            ret = -EPERM;
        else
        {
            audit_p2m(d,
                      &domctl->u.audit_p2m.orphans,
                      &domctl->u.audit_p2m.m2p_bad,
                      &domctl->u.audit_p2m.p2m_bad);
            copyback = true;
        }
        break;
#endif /* P2M_AUDIT */

    case XEN_DOMCTL_set_broken_page_p2m:
    {
        p2m_type_t pt;
        unsigned long pfn = domctl->u.set_broken_page_p2m.pfn;

        if ( !is_hvm_domain(d) )
            return -EINVAL;

        if ( unlikely(!mfn_valid(get_gfn_query(d, pfn, &pt))) ||
             unlikely(!p2m_is_ram(pt)) )
            ret = -EINVAL;
        else
            ret = p2m_change_type_one(d, pfn, pt, p2m_ram_broken);

        put_gfn(d, pfn);
        break;
    }

    case XEN_DOMCTL_get_vcpu_msrs:
    case XEN_DOMCTL_set_vcpu_msrs:
    {
        struct xen_domctl_vcpu_msrs *vmsrs = &domctl->u.vcpu_msrs;
        struct xen_domctl_vcpu_msr msr = {};
        struct vcpu *v;
        static const uint32_t msrs_to_send[] = {
            MSR_SPEC_CTRL,
            MSR_INTEL_MISC_FEATURES_ENABLES,
            MSR_TSC_AUX,
            MSR_AMD64_DR0_ADDRESS_MASK,
            MSR_AMD64_DR1_ADDRESS_MASK,
            MSR_AMD64_DR2_ADDRESS_MASK,
            MSR_AMD64_DR3_ADDRESS_MASK,
        };
        uint32_t nr_msrs = ARRAY_SIZE(msrs_to_send);

        ret = -ESRCH;
        if ( (vmsrs->vcpu >= d->max_vcpus) ||
             ((v = d->vcpu[vmsrs->vcpu]) == NULL) )
            break;

        ret = -EINVAL;
        if ( v == curr )
            break;

        /* Count maximum number of optional msrs. */
        if ( boot_cpu_has(X86_FEATURE_DBEXT) )
            nr_msrs += 4;

        if ( domctl->cmd == XEN_DOMCTL_get_vcpu_msrs )
        {
            ret = 0; copyback = true;

            /* NULL guest handle is a request for max size. */
            if ( guest_handle_is_null(vmsrs->msrs) )
                vmsrs->msr_count = nr_msrs;
            else
            {
                unsigned int j;

                i = 0;

                vcpu_pause(v);

                for ( j = 0; j < ARRAY_SIZE(msrs_to_send) && i < vmsrs->msr_count; ++j )
                {
                    uint64_t val;
                    int rc;

                    if ( copy_from_guest_offset(&msr, vmsrs->msrs, i, 1) )
                    {
                        ret = -EFAULT;
                        break;
                    }

                    msr.index = msr.index ?: msrs_to_send[j];

                    rc = guest_rdmsr(v, msr.index, &val);

                    /*
                     * It is the programmers responsibility to ensure that
                     * the msr requested contain generally-read/write MSRs.
                     * X86EMUL_EXCEPTION here implies a missing feature, and
                     * that the guest doesn't have access to the MSR.
                     */
                    if ( rc == X86EMUL_EXCEPTION )
                        continue;
                    if ( rc == X86EMUL_UNHANDLEABLE )
                        ret = vpmu_get_msr(v, msr.index, &val);
                    else
                        ret = (rc == X86EMUL_OKAY) ? 0 : -ENXIO;

                    if ( ret )
                    {
                        ASSERT_UNREACHABLE();
                        break;
                    }

                    if ( !val )
                        continue; /* Skip empty MSRs. */

                    msr.value = val;
                    if ( copy_to_guest_offset(vmsrs->msrs, i, &msr, 1) )
                    {
                        ret = -EFAULT;
                        break;
                    }
                    ++i;
                }

                vcpu_unpause(v);

                if ( i > vmsrs->msr_count && !ret )
                    ret = -ENOBUFS;
                vmsrs->msr_count = i;
            }
        }
        else
        {
            ret = -EINVAL;
            if ( vmsrs->msr_count > nr_msrs )
                break;

            vcpu_pause(v);

            for ( i = 0; i < vmsrs->msr_count; ++i )
            {
                ret = -EFAULT;
                if ( copy_from_guest_offset(&msr, vmsrs->msrs, i, 1) )
                    break;

                ret = -EINVAL;
                if ( msr.reserved )
                    break;

                switch ( msr.index )
                {
                case MSR_SPEC_CTRL:
                case MSR_INTEL_MISC_FEATURES_ENABLES:
                case MSR_TSC_AUX:
                case MSR_AMD64_DR0_ADDRESS_MASK:
                case MSR_AMD64_DR1_ADDRESS_MASK ... MSR_AMD64_DR3_ADDRESS_MASK:
                    if ( guest_wrmsr(v, msr.index, msr.value) != X86EMUL_OKAY )
                        break;
                    continue;
                }
                break;
            }

            vcpu_unpause(v);

            if ( i == vmsrs->msr_count )
                ret = 0;
            else
            {
                vmsrs->msr_count = i;
                copyback = true;
            }
        }
        break;
    }

    case XEN_DOMCTL_psr_cmt_op:
        if ( !psr_cmt_enabled() )
        {
            ret = -ENODEV;
            break;
        }

        switch ( domctl->u.psr_cmt_op.cmd )
        {
        case XEN_DOMCTL_PSR_CMT_OP_ATTACH:
            ret = psr_alloc_rmid(d);
            break;

        case XEN_DOMCTL_PSR_CMT_OP_DETACH:
            if ( d->arch.psr_rmid > 0 )
                psr_free_rmid(d);
            else
                ret = -ENOENT;
            break;

        case XEN_DOMCTL_PSR_CMT_OP_QUERY_RMID:
            domctl->u.psr_cmt_op.data = d->arch.psr_rmid;
            copyback = true;
            break;

        default:
            ret = -ENOSYS;
            break;
        }
        break;

    case XEN_DOMCTL_psr_alloc:
        switch ( domctl->u.psr_alloc.cmd )
        {
        case XEN_DOMCTL_PSR_SET_L3_CBM:
            ret = psr_set_val(d, domctl->u.psr_alloc.target,
                              domctl->u.psr_alloc.data,
                              PSR_TYPE_L3_CBM);
            break;

        case XEN_DOMCTL_PSR_SET_L3_CODE:
            ret = psr_set_val(d, domctl->u.psr_alloc.target,
                              domctl->u.psr_alloc.data,
                              PSR_TYPE_L3_CODE);
            break;

        case XEN_DOMCTL_PSR_SET_L3_DATA:
            ret = psr_set_val(d, domctl->u.psr_alloc.target,
                              domctl->u.psr_alloc.data,
                              PSR_TYPE_L3_DATA);
            break;

        case XEN_DOMCTL_PSR_SET_L2_CBM:
            ret = psr_set_val(d, domctl->u.psr_alloc.target,
                              domctl->u.psr_alloc.data,
                              PSR_TYPE_L2_CBM);
            break;

        case XEN_DOMCTL_PSR_SET_MBA_THRTL:
            ret = psr_set_val(d, domctl->u.psr_alloc.target,
                              domctl->u.psr_alloc.data,
                              PSR_TYPE_MBA_THRTL);
            break;

#define domctl_psr_get_val(d, domctl, type, copyback) ({    \
    uint32_t v_;                                            \
    int r_ = psr_get_val((d), (domctl)->u.psr_alloc.target, \
                         &v_, (type));                      \
                                                            \
    (domctl)->u.psr_alloc.data = v_;                        \
    (copyback) = true;                                      \
    r_;                                                     \
})

        case XEN_DOMCTL_PSR_GET_L3_CBM:
            ret = domctl_psr_get_val(d, domctl, PSR_TYPE_L3_CBM, copyback);
            break;

        case XEN_DOMCTL_PSR_GET_L3_CODE:
            ret = domctl_psr_get_val(d, domctl, PSR_TYPE_L3_CODE, copyback);
            break;

        case XEN_DOMCTL_PSR_GET_L3_DATA:
            ret = domctl_psr_get_val(d, domctl, PSR_TYPE_L3_DATA, copyback);
            break;

        case XEN_DOMCTL_PSR_GET_L2_CBM:
            ret = domctl_psr_get_val(d, domctl, PSR_TYPE_L2_CBM, copyback);
            break;

        case XEN_DOMCTL_PSR_GET_MBA_THRTL:
            ret = domctl_psr_get_val(d, domctl, PSR_TYPE_MBA_THRTL, copyback);
            break;

#undef domctl_psr_get_val

        default:
            ret = -EOPNOTSUPP;
            break;
        }

        break;

    case XEN_DOMCTL_get_cpu_policy:
        /* Process the CPUID leaves. */
        if ( guest_handle_is_null(domctl->u.cpu_policy.leaves) )
            domctl->u.cpu_policy.nr_leaves = CPUID_MAX_SERIALISED_LEAVES;
        else if ( (ret = x86_cpuid_copy_to_buffer(
                       d->arch.cpu_policy,
                       domctl->u.cpu_policy.leaves,
                       &domctl->u.cpu_policy.nr_leaves)) )
            break;

        /* Process the MSR entries. */
        if ( guest_handle_is_null(domctl->u.cpu_policy.msrs) )
            domctl->u.cpu_policy.nr_msrs = MSR_MAX_SERIALISED_ENTRIES;
        else if ( (ret = x86_msr_copy_to_buffer(
                       d->arch.cpu_policy,
                       domctl->u.cpu_policy.msrs,
                       &domctl->u.cpu_policy.nr_msrs)) )
            break;

        copyback = true;
        break;

    case XEN_DOMCTL_set_cpu_policy:
        if ( d == currd ) /* No domain_pause() */
        {
            ret = -EINVAL;
            break;
        }

        domain_pause(d);

        if ( d->creation_finished )
            ret = -EEXIST; /* No changing once the domain is running. */
        else
        {
            ret = update_domain_cpu_policy(d, &domctl->u.cpu_policy);
            if ( ret ) /* Copy domctl->u.cpu_policy.err_* to guest. */
                copyback = true;
        }

        domain_unpause(d);
        break;

    case XEN_DOMCTL_vmtrace_op:
        ret = do_vmtrace_op(d, &domctl->u.vmtrace_op, u_domctl);
        if ( !ret )
            copyback = true;
        break;

    default:
        ret = -ENOSYS;
        break;
    }

    if ( copyback && __copy_to_guest(u_domctl, domctl, 1) )
        ret = -EFAULT;

    return ret;
}

#ifdef CONFIG_COMPAT
#define xen_vcpu_guest_context vcpu_guest_context
#define fpu_ctxt fpu_ctxt.x
CHECK_FIELD_(struct, vcpu_guest_context, fpu_ctxt);
#undef fpu_ctxt
#undef xen_vcpu_guest_context
#endif

void arch_get_info_guest(struct vcpu *v, vcpu_guest_context_u c)
{
    unsigned int i;
    const struct domain *d = v->domain;
    bool compat = is_pv_32bit_domain(d);
#ifdef CONFIG_COMPAT
#define c(fld) (!compat ? (c.nat->fld) : (c.cmp->fld))
#else
#define c(fld) (c.nat->fld)
#endif

    memcpy(&c.nat->fpu_ctxt, v->arch.fpu_ctxt, sizeof(c.nat->fpu_ctxt));
    if ( is_pv_domain(d) )
        c(flags = v->arch.pv.vgc_flags & ~(VGCF_i387_valid|VGCF_in_kernel));
    else
        c(flags = 0);
    if ( v->fpu_initialised )
        c(flags |= VGCF_i387_valid);
    if ( !(v->pause_flags & VPF_down) )
        c(flags |= VGCF_online);
    if ( !compat )
    {
        memcpy(&c.nat->user_regs, &v->arch.user_regs, sizeof(c.nat->user_regs));
        if ( is_pv_domain(d) )
            memcpy(c.nat->trap_ctxt, v->arch.pv.trap_ctxt,
                   sizeof(c.nat->trap_ctxt));
    }
#ifdef CONFIG_COMPAT
    else
    {
        XLAT_cpu_user_regs(&c.cmp->user_regs, &v->arch.user_regs);
        if ( is_pv_domain(d) )
        {
            for ( i = 0; i < ARRAY_SIZE(c.cmp->trap_ctxt); ++i )
                XLAT_trap_info(c.cmp->trap_ctxt + i,
                               v->arch.pv.trap_ctxt + i);
        }
    }
#endif

    for ( i = 0; i < ARRAY_SIZE(v->arch.dr); ++i )
        c(debugreg[i] = v->arch.dr[i]);
    c(debugreg[6] = v->arch.dr6);
    c(debugreg[7] = v->arch.dr7 |
      (is_pv_domain(d) ? v->arch.pv.dr7_emul : 0));

    if ( is_hvm_domain(d) )
    {
        struct segment_register sreg;
        unsigned long gs_shadow;

        c.nat->ctrlreg[0] = v->arch.hvm.guest_cr[0];
        c.nat->ctrlreg[2] = v->arch.hvm.guest_cr[2];
        c.nat->ctrlreg[3] = v->arch.hvm.guest_cr[3];
        c.nat->ctrlreg[4] = v->arch.hvm.guest_cr[4];
        hvm_get_segment_register(v, x86_seg_cs, &sreg);
        c.nat->user_regs.cs = sreg.sel;
        hvm_get_segment_register(v, x86_seg_ss, &sreg);
        c.nat->user_regs.ss = sreg.sel;
        hvm_get_segment_register(v, x86_seg_ds, &sreg);
        c.nat->user_regs.ds = sreg.sel;
        hvm_get_segment_register(v, x86_seg_es, &sreg);
        c.nat->user_regs.es = sreg.sel;
        hvm_get_segment_register(v, x86_seg_fs, &sreg);
        c.nat->user_regs.fs = sreg.sel;
        c.nat->fs_base = sreg.base;
        hvm_get_segment_register(v, x86_seg_gs, &sreg);
        c.nat->user_regs.gs = sreg.sel;

        gs_shadow = hvm_get_reg(v, MSR_SHADOW_GS_BASE);

        if ( ring_0(&c.nat->user_regs) )
        {
            c.nat->gs_base_kernel = sreg.base;
            c.nat->gs_base_user = gs_shadow;
        }
        else
        {
            c.nat->gs_base_user = sreg.base;
            c.nat->gs_base_kernel = gs_shadow;
        }
    }
    else
    {
        c(ldt_base = v->arch.pv.ldt_ents ? v->arch.pv.ldt_base : 0);
        c(ldt_ents = v->arch.pv.ldt_ents);
        for ( i = 0; i < ARRAY_SIZE(v->arch.pv.gdt_frames); ++i )
            c(gdt_frames[i] = v->arch.pv.gdt_frames[i]);
#ifdef CONFIG_COMPAT
        BUILD_BUG_ON(ARRAY_SIZE(c.nat->gdt_frames) !=
                     ARRAY_SIZE(c.cmp->gdt_frames));
#endif
        for ( ; i < ARRAY_SIZE(c.nat->gdt_frames); ++i )
            c(gdt_frames[i] = 0);
        c(gdt_ents = v->arch.pv.gdt_ents);
        c(kernel_ss = v->arch.pv.kernel_ss);
        c(kernel_sp = v->arch.pv.kernel_sp);
        for ( i = 0; i < ARRAY_SIZE(v->arch.pv.ctrlreg); ++i )
            c(ctrlreg[i] = v->arch.pv.ctrlreg[i]);
        c(event_callback_eip = v->arch.pv.event_callback_eip);
        c(failsafe_callback_eip = v->arch.pv.failsafe_callback_eip);
        if ( !compat )
        {
            c.nat->syscall_callback_eip = v->arch.pv.syscall_callback_eip;
            c.nat->fs_base = v->arch.pv.fs_base;
            c.nat->gs_base_kernel = v->arch.pv.gs_base_kernel;
            c.nat->gs_base_user = v->arch.pv.gs_base_user;
        }
        else
        {
            c(event_callback_cs = v->arch.pv.event_callback_cs);
            c(failsafe_callback_cs = v->arch.pv.failsafe_callback_cs);
        }

        /* IOPL privileges are virtualised: merge back into returned eflags. */
        BUG_ON((c(user_regs.eflags) & X86_EFLAGS_IOPL) != 0);
        c(user_regs.eflags |= v->arch.pv.iopl);

        if ( !compat )
        {
            c.nat->ctrlreg[3] = xen_pfn_to_cr3(
                pagetable_get_pfn(v->arch.guest_table));
            c.nat->ctrlreg[1] =
                pagetable_is_null(v->arch.guest_table_user) ? 0
                : xen_pfn_to_cr3(pagetable_get_pfn(v->arch.guest_table_user));
        }
#ifdef CONFIG_COMPAT
        else
        {
            const l4_pgentry_t *l4e =
                map_domain_page(pagetable_get_mfn(v->arch.guest_table));

            c.cmp->ctrlreg[3] = compat_pfn_to_cr3(l4e_get_pfn(*l4e));
            unmap_domain_page(l4e);
        }
#endif

        if ( guest_kernel_mode(v, &v->arch.user_regs) )
            c(flags |= VGCF_in_kernel);
    }

    c(vm_assist = d->vm_assist);
#undef c
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
