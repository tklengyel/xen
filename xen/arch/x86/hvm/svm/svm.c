/*
 * svm.c: handling SVM architecture-related VM exits
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005-2007, Advanced Micro Devices, Inc.
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

#include <xen/guest_access.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/trace.h>
#include <xen/sched.h>
#include <xen/irq.h>
#include <xen/softirq.h>
#include <xen/hypercall.h>
#include <xen/domain_page.h>
#include <xen/xenoprof.h>
#include <asm/current.h>
#include <asm/io.h>
#include <asm/paging.h>
#include <asm/p2m.h>
#include <asm/mem_sharing.h>
#include <asm/regs.h>
#include <asm/cpufeature.h>
#include <asm/processor.h>
#include <asm/amd.h>
#include <asm/debugreg.h>
#include <asm/msr.h>
#include <asm/i387.h>
#include <asm/iocap.h>
#include <asm/hvm/emulate.h>
#include <asm/hvm/hvm.h>
#include <asm/hvm/support.h>
#include <asm/hvm/io.h>
#include <asm/hvm/emulate.h>
#include <asm/hvm/svm/asid.h>
#include <asm/hvm/svm/svm.h>
#include <asm/hvm/svm/vmcb.h>
#include <asm/hvm/svm/emulate.h>
#include <asm/hvm/svm/intr.h>
#include <asm/hvm/svm/svmdebug.h>
#include <asm/hvm/svm/nestedsvm.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/x86_emulate.h>
#include <public/sched.h>
#include <asm/hvm/vpt.h>
#include <asm/hvm/trace.h>
#include <asm/hap.h>
#include <asm/apic.h>
#include <asm/debugger.h>
#include <asm/hvm/monitor.h>
#include <asm/monitor.h>
#include <asm/xstate.h>

void noreturn svm_asm_do_resume(void);

u32 svm_feature_flags;

static void svm_update_guest_efer(struct vcpu *);

static struct hvm_function_table svm_function_table;

/*
 * Physical addresses of the Host State Area (for hardware) and vmcb (for Xen)
 * which contains Xen's fs/gs/tr/ldtr and GSBASE/STAR/SYSENTER state when in
 * guest vcpu context.
 */
static DEFINE_PER_CPU_READ_MOSTLY(paddr_t, hsa);
static DEFINE_PER_CPU_READ_MOSTLY(paddr_t, host_vmcb);
#ifdef CONFIG_PV
static DEFINE_PER_CPU(struct vmcb_struct *, host_vmcb_va);
#endif

static bool_t amd_erratum383_found __read_mostly;

/* OSVW bits */
static uint64_t osvw_length, osvw_status;
static DEFINE_SPINLOCK(osvw_lock);

/* Only crash the guest if the problem originates in kernel mode. */
static void svm_crash_or_fault(struct vcpu *v)
{
    if ( vmcb_get_cpl(v->arch.hvm.svm.vmcb) )
        hvm_inject_hw_exception(TRAP_invalid_op, X86_EVENT_NO_EC);
    else
        domain_crash(v->domain);
}

void __update_guest_eip(struct cpu_user_regs *regs, unsigned int inst_len)
{
    struct vcpu *curr = current;

    if ( unlikely(inst_len == 0) )
        return;

    if ( unlikely(inst_len > MAX_INST_LEN) )
    {
        gdprintk(XENLOG_ERR, "Bad instruction length %u\n", inst_len);
        svm_crash_or_fault(curr);
        return;
    }

    ASSERT(regs == guest_cpu_user_regs());

    regs->rip += inst_len;
    regs->eflags &= ~X86_EFLAGS_RF;

    curr->arch.hvm.svm.vmcb->int_stat.intr_shadow = 0;

    if ( regs->eflags & X86_EFLAGS_TF )
        hvm_inject_hw_exception(TRAP_debug, X86_EVENT_NO_EC);
}

static void svm_cpu_down(void)
{
    write_efer(read_efer() & ~EFER_SVME);
}

unsigned long *
svm_msrbit(unsigned long *msr_bitmap, uint32_t msr)
{
    unsigned long *msr_bit = NULL;

    /*
     * See AMD64 Programmers Manual, Vol 2, Section 15.10 (MSR-Bitmap Address).
     */
    if ( msr <= 0x1fff )
        msr_bit = msr_bitmap + 0x0000 / BYTES_PER_LONG;
    else if ( (msr >= 0xc0000000) && (msr <= 0xc0001fff) )
        msr_bit = msr_bitmap + 0x0800 / BYTES_PER_LONG;
    else if ( (msr >= 0xc0010000) && (msr <= 0xc0011fff) )
        msr_bit = msr_bitmap + 0x1000 / BYTES_PER_LONG;

    return msr_bit;
}

void svm_intercept_msr(struct vcpu *v, uint32_t msr, int flags)
{
    unsigned long *msr_bit;
    const struct domain *d = v->domain;

    msr_bit = svm_msrbit(v->arch.hvm.svm.msrpm, msr);
    BUG_ON(msr_bit == NULL);
    msr &= 0x1fff;

    if ( flags & MSR_INTERCEPT_READ )
         __set_bit(msr * 2, msr_bit);
    else if ( !monitored_msr(d, msr) )
         __clear_bit(msr * 2, msr_bit);

    if ( flags & MSR_INTERCEPT_WRITE )
        __set_bit(msr * 2 + 1, msr_bit);
    else if ( !monitored_msr(d, msr) )
        __clear_bit(msr * 2 + 1, msr_bit);
}

static void svm_enable_msr_interception(struct domain *d, uint32_t msr)
{
    struct vcpu *v;

    for_each_vcpu ( d, v )
        svm_intercept_msr(v, msr, MSR_INTERCEPT_WRITE);
}

static void svm_save_dr(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    unsigned int flag_dr_dirty = v->arch.hvm.flag_dr_dirty;

    if ( !flag_dr_dirty )
        return;

    /* Clear the DR dirty flag and re-enable intercepts for DR accesses. */
    v->arch.hvm.flag_dr_dirty = 0;
    vmcb_set_dr_intercepts(vmcb, ~0u);

    if ( v->domain->arch.cpuid->extd.dbext )
    {
        svm_intercept_msr(v, MSR_AMD64_DR0_ADDRESS_MASK, MSR_INTERCEPT_RW);
        svm_intercept_msr(v, MSR_AMD64_DR1_ADDRESS_MASK, MSR_INTERCEPT_RW);
        svm_intercept_msr(v, MSR_AMD64_DR2_ADDRESS_MASK, MSR_INTERCEPT_RW);
        svm_intercept_msr(v, MSR_AMD64_DR3_ADDRESS_MASK, MSR_INTERCEPT_RW);

        rdmsrl(MSR_AMD64_DR0_ADDRESS_MASK, v->arch.msrs->dr_mask[0]);
        rdmsrl(MSR_AMD64_DR1_ADDRESS_MASK, v->arch.msrs->dr_mask[1]);
        rdmsrl(MSR_AMD64_DR2_ADDRESS_MASK, v->arch.msrs->dr_mask[2]);
        rdmsrl(MSR_AMD64_DR3_ADDRESS_MASK, v->arch.msrs->dr_mask[3]);
    }

    v->arch.dr[0] = read_debugreg(0);
    v->arch.dr[1] = read_debugreg(1);
    v->arch.dr[2] = read_debugreg(2);
    v->arch.dr[3] = read_debugreg(3);
    v->arch.dr6   = vmcb_get_dr6(vmcb);
    v->arch.dr7   = vmcb_get_dr7(vmcb);
}

static void __restore_debug_registers(struct vmcb_struct *vmcb, struct vcpu *v)
{
    if ( v->arch.hvm.flag_dr_dirty )
        return;

    v->arch.hvm.flag_dr_dirty = 1;
    vmcb_set_dr_intercepts(vmcb, 0);

    ASSERT(v == current);

    if ( v->domain->arch.cpuid->extd.dbext )
    {
        svm_intercept_msr(v, MSR_AMD64_DR0_ADDRESS_MASK, MSR_INTERCEPT_NONE);
        svm_intercept_msr(v, MSR_AMD64_DR1_ADDRESS_MASK, MSR_INTERCEPT_NONE);
        svm_intercept_msr(v, MSR_AMD64_DR2_ADDRESS_MASK, MSR_INTERCEPT_NONE);
        svm_intercept_msr(v, MSR_AMD64_DR3_ADDRESS_MASK, MSR_INTERCEPT_NONE);

        wrmsrl(MSR_AMD64_DR0_ADDRESS_MASK, v->arch.msrs->dr_mask[0]);
        wrmsrl(MSR_AMD64_DR1_ADDRESS_MASK, v->arch.msrs->dr_mask[1]);
        wrmsrl(MSR_AMD64_DR2_ADDRESS_MASK, v->arch.msrs->dr_mask[2]);
        wrmsrl(MSR_AMD64_DR3_ADDRESS_MASK, v->arch.msrs->dr_mask[3]);
    }

    write_debugreg(0, v->arch.dr[0]);
    write_debugreg(1, v->arch.dr[1]);
    write_debugreg(2, v->arch.dr[2]);
    write_debugreg(3, v->arch.dr[3]);
    vmcb_set_dr6(vmcb, v->arch.dr6);
    vmcb_set_dr7(vmcb, v->arch.dr7);
}

/*
 * DR7 is saved and restored on every vmexit.  Other debug registers only
 * need to be restored if their value is going to affect execution -- i.e.,
 * if one of the breakpoints is enabled.  So mask out all bits that don't
 * enable some breakpoint functionality.
 */
static void svm_restore_dr(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;

    if ( unlikely(v->arch.dr7 & DR7_ACTIVE_MASK) )
        __restore_debug_registers(vmcb, v);
}

static int svm_vmcb_save(struct vcpu *v, struct hvm_hw_cpu *c)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;

    c->sysenter_cs = v->arch.hvm.svm.guest_sysenter_cs;
    c->sysenter_esp = v->arch.hvm.svm.guest_sysenter_esp;
    c->sysenter_eip = v->arch.hvm.svm.guest_sysenter_eip;

    if ( vmcb->event_inj.v &&
         hvm_event_needs_reinjection(vmcb->event_inj.type,
                                     vmcb->event_inj.vector) )
    {
        c->pending_event = vmcb->event_inj.raw;
        c->error_code = vmcb->event_inj.ec;
    }

    return 1;
}

static int svm_vmcb_restore(struct vcpu *v, struct hvm_hw_cpu *c)
{
    struct page_info *page = NULL;
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    struct p2m_domain *p2m = p2m_get_hostp2m(v->domain);

    if ( c->pending_valid )
    {
        if ( (c->pending_type == 1) || (c->pending_type > 4) ||
             (c->pending_reserved != 0) )
        {
            dprintk(XENLOG_ERR, "%pv: Invalid pending event %#"PRIx32"\n",
                    v, c->pending_event);
            return -EINVAL;
        }

        if ( c->pending_error_valid &&
             c->error_code != (uint16_t)c->error_code )
        {
            dprintk(XENLOG_ERR, "%pv: Invalid error code %#"PRIx32"\n",
                    v, c->error_code);
            return -EINVAL;
        }
    }

    if ( !paging_mode_hap(v->domain) )
    {
        if ( c->cr0 & X86_CR0_PG )
        {
            page = get_page_from_gfn(v->domain, c->cr3 >> PAGE_SHIFT,
                                     NULL, P2M_ALLOC);
            if ( !page )
            {
                gdprintk(XENLOG_ERR, "Invalid CR3 value=%#"PRIx64"\n",
                         c->cr3);
                return -EINVAL;
            }
        }

        if ( v->arch.hvm.guest_cr[0] & X86_CR0_PG )
            put_page(pagetable_get_page(v->arch.guest_table));

        v->arch.guest_table =
            page ? pagetable_from_page(page) : pagetable_null();
    }

    v->arch.hvm.guest_cr[0] = c->cr0 | X86_CR0_ET;
    v->arch.hvm.guest_cr[3] = c->cr3;
    v->arch.hvm.guest_cr[4] = c->cr4;
    svm_update_guest_cr(v, 0, 0);
    svm_update_guest_cr(v, 4, 0);

    /* Load sysenter MSRs into both VMCB save area and VCPU fields. */
    vmcb->sysenter_cs = v->arch.hvm.svm.guest_sysenter_cs = c->sysenter_cs;
    vmcb->sysenter_esp = v->arch.hvm.svm.guest_sysenter_esp = c->sysenter_esp;
    vmcb->sysenter_eip = v->arch.hvm.svm.guest_sysenter_eip = c->sysenter_eip;

    if ( paging_mode_hap(v->domain) )
    {
        vmcb_set_np_enable(vmcb, 1);
        vmcb_set_g_pat(vmcb, MSR_IA32_CR_PAT_RESET /* guest PAT */);
        vmcb_set_h_cr3(vmcb, pagetable_get_paddr(p2m_get_pagetable(p2m)));
    }

    if ( c->pending_valid &&
         hvm_event_needs_reinjection(c->pending_type, c->pending_vector) )
    {
        gdprintk(XENLOG_INFO, "Re-injecting %#"PRIx32", %#"PRIx32"\n",
                 c->pending_event, c->error_code);
        vmcb->event_inj.raw = c->pending_event;
        vmcb->event_inj.ec = c->error_code;
    }
    else
        vmcb->event_inj.raw = 0;

    vmcb->cleanbits.raw = 0;
    paging_update_paging_modes(v);

    return 0;
}


static void svm_save_cpu_state(struct vcpu *v, struct hvm_hw_cpu *data)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;

    data->shadow_gs        = vmcb->kerngsbase;
    data->msr_lstar        = vmcb->lstar;
    data->msr_star         = vmcb->star;
    data->msr_cstar        = vmcb->cstar;
    data->msr_syscall_mask = vmcb->sfmask;
}


static void svm_load_cpu_state(struct vcpu *v, struct hvm_hw_cpu *data)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;

    vmcb->kerngsbase = data->shadow_gs;
    vmcb->lstar      = data->msr_lstar;
    vmcb->star       = data->msr_star;
    vmcb->cstar      = data->msr_cstar;
    vmcb->sfmask     = data->msr_syscall_mask;
    v->arch.hvm.guest_efer = data->msr_efer;
    svm_update_guest_efer(v);
}

static void svm_save_vmcb_ctxt(struct vcpu *v, struct hvm_hw_cpu *ctxt)
{
    svm_save_cpu_state(v, ctxt);
    svm_vmcb_save(v, ctxt);
}

static int svm_load_vmcb_ctxt(struct vcpu *v, struct hvm_hw_cpu *ctxt)
{
    svm_load_cpu_state(v, ctxt);
    if ( svm_vmcb_restore(v, ctxt) )
    {
        gdprintk(XENLOG_ERR, "svm_vmcb restore failed!\n");
        domain_crash(v->domain);
        return -EINVAL;
    }

    return 0;
}

static void svm_fpu_enter(struct vcpu *v)
{
    struct vmcb_struct *n1vmcb = vcpu_nestedhvm(v).nv_n1vmcx;

    vcpu_restore_fpu_lazy(v);
    vmcb_set_exception_intercepts(
        n1vmcb,
        vmcb_get_exception_intercepts(n1vmcb) & ~(1U << TRAP_no_device));
}

static void svm_fpu_leave(struct vcpu *v)
{
    struct vmcb_struct *n1vmcb = vcpu_nestedhvm(v).nv_n1vmcx;

    ASSERT(!v->fpu_dirtied);
    ASSERT(read_cr0() & X86_CR0_TS);

    /*
     * If the guest does not have TS enabled then we must cause and handle an
     * exception on first use of the FPU. If the guest *does* have TS enabled
     * then this is not necessary: no FPU activity can occur until the guest
     * clears CR0.TS, and we will initialise the FPU when that happens.
     */
    if ( !(v->arch.hvm.guest_cr[0] & X86_CR0_TS) )
    {
        vmcb_set_exception_intercepts(
            n1vmcb,
            vmcb_get_exception_intercepts(n1vmcb) | (1U << TRAP_no_device));
        vmcb_set_cr0(n1vmcb, vmcb_get_cr0(n1vmcb) | X86_CR0_TS);
    }
}

static unsigned int svm_get_interrupt_shadow(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    unsigned int intr_shadow = 0;

    if ( vmcb->int_stat.intr_shadow )
        intr_shadow |= HVM_INTR_SHADOW_MOV_SS | HVM_INTR_SHADOW_STI;

    if ( vmcb_get_general1_intercepts(vmcb) & GENERAL1_INTERCEPT_IRET )
        intr_shadow |= HVM_INTR_SHADOW_NMI;

    return intr_shadow;
}

static void svm_set_interrupt_shadow(struct vcpu *v, unsigned int intr_shadow)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    u32 general1_intercepts = vmcb_get_general1_intercepts(vmcb);

    vmcb->int_stat.intr_shadow =
        !!(intr_shadow & (HVM_INTR_SHADOW_MOV_SS|HVM_INTR_SHADOW_STI));

    general1_intercepts &= ~GENERAL1_INTERCEPT_IRET;
    if ( intr_shadow & HVM_INTR_SHADOW_NMI )
        general1_intercepts |= GENERAL1_INTERCEPT_IRET;
    vmcb_set_general1_intercepts(vmcb, general1_intercepts);
}

static int svm_guest_x86_mode(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;

    if ( unlikely(!(v->arch.hvm.guest_cr[0] & X86_CR0_PE)) )
        return 0;
    if ( unlikely(guest_cpu_user_regs()->eflags & X86_EFLAGS_VM) )
        return 1;
    if ( hvm_long_mode_active(v) && likely(vmcb->cs.l) )
        return 8;
    return likely(vmcb->cs.db) ? 4 : 2;
}

void svm_update_guest_cr(struct vcpu *v, unsigned int cr, unsigned int flags)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    uint64_t value;

    switch ( cr )
    {
    case 0:
    {
        unsigned long hw_cr0_mask = 0;

        if ( !(v->arch.hvm.guest_cr[0] & X86_CR0_TS) )
        {
            if ( v != current )
            {
                if ( !v->arch.fully_eager_fpu )
                    hw_cr0_mask |= X86_CR0_TS;
            }
            else if ( vmcb_get_cr0(vmcb) & X86_CR0_TS )
                svm_fpu_enter(v);
        }

        if ( paging_mode_hap(v->domain) )
        {
            uint32_t intercepts = vmcb_get_cr_intercepts(vmcb);

            /* Trap CR3 updates if CR3 memory events are enabled. */
            if ( v->domain->arch.monitor.write_ctrlreg_enabled &
                 monitor_ctrlreg_bitmask(VM_EVENT_X86_CR3) )
               vmcb_set_cr_intercepts(vmcb, intercepts | CR_INTERCEPT_CR3_WRITE);
        }

        value = v->arch.hvm.guest_cr[0] | hw_cr0_mask;
        if ( !paging_mode_hap(v->domain) )
            value |= X86_CR0_PG | X86_CR0_WP;
        vmcb_set_cr0(vmcb, value);
        break;
    }
    case 2:
        vmcb_set_cr2(vmcb, v->arch.hvm.guest_cr[2]);
        break;
    case 3:
        vmcb_set_cr3(vmcb, v->arch.hvm.hw_cr[3]);
        if ( !nestedhvm_enabled(v->domain) )
        {
            if ( !(flags & HVM_UPDATE_GUEST_CR3_NOFLUSH) )
                hvm_asid_flush_vcpu(v);
        }
        else if ( nestedhvm_vmswitch_in_progress(v) )
            ; /* CR3 switches during VMRUN/VMEXIT do not flush the TLB. */
        else if ( !(flags & HVM_UPDATE_GUEST_CR3_NOFLUSH) )
            hvm_asid_flush_vcpu_asid(
                nestedhvm_vcpu_in_guestmode(v)
                ? &vcpu_nestedhvm(v).nv_n2asid : &v->arch.hvm.n1asid);
        break;
    case 4:
        value = HVM_CR4_HOST_MASK;
        if ( paging_mode_hap(v->domain) )
            value &= ~X86_CR4_PAE;
        value |= v->arch.hvm.guest_cr[4];

        if ( !hvm_paging_enabled(v) )
        {
            /*
             * When the guest thinks paging is disabled, Xen may need to hide
             * the effects of shadow paging, as hardware runs with the host
             * paging settings, rather than the guests settings.
             *
             * Without CR0.PG, all memory accesses are user mode, so
             * _PAGE_USER must be set in the shadow pagetables for guest
             * userspace to function.  This in turn trips up guest supervisor
             * mode if SMEP/SMAP are left active in context.  They wouldn't
             * have any effect if paging was actually disabled, so hide them
             * behind the back of the guest.
             */
            value &= ~(X86_CR4_SMEP | X86_CR4_SMAP);
        }

        vmcb_set_cr4(vmcb, value);
        break;
    default:
        BUG();
    }
}

static void svm_update_guest_efer(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    unsigned long guest_efer = v->arch.hvm.guest_efer,
        xen_efer = read_efer();

    if ( paging_mode_shadow(v->domain) )
    {
        /* EFER.NX is a Xen-owned bit and is not under guest control. */
        guest_efer &= ~EFER_NXE;
        guest_efer |= xen_efer & EFER_NXE;

        /*
         * CR0.PG is a Xen-owned bit, and remains set even when the guest has
         * logically disabled paging.
         *
         * LMA was calculated using the guest CR0.PG setting, but LME needs
         * clearing to avoid interacting with Xen's CR0.PG setting.  As writes
         * to CR0 are intercepted, it is safe to leave LME clear at this
         * point, and fix up both LME and LMA when CR0.PG is set.
         */
        if ( !(guest_efer & EFER_LMA) )
            guest_efer &= ~EFER_LME;
    }

    /* SVME must remain set in non-root mode. */
    guest_efer |= EFER_SVME;

    vmcb_set_efer(vmcb, guest_efer);

    ASSERT(nestedhvm_enabled(v->domain) ||
           !(v->arch.hvm.guest_efer & EFER_SVME));

    if ( nestedhvm_enabled(v->domain) )
        svm_nested_features_on_efer_update(v);
}

static void svm_cpuid_policy_changed(struct vcpu *v)
{
    struct svm_vcpu *svm = &v->arch.hvm.svm;
    struct vmcb_struct *vmcb = svm->vmcb;
    const struct cpuid_policy *cp = v->domain->arch.cpuid;
    u32 bitmap = vmcb_get_exception_intercepts(vmcb);

    if ( opt_hvm_fep ||
         (v->domain->arch.cpuid->x86_vendor != boot_cpu_data.x86_vendor) )
        bitmap |= (1U << TRAP_invalid_op);
    else
        bitmap &= ~(1U << TRAP_invalid_op);

    vmcb_set_exception_intercepts(vmcb, bitmap);

    /* Give access to MSR_SPEC_CTRL if the guest has been told about it. */
    svm_intercept_msr(v, MSR_SPEC_CTRL,
                      cp->extd.ibrs ? MSR_INTERCEPT_NONE : MSR_INTERCEPT_RW);

    /* Give access to MSR_PRED_CMD if the guest has been told about it. */
    svm_intercept_msr(v, MSR_PRED_CMD,
                      cp->extd.ibpb ? MSR_INTERCEPT_NONE : MSR_INTERCEPT_RW);
}

void svm_sync_vmcb(struct vcpu *v, enum vmcb_sync_state new_state)
{
    struct svm_vcpu *svm = &v->arch.hvm.svm;

    if ( new_state == vmcb_needs_vmsave )
    {
        if ( svm->vmcb_sync_state == vmcb_needs_vmload )
            svm_vmload_pa(svm->vmcb_pa);

        svm->vmcb_sync_state = new_state;
    }
    else
    {
        if ( svm->vmcb_sync_state == vmcb_needs_vmsave )
            svm_vmsave_pa(svm->vmcb_pa);

        if ( svm->vmcb_sync_state != vmcb_needs_vmload )
            svm->vmcb_sync_state = new_state;
    }
}

static unsigned int svm_get_cpl(struct vcpu *v)
{
    return vmcb_get_cpl(v->arch.hvm.svm.vmcb);
}

static void svm_get_segment_register(struct vcpu *v, enum x86_segment seg,
                                     struct segment_register *reg)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;

    ASSERT((v == current) || !vcpu_runnable(v));

    switch ( seg )
    {
    case x86_seg_fs ... x86_seg_gs:
        svm_sync_vmcb(v, vmcb_in_sync);

        /* Fallthrough. */
    case x86_seg_es ... x86_seg_ds:
        *reg = vmcb->sreg[seg];

        if ( seg == x86_seg_ss )
            reg->dpl = vmcb_get_cpl(vmcb);
        break;

    case x86_seg_tr:
        svm_sync_vmcb(v, vmcb_in_sync);
        *reg = vmcb->tr;
        break;

    case x86_seg_gdtr:
        *reg = vmcb->gdtr;
        break;

    case x86_seg_idtr:
        *reg = vmcb->idtr;
        break;

    case x86_seg_ldtr:
        svm_sync_vmcb(v, vmcb_in_sync);
        *reg = vmcb->ldtr;
        break;

    default:
        ASSERT_UNREACHABLE();
        domain_crash(v->domain);
        *reg = (struct segment_register){};
    }
}

static void svm_set_segment_register(struct vcpu *v, enum x86_segment seg,
                                     struct segment_register *reg)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;

    ASSERT((v == current) || !vcpu_runnable(v));

    switch ( seg )
    {
    case x86_seg_cs:
    case x86_seg_ds:
    case x86_seg_es:
    case x86_seg_ss: /* cpl */
        vmcb->cleanbits.seg = false;
        break;

    case x86_seg_gdtr:
    case x86_seg_idtr:
        vmcb->cleanbits.dt = false;
        break;

    case x86_seg_fs:
    case x86_seg_gs:
    case x86_seg_tr:
    case x86_seg_ldtr:
        if ( v == current )
            svm_sync_vmcb(v, vmcb_needs_vmload);
        break;

    default:
        ASSERT_UNREACHABLE();
        domain_crash(v->domain);
        return;
    }

    switch ( seg )
    {
    case x86_seg_ss:
        vmcb_set_cpl(vmcb, reg->dpl);

        /* Fallthrough */
    case x86_seg_es ... x86_seg_cs:
    case x86_seg_ds ... x86_seg_gs:
        vmcb->sreg[seg] = *reg;
        break;

    case x86_seg_tr:
        vmcb->tr = *reg;
        break;

    case x86_seg_gdtr:
        vmcb->gdtr.base = reg->base;
        vmcb->gdtr.limit = reg->limit;
        break;

    case x86_seg_idtr:
        vmcb->idtr.base = reg->base;
        vmcb->idtr.limit = reg->limit;
        break;

    case x86_seg_ldtr:
        vmcb->ldtr = *reg;
        break;

    case x86_seg_none:
        ASSERT_UNREACHABLE();
        break;
    }
}

static unsigned long svm_get_shadow_gs_base(struct vcpu *v)
{
    return v->arch.hvm.svm.vmcb->kerngsbase;
}

static int svm_set_guest_pat(struct vcpu *v, u64 gpat)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;

    if ( !paging_mode_hap(v->domain) )
        return 0;

    vmcb_set_g_pat(vmcb, gpat);
    return 1;
}

static int svm_get_guest_pat(struct vcpu *v, u64 *gpat)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;

    if ( !paging_mode_hap(v->domain) )
        return 0;

    *gpat = vmcb_get_g_pat(vmcb);
    return 1;
}

static uint64_t scale_tsc(uint64_t host_tsc, uint64_t ratio)
{
    uint64_t mult, frac, scaled_host_tsc;

    if ( ratio == DEFAULT_TSC_RATIO )
        return host_tsc;

    /*
     * Suppose the most significant 32 bits of host_tsc and ratio are
     * tsc_h and mult, and the least 32 bits of them are tsc_l and frac,
     * then
     *     host_tsc * ratio * 2^-32
     *     = host_tsc * (mult * 2^32 + frac) * 2^-32
     *     = host_tsc * mult + (tsc_h * 2^32 + tsc_l) * frac * 2^-32
     *     = host_tsc * mult + tsc_h * frac + ((tsc_l * frac) >> 32)
     *
     * Multiplications in the last two terms are between 32-bit integers,
     * so both of them can fit in 64-bit integers.
     *
     * Because mult is usually less than 10 in practice, it's very rare
     * that host_tsc * mult can overflow a 64-bit integer.
     */
    mult = ratio >> 32;
    frac = ratio & ((1ULL << 32) - 1);
    scaled_host_tsc  = host_tsc * mult;
    scaled_host_tsc += (host_tsc >> 32) * frac;
    scaled_host_tsc += ((host_tsc & ((1ULL << 32) - 1)) * frac) >> 32;

    return scaled_host_tsc;
}

static uint64_t svm_get_tsc_offset(uint64_t host_tsc, uint64_t guest_tsc,
    uint64_t ratio)
{
    return guest_tsc - scale_tsc(host_tsc, ratio);
}

static void svm_set_tsc_offset(struct vcpu *v, u64 offset, u64 at_tsc)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    struct vmcb_struct *n1vmcb, *n2vmcb;
    uint64_t n2_tsc_offset = 0;
    struct domain *d = v->domain;

    if ( !nestedhvm_enabled(d) )
    {
        vmcb_set_tsc_offset(vmcb, offset);
        return;
    }

    n1vmcb = vcpu_nestedhvm(v).nv_n1vmcx;
    n2vmcb = vcpu_nestedhvm(v).nv_n2vmcx;

    if ( nestedhvm_vcpu_in_guestmode(v) )
    {
        struct nestedsvm *svm = &vcpu_nestedsvm(v);

        n2_tsc_offset = vmcb_get_tsc_offset(n2vmcb) -
                        vmcb_get_tsc_offset(n1vmcb);
        if ( svm->ns_tscratio != DEFAULT_TSC_RATIO )
        {
            uint64_t guest_tsc = hvm_get_guest_tsc_fixed(v, at_tsc);

            n2_tsc_offset = svm_get_tsc_offset(guest_tsc,
                                               guest_tsc + n2_tsc_offset,
                                               svm->ns_tscratio);
        }
        vmcb_set_tsc_offset(n1vmcb, offset);
    }

    vmcb_set_tsc_offset(vmcb, offset + n2_tsc_offset);
}

static void svm_set_rdtsc_exiting(struct vcpu *v, bool_t enable)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    u32 general1_intercepts = vmcb_get_general1_intercepts(vmcb);
    u32 general2_intercepts = vmcb_get_general2_intercepts(vmcb);

    general1_intercepts &= ~GENERAL1_INTERCEPT_RDTSC;
    general2_intercepts &= ~GENERAL2_INTERCEPT_RDTSCP;

    if ( enable )
    {
        general1_intercepts |= GENERAL1_INTERCEPT_RDTSC;
        general2_intercepts |= GENERAL2_INTERCEPT_RDTSCP;
    }

    vmcb_set_general1_intercepts(vmcb, general1_intercepts);
    vmcb_set_general2_intercepts(vmcb, general2_intercepts);
}

static void svm_set_descriptor_access_exiting(struct vcpu *v, bool enable)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    u32 general1_intercepts = vmcb_get_general1_intercepts(vmcb);
    u32 mask = GENERAL1_INTERCEPT_IDTR_READ | GENERAL1_INTERCEPT_GDTR_READ
            | GENERAL1_INTERCEPT_LDTR_READ | GENERAL1_INTERCEPT_TR_READ
            | GENERAL1_INTERCEPT_IDTR_WRITE | GENERAL1_INTERCEPT_GDTR_WRITE
            | GENERAL1_INTERCEPT_LDTR_WRITE | GENERAL1_INTERCEPT_TR_WRITE;

    if ( enable )
        general1_intercepts |= mask;
    else
        general1_intercepts &= ~mask;

    vmcb_set_general1_intercepts(vmcb, general1_intercepts);
}

static unsigned int svm_get_insn_bytes(struct vcpu *v, uint8_t *buf)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    unsigned int len = v->arch.hvm.svm.cached_insn_len;

    if ( len != 0 )
    {
        /* Latch and clear the cached instruction. */
        memcpy(buf, vmcb->guest_ins, MAX_INST_LEN);
        v->arch.hvm.svm.cached_insn_len = 0;
    }

    return len;
}

static void svm_init_hypercall_page(void *p)
{
    unsigned int i;

    for ( i = 0; i < (PAGE_SIZE / 32); i++, p += 32 )
    {
        if ( unlikely(i == __HYPERVISOR_iret) )
        {
            /* HYPERVISOR_iret isn't supported */
            *(u16 *)p = 0x0b0f; /* ud2 */

            continue;
        }

        *(u8  *)(p + 0) = 0xb8; /* mov imm32, %eax */
        *(u32 *)(p + 1) = i;
        *(u8  *)(p + 5) = 0x0f; /* vmmcall */
        *(u8  *)(p + 6) = 0x01;
        *(u8  *)(p + 7) = 0xd9;
        *(u8  *)(p + 8) = 0xc3; /* ret */
    }
}

static inline void svm_tsc_ratio_save(struct vcpu *v)
{
    /* Other vcpus might not have vtsc enabled. So disable TSC_RATIO here. */
    if ( cpu_has_tsc_ratio && !v->domain->arch.vtsc )
        wrmsrl(MSR_AMD64_TSC_RATIO, DEFAULT_TSC_RATIO);
}

static inline void svm_tsc_ratio_load(struct vcpu *v)
{
    if ( cpu_has_tsc_ratio && !v->domain->arch.vtsc )
        wrmsrl(MSR_AMD64_TSC_RATIO, hvm_tsc_scaling_ratio(v->domain));
}

static void svm_ctxt_switch_from(struct vcpu *v)
{
    int cpu = smp_processor_id();

    /*
     * Return early if trying to do a context switch without SVM enabled,
     * this can happen when the hypervisor shuts down with HVM guests
     * still running.
     */
    if ( unlikely((read_efer() & EFER_SVME) == 0) )
        return;

    if ( !v->arch.fully_eager_fpu )
        svm_fpu_leave(v);

    svm_save_dr(v);
    svm_tsc_ratio_save(v);

    svm_sync_vmcb(v, vmcb_needs_vmload);
    svm_vmload_pa(per_cpu(host_vmcb, cpu));

    /* Resume use of ISTs now that the host TR is reinstated. */
    enable_each_ist(idt_tables[cpu]);
}

static void svm_ctxt_switch_to(struct vcpu *v)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    int cpu = smp_processor_id();

    /*
     * This is required, because VMRUN does consistency check and some of the
     * DOM0 selectors are pointing to invalid GDT locations, and cause AMD
     * processors to shutdown.
     */
    asm volatile ("mov %0, %%ds; mov %0, %%es; mov %0, %%ss;" :: "r" (0));

    /*
     * Cannot use ISTs for NMI/#MC/#DF while we are running with the guest TR.
     * But this doesn't matter: the IST is only req'd to handle SYSCALL/SYSRET.
     */
    disable_each_ist(idt_tables[cpu]);

    svm_restore_dr(v);

    vmcb->cleanbits.raw = 0;
    svm_tsc_ratio_load(v);

    if ( cpu_has_msr_tsc_aux )
        wrmsr_tsc_aux(v->arch.msrs->tsc_aux);
}

static void noreturn svm_do_resume(void)
{
    struct vcpu *v = current;
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    bool debug_state = (v->domain->debugger_attached ||
                        v->domain->arch.monitor.software_breakpoint_enabled ||
                        v->domain->arch.monitor.debug_exception_enabled);
    bool_t vcpu_guestmode = 0;
    struct vlapic *vlapic = vcpu_vlapic(v);

    if ( nestedhvm_enabled(v->domain) && nestedhvm_vcpu_in_guestmode(v) )
        vcpu_guestmode = 1;

    if ( !vcpu_guestmode &&
        unlikely(v->arch.hvm.debug_state_latch != debug_state) )
    {
        uint32_t intercepts = vmcb_get_exception_intercepts(vmcb);

        v->arch.hvm.debug_state_latch = debug_state;
        vmcb_set_exception_intercepts(
            vmcb, debug_state ? (intercepts | (1U << TRAP_int3))
                              : (intercepts & ~(1U << TRAP_int3)));
    }

    if ( v->arch.hvm.svm.launch_core != smp_processor_id() )
    {
        v->arch.hvm.svm.launch_core = smp_processor_id();
        hvm_migrate_timers(v);
        hvm_migrate_pirqs(v);
        /* Migrating to another ASID domain.  Request a new ASID. */
        hvm_asid_flush_vcpu(v);
    }

    if ( !vcpu_guestmode && !vlapic_hw_disabled(vlapic) )
    {
        vintr_t intr;

        /* Reflect the vlapic's TPR in the hardware vtpr */
        intr = vmcb_get_vintr(vmcb);
        intr.fields.tpr =
            (vlapic_get_reg(vlapic, APIC_TASKPRI) & 0xFF) >> 4;
        vmcb_set_vintr(vmcb, intr);
    }

    hvm_do_resume(v);

    reset_stack_and_jump(svm_asm_do_resume);
}

void svm_vmenter_helper(const struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    struct vmcb_struct *vmcb = curr->arch.hvm.svm.vmcb;

    ASSERT(hvmemul_cache_disabled(curr));

    svm_asid_handle_vmrun();

    if ( unlikely(tb_init_done) )
        HVMTRACE_ND(VMENTRY,
                    nestedhvm_vcpu_in_guestmode(curr) ? TRC_HVM_NESTEDFLAG : 0,
                    1/*cycles*/);

    svm_sync_vmcb(curr, vmcb_needs_vmsave);

    vmcb->rax = regs->rax;
    vmcb->rip = regs->rip;
    vmcb->rsp = regs->rsp;
    vmcb->rflags = regs->rflags | X86_EFLAGS_MBS;
}

static void svm_guest_osvw_init(struct domain *d)
{
    struct svm_domain *svm = &d->arch.hvm.svm;

    spin_lock(&osvw_lock);

    /*
     * Guests should see errata 400 and 415 as fixed (assuming that
     * HLT and IO instructions are intercepted).
     */
    svm->osvw.length = min(max(3ul, osvw_length), 64ul);
    svm->osvw.status = osvw_status & ~6;

    /*
     * By increasing VCPU's osvw.length to 3 we are telling the guest that
     * all osvw.status bits inside that length, including bit 0 (which is
     * reserved for erratum 298), are valid. However, if host processor's
     * osvw_len is 0 then osvw_status[0] carries no information. We need to
     * be conservative here and therefore we tell the guest that erratum 298
     * is present (because we really don't know).
     */
    if ( osvw_length == 0 && boot_cpu_data.x86 == 0x10 )
        svm->osvw.status |= 1;

    spin_unlock(&osvw_lock);
}

static void svm_host_osvw_reset(void)
{
    spin_lock(&osvw_lock);

    osvw_length = 64; /* One register (MSRC001_0141) worth of errata */
    osvw_status = 0;

    spin_unlock(&osvw_lock);
}

static void svm_host_osvw_init(void)
{
    spin_lock(&osvw_lock);

    /*
     * Get OSVW bits. If bits are not the same on different processors then
     * choose the worst case (i.e. if erratum is present on one processor and
     * not on another assume that the erratum is present everywhere).
     */
    if ( test_bit(X86_FEATURE_OSVW, &boot_cpu_data.x86_capability) )
    {
        uint64_t len, status;

        if ( rdmsr_safe(MSR_AMD_OSVW_ID_LENGTH, len) ||
             rdmsr_safe(MSR_AMD_OSVW_STATUS, status) )
            len = status = 0;

        if ( len < osvw_length )
            osvw_length = len;

        osvw_status |= status;
        osvw_status &= (1ULL << osvw_length) - 1;
    }
    else
        osvw_length = osvw_status = 0;

    spin_unlock(&osvw_lock);
}

static int acpi_c1e_quirk(int dir, unsigned int port, unsigned int bytes,
                          uint32_t *val)
{
    ASSERT(bytes == 1 && port == acpi_smi_cmd);

    if ( dir == IOREQ_READ )
        *val = inb(port);
    else
    {
        outb(*val, port);
        amd_check_disable_c1e(port, *val);
    }

    return X86EMUL_OKAY;
}

static int svm_domain_initialise(struct domain *d)
{
    static const struct arch_csw csw = {
        .from = svm_ctxt_switch_from,
        .to   = svm_ctxt_switch_to,
        .tail = svm_do_resume,
    };

    d->arch.ctxt_switch = &csw;

    svm_guest_osvw_init(d);

    if ( is_hardware_domain(d) && amd_acpi_c1e_quirk )
        register_portio_handler(d, acpi_smi_cmd, 1, acpi_c1e_quirk);

    return 0;
}

static int svm_vcpu_initialise(struct vcpu *v)
{
    int rc;

    v->arch.hvm.svm.launch_core = -1;

    if ( (rc = svm_create_vmcb(v)) != 0 )
    {
        dprintk(XENLOG_WARNING,
                "Failed to create VMCB for vcpu %d: err=%d.\n",
                v->vcpu_id, rc);
        return rc;
    }

    return 0;
}

static void svm_vcpu_destroy(struct vcpu *v)
{
    svm_destroy_vmcb(v);
    passive_domain_destroy(v);
}

/*
 * Emulate enough of interrupt injection to cover the DPL check (omitted by
 * hardware), and to work out whether it is safe to move %rip fowards for
 * architectural trap vs fault semantics in the exception frame (which
 * hardware won't cope with).
 *
 * The event parameter will be modified to a fault if necessary.
 */
static void svm_emul_swint_injection(struct x86_event *event)
{
    struct vcpu *curr = current;
    const struct vmcb_struct *vmcb = curr->arch.hvm.svm.vmcb;
    const struct cpu_user_regs *regs = guest_cpu_user_regs();
    unsigned int trap = event->vector, type = event->type;
    unsigned int fault = TRAP_gp_fault, ec = 0;
    pagefault_info_t pfinfo;
    struct segment_register cs, idtr;
    unsigned int idte_size, idte_offset;
    unsigned long idte_linear_addr;
    struct { uint32_t a, b, c, d; } idte = {};
    bool lm = vmcb_get_efer(vmcb) & EFER_LMA;
    int rc;

    if ( !(vmcb_get_cr0(vmcb) & X86_CR0_PE) )
        goto raise_exception; /* TODO: support real-mode injection? */

    idte_size   = lm ? 16 : 8;
    idte_offset = trap * idte_size;

    /* ICEBP sets the External Event bit despite being an instruction. */
    ec = (trap << 3) | X86_XEC_IDT |
        (type == X86_EVENTTYPE_PRI_SW_EXCEPTION ? X86_XEC_EXT : 0);

    /*
     * TODO: This does not cover the v8086 mode with CR4.VME case
     * correctly, but falls on the safe side from the point of view of a
     * 32bit OS.  Someone with many TUITs can see about reading the TSS
     * Software Interrupt Redirection bitmap.
     */
    if ( (regs->eflags & X86_EFLAGS_VM) &&
         MASK_EXTR(regs->eflags, X86_EFLAGS_IOPL) != 3 )
        goto raise_exception;

    /*
     * Read all 8/16 bytes so the idtr limit check is applied properly to
     * this entry, even though we don't look at all the words read.
     */
    hvm_get_segment_register(curr, x86_seg_cs, &cs);
    hvm_get_segment_register(curr, x86_seg_idtr, &idtr);
    if ( !hvm_virtual_to_linear_addr(x86_seg_idtr, &idtr, idte_offset,
                                     idte_size, hvm_access_read,
                                     &cs, &idte_linear_addr) )
        goto raise_exception;

    rc = hvm_copy_from_guest_linear(&idte, idte_linear_addr, idte_size,
                                    PFEC_implicit, &pfinfo);
    if ( rc )
    {
        if ( rc == HVMTRANS_bad_linear_to_gfn )
        {
            fault = TRAP_page_fault;
            ec = pfinfo.ec;
            event->cr2 = pfinfo.linear;
        }

        goto raise_exception;
    }

    /* This must be an interrupt, trap, or task gate. */
    switch ( (idte.b >> 8) & 0x1f )
    {
    case SYS_DESC_irq_gate:
    case SYS_DESC_trap_gate:
        break;
    case SYS_DESC_irq_gate16:
    case SYS_DESC_trap_gate16:
    case SYS_DESC_task_gate:
        if ( !lm )
            break;
        /* fall through */
    default:
        goto raise_exception;
    }

    /* The 64-bit high half's type must be zero. */
    if ( idte.d & 0x1f00 )
        goto raise_exception;

    /* ICEBP counts as a hardware event, and bypasses the dpl check. */
    if ( type != X86_EVENTTYPE_PRI_SW_EXCEPTION &&
         vmcb_get_cpl(vmcb) > ((idte.b >> 13) & 3) )
        goto raise_exception;

    /* Is this entry present? */
    if ( !(idte.b & (1u << 15)) )
    {
        fault = TRAP_no_segment;
        goto raise_exception;
    }

    /*
     * Any further fault during injection will cause a double fault.  It
     * is fine to leave this up to hardware, and software won't be in a
     * position to care about the architectural correctness of %rip in the
     * exception frame.
     */
    return;

 raise_exception:
    event->vector = fault;
    event->type = X86_EVENTTYPE_HW_EXCEPTION;
    event->insn_len = 0;
    event->error_code = ec;
}

static void svm_inject_event(const struct x86_event *event)
{
    struct vcpu *curr = current;
    struct vmcb_struct *vmcb = curr->arch.hvm.svm.vmcb;
    intinfo_t eventinj = vmcb->event_inj;
    struct x86_event _event = *event;
    struct cpu_user_regs *regs = guest_cpu_user_regs();

    /*
     * For hardware lacking NRips support, and always for ICEBP instructions,
     * the processor requires extra help to deliver software events.
     *
     * Xen must emulate enough of the event injection to be sure that a
     * further fault shouldn't occur during delivery.  This covers the fact
     * that hardware doesn't perform DPL checking on injection.
     */
    if ( event->type == X86_EVENTTYPE_PRI_SW_EXCEPTION ||
         (!cpu_has_svm_nrips && (event->type >= X86_EVENTTYPE_SW_INTERRUPT)) )
        svm_emul_swint_injection(&_event);

    switch ( _event.vector | -(_event.type == X86_EVENTTYPE_SW_INTERRUPT) )
    {
    case TRAP_debug:
        if ( regs->eflags & X86_EFLAGS_TF )
        {
            __restore_debug_registers(vmcb, curr);
            vmcb_set_dr6(vmcb, vmcb_get_dr6(vmcb) | DR_STEP);
        }
        /* fall through */
    case TRAP_int3:
        if ( curr->domain->debugger_attached )
        {
            /* Debug/Int3: Trap to debugger. */
            domain_pause_for_debugger();
            return;
        }
        break;

    case TRAP_page_fault:
        ASSERT(_event.type == X86_EVENTTYPE_HW_EXCEPTION);
        curr->arch.hvm.guest_cr[2] = _event.cr2;
        vmcb_set_cr2(vmcb, _event.cr2);
        break;
    }

    if ( eventinj.v && (eventinj.type == X86_EVENTTYPE_HW_EXCEPTION) )
    {
        _event.vector = hvm_combine_hw_exceptions(
            eventinj.vector, _event.vector);
        if ( _event.vector == TRAP_double_fault )
            _event.error_code = 0;
    }

    eventinj.raw = 0;
    eventinj.v = true;
    eventinj.vector = _event.vector;

    /*
     * Refer to AMD Vol 2: System Programming, 15.20 Event Injection.
     *
     * On hardware lacking NextRIP support, and all hardware in the case of
     * icebp, software events with trap semantics need emulating, so %rip in
     * the trap frame points after the instruction.
     *
     * svm_emul_swint_injection() has already confirmed that events with trap
     * semantics won't fault on injection.  Position %rip/NextRIP suitably,
     * and restrict the event type to what hardware will tolerate.
     */
    switch ( _event.type )
    {
    case X86_EVENTTYPE_SW_INTERRUPT: /* int $n */
        if ( cpu_has_svm_nrips )
            vmcb->nextrip = regs->rip + _event.insn_len;
        else
            regs->rip += _event.insn_len;
        eventinj.type = X86_EVENTTYPE_SW_INTERRUPT;
        break;

    case X86_EVENTTYPE_PRI_SW_EXCEPTION: /* icebp */
        /*
         * icebp's injection must always be emulated, as hardware does not
         * special case HW_EXCEPTION with vector 1 (#DB) as having trap
         * semantics.
         */
        regs->rip += _event.insn_len;
        if ( cpu_has_svm_nrips )
            vmcb->nextrip = regs->rip;
        eventinj.type = X86_EVENTTYPE_HW_EXCEPTION;
        break;

    case X86_EVENTTYPE_SW_EXCEPTION: /* int3, into */
        /*
         * Hardware special cases HW_EXCEPTION with vectors 3 and 4 as having
         * trap semantics, and will perform DPL checks.
         */
        if ( cpu_has_svm_nrips )
            vmcb->nextrip = regs->rip + _event.insn_len;
        else
            regs->rip += _event.insn_len;
        eventinj.type = X86_EVENTTYPE_HW_EXCEPTION;
        break;

    default:
        eventinj.type = X86_EVENTTYPE_HW_EXCEPTION;
        eventinj.ev = (_event.error_code != X86_EVENT_NO_EC);
        eventinj.ec = _event.error_code;
        break;
    }

    /*
     * If injecting an event outside of 64bit mode, zero the upper bits of the
     * %eip and nextrip after the adjustments above.
     */
    if ( !((vmcb_get_efer(vmcb) & EFER_LMA) && vmcb->cs.l) )
    {
        regs->rip = regs->eip;
        vmcb->nextrip = (uint32_t)vmcb->nextrip;
    }

    ASSERT(!eventinj.ev || eventinj.ec == (uint16_t)eventinj.ec);
    vmcb->event_inj = eventinj;

    if ( _event.vector == TRAP_page_fault &&
         _event.type == X86_EVENTTYPE_HW_EXCEPTION )
        HVMTRACE_LONG_2D(PF_INJECT, _event.error_code,
                         TRC_PAR_LONG(_event.cr2));
    else
        HVMTRACE_2D(INJ_EXC, _event.vector, _event.error_code);
}

static bool svm_event_pending(const struct vcpu *v)
{
    return v->arch.hvm.svm.vmcb->event_inj.v;
}

static void svm_cpu_dead(unsigned int cpu)
{
    paddr_t *this_hsa = &per_cpu(hsa, cpu);
    paddr_t *this_vmcb = &per_cpu(host_vmcb, cpu);

    if ( *this_hsa )
    {
        free_domheap_page(maddr_to_page(*this_hsa));
        *this_hsa = 0;
    }

#ifdef CONFIG_PV
    if ( per_cpu(host_vmcb_va, cpu) )
    {
        unmap_domain_page_global(per_cpu(host_vmcb_va, cpu));
        per_cpu(host_vmcb_va, cpu) = NULL;
    }
#endif

    if ( *this_vmcb )
    {
        free_domheap_page(maddr_to_page(*this_vmcb));
        *this_vmcb = 0;
    }
}

static int svm_cpu_up_prepare(unsigned int cpu)
{
    paddr_t *this_hsa = &per_cpu(hsa, cpu);
    paddr_t *this_vmcb = &per_cpu(host_vmcb, cpu);
    nodeid_t node = cpu_to_node(cpu);
    unsigned int memflags = 0;
    struct page_info *pg;

    if ( node != NUMA_NO_NODE )
        memflags = MEMF_node(node);

    if ( !*this_hsa )
    {
        pg = alloc_domheap_page(NULL, memflags);
        if ( !pg )
            goto err;

        clear_domain_page(page_to_mfn(pg));
        *this_hsa = page_to_maddr(pg);
    }

    if ( !*this_vmcb )
    {
        pg = alloc_domheap_page(NULL, memflags);
        if ( !pg )
            goto err;

#ifdef CONFIG_PV
        per_cpu(host_vmcb_va, cpu) = __map_domain_page_global(pg);
#endif

        clear_domain_page(page_to_mfn(pg));
        *this_vmcb = page_to_maddr(pg);
    }

    return 0;

 err:
    svm_cpu_dead(cpu);
    return -ENOMEM;
}

static void svm_init_erratum_383(const struct cpuinfo_x86 *c)
{
    uint64_t msr_content;

    /* check whether CPU is affected */
    if ( !cpu_has_amd_erratum(c, AMD_ERRATUM_383) )
        return;

    /* use safe methods to be compatible with nested virtualization */
    if ( rdmsr_safe(MSR_AMD64_DC_CFG, msr_content) == 0 &&
         wrmsr_safe(MSR_AMD64_DC_CFG, msr_content | (1ULL << 47)) == 0 )
        amd_erratum383_found = 1;
    else
        printk("Failed to enable erratum 383\n");
}

#ifdef CONFIG_PV
void svm_load_segs_prefetch(void)
{
    const struct vmcb_struct *vmcb = this_cpu(host_vmcb_va);

    if ( vmcb )
        /*
         * The main reason for this prefetch is for the TLB fill.  Use the
         * opportunity to fetch the lowest address used, to get the best
         * behaviour out of hardware's next-line prefetcher.
         */
        prefetchw(&vmcb->fs);
}

bool svm_load_segs(unsigned int ldt_ents, unsigned long ldt_base,
                   unsigned long fs_base, unsigned long gs_base,
                   unsigned long gs_shadow)
{
    unsigned int cpu = smp_processor_id();
    struct vmcb_struct *vmcb = per_cpu(host_vmcb_va, cpu);

    if ( unlikely(!vmcb) )
        return false;

    vmcb->fs.sel = 0;
    vmcb->fs.attr = 0;
    vmcb->fs.limit = 0;
    vmcb->fs.base = fs_base;

    vmcb->gs.sel = 0;
    vmcb->gs.attr = 0;
    vmcb->gs.limit = 0;
    vmcb->gs.base = gs_base;

    if ( likely(!ldt_ents) )
        memset(&vmcb->ldtr, 0, sizeof(vmcb->ldtr));
    else
    {
        /* Keep GDT in sync. */
        seg_desc_t *desc =
            this_cpu(gdt) + LDT_ENTRY - FIRST_RESERVED_GDT_ENTRY;

        _set_tssldt_desc(desc, ldt_base, ldt_ents * 8 - 1, SYS_DESC_ldt);

        vmcb->ldtr.sel = LDT_SELECTOR;
        vmcb->ldtr.attr = SYS_DESC_ldt | (_SEGMENT_P >> 8);
        vmcb->ldtr.limit = ldt_ents * 8 - 1;
        vmcb->ldtr.base = ldt_base;
    }

    vmcb->kerngsbase = gs_shadow;

    svm_vmload_pa(per_cpu(host_vmcb, cpu));

    return true;
}
#endif

static int _svm_cpu_up(bool bsp)
{
    uint64_t msr_content;
    int rc;
    unsigned int cpu = smp_processor_id();
    const struct cpuinfo_x86 *c = &cpu_data[cpu];

    /* Check whether SVM feature is disabled in BIOS */
    rdmsrl(MSR_K8_VM_CR, msr_content);
    if ( msr_content & VM_CR_SVM_DISABLE )
    {
        printk("CPU%d: AMD SVM Extension is disabled in BIOS.\n", cpu);
        return -EINVAL;
    }

    if ( bsp && (rc = svm_cpu_up_prepare(cpu)) != 0 )
        return rc;

    write_efer(read_efer() | EFER_SVME);

    /* Initialize the HSA for this core. */
    wrmsrl(MSR_K8_VM_HSAVE_PA, per_cpu(hsa, cpu));

    /* check for erratum 383 */
    svm_init_erratum_383(c);

    /* Initialize core's ASID handling. */
    svm_asid_init(c);

    /* Initialize OSVW bits to be used by guests */
    svm_host_osvw_init();

    /* Minimal checking that enough CPU setup was done by now. */
    ASSERT(str() == TSS_SELECTOR);
    svm_vmsave_pa(per_cpu(host_vmcb, cpu));

    return 0;
}

static int svm_cpu_up(void)
{
    return _svm_cpu_up(false);
}

const struct hvm_function_table * __init start_svm(void)
{
    bool_t printed = 0;

    svm_host_osvw_reset();

    if ( _svm_cpu_up(true) )
    {
        printk("SVM: failed to initialise.\n");
        return NULL;
    }

    setup_vmcb_dump();

    if ( boot_cpu_data.extended_cpuid_level >= 0x8000000a )
        svm_feature_flags = cpuid_edx(0x8000000a);

    printk("SVM: Supported advanced features:\n");

    /* DecodeAssists fast paths assume nextrip is valid for fast rIP update. */
    if ( !cpu_has_svm_nrips )
        __clear_bit(SVM_FEATURE_DECODEASSISTS, &svm_feature_flags);

    if ( cpu_has_tsc_ratio )
        svm_function_table.tsc_scaling.ratio_frac_bits = 32;

#define P(p,s) if ( p ) { printk(" - %s\n", s); printed = 1; }
    P(cpu_has_svm_npt, "Nested Page Tables (NPT)");
    P(cpu_has_svm_lbrv, "Last Branch Record (LBR) Virtualisation");
    P(cpu_has_svm_nrips, "Next-RIP Saved on #VMEXIT");
    P(cpu_has_svm_cleanbits, "VMCB Clean Bits");
    P(cpu_has_svm_decode, "DecodeAssists");
    P(cpu_has_svm_vloadsave, "Virtual VMLOAD/VMSAVE");
    P(cpu_has_svm_vgif, "Virtual GIF");
    P(cpu_has_pause_filter, "Pause-Intercept Filter");
    P(cpu_has_pause_thresh, "Pause-Intercept Filter Threshold");
    P(cpu_has_tsc_ratio, "TSC Rate MSR");
    P(cpu_has_svm_sss, "NPT Supervisor Shadow Stack");
    P(cpu_has_svm_spec_ctrl, "MSR_SPEC_CTRL virtualisation");
#undef P

    if ( !printed )
        printk(" - none\n");

    svm_function_table.hap_supported = !!cpu_has_svm_npt;
    svm_function_table.hap_capabilities = HVM_HAP_SUPERPAGE_2MB |
        (cpu_has_page1gb ? HVM_HAP_SUPERPAGE_1GB : 0);

    return &svm_function_table;
}

static void svm_do_nested_pgfault(struct vcpu *v,
    struct cpu_user_regs *regs, uint64_t pfec, paddr_t gpa, bool idt_vec)
{
    int ret;
    unsigned long gfn = gpa >> PAGE_SHIFT;
    mfn_t mfn = INVALID_MFN;
    p2m_type_t p2mt = p2m_invalid;
    p2m_access_t p2ma;
    struct p2m_domain *p2m = NULL;

    /*
     * Since HW doesn't explicitly provide a read access bit and we need to
     * somehow describe read-modify-write instructions we will conservatively
     * set read_access for all memory accesses that are not instruction fetches.
     */
    struct npfec npfec = {
        .read_access = !(pfec & PFEC_insn_fetch),
        .write_access = !!(pfec & PFEC_write_access),
        .insn_fetch = !!(pfec & PFEC_insn_fetch),
        .present = !!(pfec & PFEC_page_present),
    };

    /* These bits are mutually exclusive */
    if ( pfec & NPT_PFEC_with_gla )
        npfec.kind = npfec_kind_with_gla;
    else if ( pfec & NPT_PFEC_in_gpt )
        npfec.kind = npfec_kind_in_gpt;

    npfec.idt_vectoring = idt_vec;

    ret = hvm_hap_nested_page_fault(gpa, ~0ul, npfec);

    if ( tb_init_done )
    {
        struct {
            uint64_t gpa;
            uint64_t mfn;
            uint32_t qualification;
            uint32_t p2mt;
        } _d;

        p2m = p2m_get_p2m(v);
        mfn = __get_gfn_type_access(p2m, gfn, &p2mt, &p2ma, 0, NULL, 0);

        _d.gpa = gpa;
        _d.qualification = 0;
        _d.mfn = mfn_x(mfn);
        _d.p2mt = p2mt;

        __trace_var(TRC_HVM_NPF, 0, sizeof(_d), &_d);
    }

    switch ( ret )
    {
    case 1:
        return;
    case -1:
        ASSERT(nestedhvm_enabled(v->domain) && nestedhvm_vcpu_in_guestmode(v));
        /* inject #VMEXIT(NPF) into guest. */
        nestedsvm_vmexit_defer(v, VMEXIT_NPF, pfec, gpa);
        return;
    }

    /* Everything else is an error. */
    if ( p2m == NULL )
    {
        p2m = p2m_get_p2m(v);
        mfn = __get_gfn_type_access(p2m, gfn, &p2mt, &p2ma, 0, NULL, 0);
    }
    gdprintk(XENLOG_ERR,
         "SVM violation gpa %#"PRIpaddr", mfn %#lx, type %i %s\n",
         gpa, mfn_x(mfn), p2mt, idt_vec ? "IDT vectoring" : "");
    domain_crash(v->domain);
}

static void svm_fpu_dirty_intercept(void)
{
    struct vcpu *v = current;
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    struct vmcb_struct *n1vmcb = vcpu_nestedhvm(v).nv_n1vmcx;

    svm_fpu_enter(v);

    if ( vmcb != n1vmcb )
    {
       /* Check if l1 guest must make FPU ready for the l2 guest */
       if ( v->arch.hvm.guest_cr[0] & X86_CR0_TS )
           hvm_inject_hw_exception(TRAP_no_device, X86_EVENT_NO_EC);
       else
           vmcb_set_cr0(n1vmcb, vmcb_get_cr0(n1vmcb) & ~X86_CR0_TS);
       return;
    }

    if ( !(v->arch.hvm.guest_cr[0] & X86_CR0_TS) )
        vmcb_set_cr0(vmcb, vmcb_get_cr0(vmcb) & ~X86_CR0_TS);
}

static void svm_vmexit_do_cr_access(
    struct vmcb_struct *vmcb, struct cpu_user_regs *regs)
{
    int gp, cr, dir, rc;

    cr = vmcb->exitcode - VMEXIT_CR0_READ;
    dir = (cr > 15);
    cr &= 0xf;
    gp = vmcb->exitinfo1 & 0xf;

    rc = dir ? hvm_mov_to_cr(cr, gp) : hvm_mov_from_cr(cr, gp);

    if ( rc == X86EMUL_OKAY )
        __update_guest_eip(regs, vmcb->nextrip - vmcb->rip);
}

static void svm_dr_access(struct vcpu *v, struct cpu_user_regs *regs)
{
    struct vmcb_struct *vmcb = vcpu_nestedhvm(v).nv_n1vmcx;

    HVMTRACE_0D(DR_WRITE);
    __restore_debug_registers(vmcb, v);
}

static int svm_msr_read_intercept(unsigned int msr, uint64_t *msr_content)
{
    struct vcpu *v = current;
    const struct domain *d = v->domain;
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    const struct nestedsvm *nsvm = &vcpu_nestedsvm(v);
    uint64_t tmp;

    switch ( msr )
    {
        /*
         * Sync not needed while the cross-vendor logic is in unilateral effect.
    case MSR_IA32_SYSENTER_CS:
    case MSR_IA32_SYSENTER_ESP:
    case MSR_IA32_SYSENTER_EIP:
         */
    case MSR_STAR:
    case MSR_LSTAR:
    case MSR_CSTAR:
    case MSR_SYSCALL_MASK:
    case MSR_FS_BASE:
    case MSR_GS_BASE:
    case MSR_SHADOW_GS_BASE:
        svm_sync_vmcb(v, vmcb_in_sync);
        break;
    }

    switch ( msr )
    {
    case MSR_IA32_SYSENTER_CS:
        *msr_content = v->arch.hvm.svm.guest_sysenter_cs;
        break;
    case MSR_IA32_SYSENTER_ESP:
        *msr_content = v->arch.hvm.svm.guest_sysenter_esp;
        break;
    case MSR_IA32_SYSENTER_EIP:
        *msr_content = v->arch.hvm.svm.guest_sysenter_eip;
        break;

    case MSR_STAR:
        *msr_content = vmcb->star;
        break;

    case MSR_LSTAR:
        *msr_content = vmcb->lstar;
        break;

    case MSR_CSTAR:
        *msr_content = vmcb->cstar;
        break;

    case MSR_SYSCALL_MASK:
        *msr_content = vmcb->sfmask;
        break;

    case MSR_FS_BASE:
        *msr_content = vmcb->fs.base;
        break;

    case MSR_GS_BASE:
        *msr_content = vmcb->gs.base;
        break;

    case MSR_SHADOW_GS_BASE:
        *msr_content = vmcb->kerngsbase;
        break;

    case MSR_IA32_MCx_MISC(4): /* Threshold register */
    case MSR_F10_MC4_MISC1 ... MSR_F10_MC4_MISC3:
        /*
         * MCA/MCE: We report that the threshold register is unavailable
         * for OS use (locked by the BIOS).
         */
        *msr_content = 1ULL << 61; /* MC4_MISC.Locked */
        break;

    case MSR_F10_BU_CFG:
        if ( !rdmsr_safe(msr, *msr_content) )
            break;

        if ( boot_cpu_data.x86 == 0xf )
        {
            /*
             * Win2k8 x64 reads this MSR on revF chips, where it wasn't
             * publically available; it uses a magic constant in %rdi as a
             * password, which we don't have in rdmsr_safe().  Since we'll
             * throw a #GP for later writes, just use a plausible value here
             * (the reset value from rev10h chips) if the real CPU didn't
             * provide one.
             */
            *msr_content = 0x10200020;
            break;
        }
        goto gpf;

    case MSR_F10_BU_CFG2:
        if ( rdmsr_safe(msr, *msr_content) )
            goto gpf;
        break;

    case MSR_IA32_EBC_FREQUENCY_ID:
        /*
         * This Intel-only register may be accessed if this HVM guest
         * has been migrated from an Intel host. The value zero is not
         * particularly meaningful, but at least avoids the guest crashing!
         */
        *msr_content = 0;
        break;

    case MSR_IA32_DEBUGCTLMSR:
        *msr_content = vmcb_get_debugctlmsr(vmcb);
        break;

    case MSR_IA32_LASTBRANCHFROMIP:
        *msr_content = vmcb_get_lastbranchfromip(vmcb);
        break;

    case MSR_IA32_LASTBRANCHTOIP:
        *msr_content = vmcb_get_lastbranchtoip(vmcb);
        break;

    case MSR_IA32_LASTINTFROMIP:
        *msr_content = vmcb_get_lastintfromip(vmcb);
        break;

    case MSR_IA32_LASTINTTOIP:
        *msr_content = vmcb_get_lastinttoip(vmcb);
        break;

    case MSR_K7_PERFCTR0:
    case MSR_K7_PERFCTR1:
    case MSR_K7_PERFCTR2:
    case MSR_K7_PERFCTR3:
    case MSR_K7_EVNTSEL0:
    case MSR_K7_EVNTSEL1:
    case MSR_K7_EVNTSEL2:
    case MSR_K7_EVNTSEL3:
    case MSR_AMD_FAM15H_PERFCTR0:
    case MSR_AMD_FAM15H_PERFCTR1:
    case MSR_AMD_FAM15H_PERFCTR2:
    case MSR_AMD_FAM15H_PERFCTR3:
    case MSR_AMD_FAM15H_PERFCTR4:
    case MSR_AMD_FAM15H_PERFCTR5:
    case MSR_AMD_FAM15H_EVNTSEL0:
    case MSR_AMD_FAM15H_EVNTSEL1:
    case MSR_AMD_FAM15H_EVNTSEL2:
    case MSR_AMD_FAM15H_EVNTSEL3:
    case MSR_AMD_FAM15H_EVNTSEL4:
    case MSR_AMD_FAM15H_EVNTSEL5:
        if ( vpmu_do_rdmsr(msr, msr_content) )
            goto gpf;
        break;

    case MSR_K8_SYSCFG:
    case MSR_K8_TOP_MEM1:
    case MSR_K8_TOP_MEM2:
    case MSR_K8_VM_CR:
    case MSR_AMD64_EX_CFG:
        *msr_content = 0;
        break;

    case MSR_K8_VM_HSAVE_PA:
        *msr_content = nsvm->ns_msr_hsavepa;
        break;

    case MSR_AMD64_TSC_RATIO:
        *msr_content = nsvm->ns_tscratio;
        break;

    case MSR_AMD_OSVW_ID_LENGTH:
    case MSR_AMD_OSVW_STATUS:
        if ( !d->arch.cpuid->extd.osvw )
            goto gpf;
        *msr_content = d->arch.hvm.svm.osvw.raw[msr - MSR_AMD_OSVW_ID_LENGTH];
        break;

    default:
        if ( d->arch.msr_relaxed && !rdmsr_safe(msr, tmp) )
        {
            *msr_content = 0;
            break;
        }

        gdprintk(XENLOG_WARNING, "RDMSR 0x%08x unimplemented\n", msr);
        goto gpf;
    }

    HVM_DBG_LOG(DBG_LEVEL_MSR, "returns: ecx=%x, msr_value=%"PRIx64,
                msr, *msr_content);
    return X86EMUL_OKAY;

 gpf:
    return X86EMUL_EXCEPTION;
}

static int svm_msr_write_intercept(unsigned int msr, uint64_t msr_content)
{
    struct vcpu *v = current;
    struct domain *d = v->domain;
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    struct nestedsvm *nsvm = &vcpu_nestedsvm(v);

    switch ( msr )
    {
    case MSR_IA32_SYSENTER_CS:
    case MSR_IA32_SYSENTER_ESP:
    case MSR_IA32_SYSENTER_EIP:
    case MSR_STAR:
    case MSR_LSTAR:
    case MSR_CSTAR:
    case MSR_SYSCALL_MASK:
    case MSR_FS_BASE:
    case MSR_GS_BASE:
    case MSR_SHADOW_GS_BASE:
        svm_sync_vmcb(v, vmcb_needs_vmload);
        break;
    }

    switch ( msr )
    {
    case MSR_IA32_SYSENTER_ESP:
    case MSR_IA32_SYSENTER_EIP:
    case MSR_LSTAR:
    case MSR_CSTAR:
    case MSR_FS_BASE:
    case MSR_GS_BASE:
    case MSR_SHADOW_GS_BASE:
        if ( !is_canonical_address(msr_content) )
            goto gpf;

        switch ( msr )
        {
        case MSR_IA32_SYSENTER_ESP:
            vmcb->sysenter_esp = v->arch.hvm.svm.guest_sysenter_esp = msr_content;
            break;

        case MSR_IA32_SYSENTER_EIP:
            vmcb->sysenter_eip = v->arch.hvm.svm.guest_sysenter_eip = msr_content;
            break;

        case MSR_LSTAR:
            vmcb->lstar = msr_content;
            break;

        case MSR_CSTAR:
            vmcb->cstar = msr_content;
            break;

        case MSR_FS_BASE:
            vmcb->fs.base = msr_content;
            break;

        case MSR_GS_BASE:
            vmcb->gs.base = msr_content;
            break;

        case MSR_SHADOW_GS_BASE:
            vmcb->kerngsbase = msr_content;
            break;
        }
        break;

    case MSR_IA32_SYSENTER_CS:
        vmcb->sysenter_cs = v->arch.hvm.svm.guest_sysenter_cs = msr_content;
        break;

    case MSR_STAR:
        vmcb->star = msr_content;
        break;

    case MSR_SYSCALL_MASK:
        vmcb->sfmask = msr_content;
        break;

    case MSR_IA32_DEBUGCTLMSR:
        vmcb_set_debugctlmsr(vmcb, msr_content);
        if ( !msr_content || !cpu_has_svm_lbrv )
            break;
        vmcb->virt_ext.fields.lbr_enable = 1;
        svm_disable_intercept_for_msr(v, MSR_IA32_DEBUGCTLMSR);
        svm_disable_intercept_for_msr(v, MSR_IA32_LASTBRANCHFROMIP);
        svm_disable_intercept_for_msr(v, MSR_IA32_LASTBRANCHTOIP);
        svm_disable_intercept_for_msr(v, MSR_IA32_LASTINTFROMIP);
        svm_disable_intercept_for_msr(v, MSR_IA32_LASTINTTOIP);
        break;

    case MSR_IA32_LASTBRANCHFROMIP:
        vmcb_set_lastbranchfromip(vmcb, msr_content);
        break;

    case MSR_IA32_LASTBRANCHTOIP:
        vmcb_set_lastbranchtoip(vmcb, msr_content);
        break;

    case MSR_IA32_LASTINTFROMIP:
        vmcb_set_lastintfromip(vmcb, msr_content);
        break;

    case MSR_IA32_LASTINTTOIP:
        vmcb_set_lastinttoip(vmcb, msr_content);
        break;

    case MSR_K7_PERFCTR0:
    case MSR_K7_PERFCTR1:
    case MSR_K7_PERFCTR2:
    case MSR_K7_PERFCTR3:
    case MSR_K7_EVNTSEL0:
    case MSR_K7_EVNTSEL1:
    case MSR_K7_EVNTSEL2:
    case MSR_K7_EVNTSEL3:
    case MSR_AMD_FAM15H_PERFCTR0:
    case MSR_AMD_FAM15H_PERFCTR1:
    case MSR_AMD_FAM15H_PERFCTR2:
    case MSR_AMD_FAM15H_PERFCTR3:
    case MSR_AMD_FAM15H_PERFCTR4:
    case MSR_AMD_FAM15H_PERFCTR5:
    case MSR_AMD_FAM15H_EVNTSEL0:
    case MSR_AMD_FAM15H_EVNTSEL1:
    case MSR_AMD_FAM15H_EVNTSEL2:
    case MSR_AMD_FAM15H_EVNTSEL3:
    case MSR_AMD_FAM15H_EVNTSEL4:
    case MSR_AMD_FAM15H_EVNTSEL5:
        if ( vpmu_do_wrmsr(msr, msr_content) )
            goto gpf;
        break;

    case MSR_K8_TOP_MEM1:
    case MSR_K8_TOP_MEM2:
    case MSR_K8_SYSCFG:
    case MSR_K8_VM_CR:
    case MSR_AMD64_EX_CFG:
        /* ignore write. handle all bits as read-only. */
        break;

    case MSR_K8_VM_HSAVE_PA:
        if ( (msr_content & ~PAGE_MASK) || msr_content > 0xfd00000000ULL )
            goto gpf;
        nsvm->ns_msr_hsavepa = msr_content;
        break;

    case MSR_F10_BU_CFG:
    case MSR_F10_BU_CFG2:
        if ( rdmsr_safe(msr, msr_content) )
            goto gpf;
        break;

    case MSR_AMD64_TSC_RATIO:
        if ( msr_content & TSC_RATIO_RSVD_BITS )
            goto gpf;
        nsvm->ns_tscratio = msr_content;
        break;

    case MSR_IA32_MCx_MISC(4): /* Threshold register */
    case MSR_F10_MC4_MISC1 ... MSR_F10_MC4_MISC3:
        /*
         * MCA/MCE: Threshold register is reported to be locked, so we ignore
         * all write accesses. This behaviour matches real HW, so guests should
         * have no problem with this.
         */
        break;

    case MSR_AMD_OSVW_ID_LENGTH:
    case MSR_AMD_OSVW_STATUS:
        if ( !d->arch.cpuid->extd.osvw )
            goto gpf;
        /* Write-discard */
        break;

    default:
        if ( d->arch.msr_relaxed && !rdmsr_safe(msr, msr_content) )
            break;

        gdprintk(XENLOG_WARNING,
                 "WRMSR 0x%08x val 0x%016"PRIx64" unimplemented\n",
                 msr, msr_content);
        goto gpf;
    }

    return X86EMUL_OKAY;

 gpf:
    return X86EMUL_EXCEPTION;
}

static void svm_do_msr_access(struct cpu_user_regs *regs)
{
    struct vcpu *curr = current;
    bool rdmsr = curr->arch.hvm.svm.vmcb->exitinfo1 == 0;
    int rc, inst_len = svm_get_insn_len(curr, rdmsr ? INSTR_RDMSR
                                                    : INSTR_WRMSR);

    if ( inst_len == 0 )
        return;

    if ( rdmsr )
    {
        uint64_t msr_content = 0;

        rc = hvm_msr_read_intercept(regs->ecx, &msr_content);
        if ( rc == X86EMUL_OKAY )
            msr_split(regs, msr_content);
    }
    else
        rc = hvm_msr_write_intercept(regs->ecx, msr_fold(regs), true);

    if ( rc == X86EMUL_OKAY )
        __update_guest_eip(regs, inst_len);
    else if ( rc == X86EMUL_EXCEPTION )
        hvm_inject_hw_exception(TRAP_gp_fault, 0);
}

static void svm_vmexit_do_hlt(struct vmcb_struct *vmcb,
                              struct cpu_user_regs *regs)
{
    unsigned int inst_len;

    if ( (inst_len = svm_get_insn_len(current, INSTR_HLT)) == 0 )
        return;
    __update_guest_eip(regs, inst_len);

    hvm_hlt(regs->eflags);
}

static void svm_vmexit_do_rdtsc(struct cpu_user_regs *regs, bool rdtscp)
{
    struct vcpu *curr = current;
    const struct domain *currd = curr->domain;
    unsigned int inst_len;

    if ( rdtscp && !currd->arch.cpuid->extd.rdtscp )
    {
        hvm_inject_hw_exception(TRAP_invalid_op, X86_EVENT_NO_EC);
        return;
    }

    if ( (inst_len = svm_get_insn_len(curr, rdtscp ? INSTR_RDTSCP
                                                   : INSTR_RDTSC)) == 0 )
        return;

    __update_guest_eip(regs, inst_len);

    if ( rdtscp )
        regs->rcx = curr->arch.msrs->tsc_aux;

    hvm_rdtsc_intercept(regs);
}

static void svm_vmexit_do_pause(struct cpu_user_regs *regs)
{
    unsigned int inst_len;

    if ( (inst_len = svm_get_insn_len(current, INSTR_PAUSE)) == 0 )
        return;
    __update_guest_eip(regs, inst_len);

    /*
     * The guest is running a contended spinlock and we've detected it.
     * Do something useful, like reschedule the guest
     */
    perfc_incr(pauseloop_exits);
    do_sched_op(SCHEDOP_yield, guest_handle_from_ptr(NULL, void));
}

static void
svm_vmexit_do_vmrun(struct cpu_user_regs *regs,
                    struct vcpu *v, uint64_t vmcbaddr)
{
    if ( !nsvm_efer_svm_enabled(v) )
    {
        hvm_inject_hw_exception(TRAP_invalid_op, X86_EVENT_NO_EC);
        return;
    }

    if ( !nestedsvm_vmcb_map(v, vmcbaddr) )
    {
        gdprintk(XENLOG_ERR, "VMRUN: mapping vmcb failed, injecting #GP\n");
        hvm_inject_hw_exception(TRAP_gp_fault, 0);
        return;
    }

    vcpu_nestedhvm(v).nv_vmentry_pending = 1;
    return;
}

static struct page_info *
nsvm_get_nvmcb_page(struct vcpu *v, uint64_t vmcbaddr)
{
    p2m_type_t p2mt;
    struct page_info *page;
    struct nestedvcpu *nv = &vcpu_nestedhvm(v);

    if ( !nestedsvm_vmcb_map(v, vmcbaddr) )
        return NULL;

    /* Need to translate L1-GPA to MPA */
    page = get_page_from_gfn(v->domain, nv->nv_vvmcxaddr >> PAGE_SHIFT,
                             &p2mt, P2M_ALLOC | P2M_UNSHARE);
    if ( !page )
        return NULL;

    if ( !p2m_is_ram(p2mt) || p2m_is_readonly(p2mt) )
    {
        put_page(page);
        return NULL;
    }

    return  page;
}

static void
svm_vmexit_do_vmload(struct vmcb_struct *vmcb,
                     struct cpu_user_regs *regs,
                     struct vcpu *v, uint64_t vmcbaddr)
{
    unsigned int inst_len;
    struct page_info *page;

    if ( (inst_len = svm_get_insn_len(v, INSTR_VMLOAD)) == 0 )
        return;

    if ( !nsvm_efer_svm_enabled(v) )
    {
        hvm_inject_hw_exception(TRAP_invalid_op, X86_EVENT_NO_EC);
        return;
    }

    page = nsvm_get_nvmcb_page(v, vmcbaddr);
    if ( !page )
    {
        gdprintk(XENLOG_ERR,
            "VMLOAD: mapping failed, injecting #GP\n");
        hvm_inject_hw_exception(TRAP_gp_fault, 0);
        return;
    }

    svm_vmload_pa(page_to_maddr(page));
    put_page(page);

    /* State in L1 VMCB is stale now */
    v->arch.hvm.svm.vmcb_sync_state = vmcb_needs_vmsave;

    __update_guest_eip(regs, inst_len);
}

static void
svm_vmexit_do_vmsave(struct vmcb_struct *vmcb,
                     struct cpu_user_regs *regs,
                     struct vcpu *v, uint64_t vmcbaddr)
{
    unsigned int inst_len;
    struct page_info *page;

    if ( (inst_len = svm_get_insn_len(v, INSTR_VMSAVE)) == 0 )
        return;

    if ( !nsvm_efer_svm_enabled(v) )
    {
        hvm_inject_hw_exception(TRAP_invalid_op, X86_EVENT_NO_EC);
        return;
    }

    page = nsvm_get_nvmcb_page(v, vmcbaddr);
    if ( !page )
    {
        gdprintk(XENLOG_ERR,
            "VMSAVE: mapping vmcb failed, injecting #GP\n");
        hvm_inject_hw_exception(TRAP_gp_fault, 0);
        return;
    }

    svm_vmsave_pa(page_to_maddr(page));
    put_page(page);
    __update_guest_eip(regs, inst_len);
}

static int svm_is_erratum_383(struct cpu_user_regs *regs)
{
    uint64_t msr_content;
    uint32_t i;
    struct vcpu *v = current;

    if ( !amd_erratum383_found )
        return 0;

    rdmsrl(MSR_IA32_MC0_STATUS, msr_content);
    /* Bit 62 may or may not be set for this mce */
    msr_content &= ~(1ULL << 62);

    if ( msr_content != 0xb600000000010015ULL )
        return 0;

    /* Clear MCi_STATUS registers */
    for ( i = 0; i < this_cpu(nr_mce_banks); i++ )
        wrmsrl(MSR_IA32_MCx_STATUS(i), 0ULL);

    rdmsrl(MSR_IA32_MCG_STATUS, msr_content);
    wrmsrl(MSR_IA32_MCG_STATUS, msr_content & ~(1ULL << 2));

    /* flush TLB */
    flush_tlb_mask(v->domain->dirty_cpumask);

    return 1;
}

static void svm_vmexit_mce_intercept(
    struct vcpu *v, struct cpu_user_regs *regs)
{
    if ( svm_is_erratum_383(regs) )
    {
        gdprintk(XENLOG_ERR, "SVM hits AMD erratum 383\n");
        domain_crash(v->domain);
    }
}

static void svm_wbinvd_intercept(void)
{
    if ( cache_flush_permitted(current->domain) )
        flush_all(FLUSH_CACHE);
}

static void svm_vmexit_do_invalidate_cache(struct cpu_user_regs *regs,
                                           bool invld)
{
    unsigned int inst_len = svm_get_insn_len(current, invld ? INSTR_INVD
                                                            : INSTR_WBINVD);

    if ( inst_len == 0 )
        return;

    svm_wbinvd_intercept();

    __update_guest_eip(regs, inst_len);
}

static void svm_invlpga_intercept(
    struct vcpu *v, unsigned long linear, uint32_t asid)
{
    svm_invlpga(linear,
                (asid == 0)
                ? v->arch.hvm.n1asid.asid
                : vcpu_nestedhvm(v).nv_n2asid.asid);
}

static void svm_invlpg_intercept(unsigned long linear)
{
    HVMTRACE_LONG_2D(INVLPG, 0, TRC_PAR_LONG(linear));
    paging_invlpg(current, linear);
}

static bool is_invlpg(const struct x86_emulate_state *state,
                      const struct x86_emulate_ctxt *ctxt)
{
    unsigned int ext;

    return ctxt->opcode == X86EMUL_OPC(0x0f, 0x01) &&
           x86_insn_modrm(state, NULL, &ext) != 3 &&
           (ext & 7) == 7;
}

static void svm_invlpg(struct vcpu *v, unsigned long linear)
{
    svm_asid_g_invlpg(v, linear);
}

static bool svm_get_pending_event(struct vcpu *v, struct x86_event *info)
{
    const struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;

    if ( vmcb->event_inj.v )
        return false;

    info->vector = vmcb->event_inj.vector;
    info->type = vmcb->event_inj.type;
    info->error_code = vmcb->event_inj.ec;

    return true;
}

static uint64_t svm_get_reg(struct vcpu *v, unsigned int reg)
{
    const struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    struct domain *d = v->domain;

    switch ( reg )
    {
    case MSR_SPEC_CTRL:
        return vmcb->spec_ctrl;

    default:
        printk(XENLOG_G_ERR "%s(%pv, 0x%08x) Bad register\n",
               __func__, v, reg);
        domain_crash(d);
        return 0;
    }
}

static void svm_set_reg(struct vcpu *v, unsigned int reg, uint64_t val)
{
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    struct domain *d = v->domain;

    switch ( reg )
    {
    case MSR_SPEC_CTRL:
        vmcb->spec_ctrl = val;
        break;

    default:
        printk(XENLOG_G_ERR "%s(%pv, 0x%08x, 0x%016"PRIx64") Bad register\n",
               __func__, v, reg, val);
        domain_crash(d);
    }
}

static struct hvm_function_table __initdata svm_function_table = {
    .name                 = "SVM",
    .cpu_up_prepare       = svm_cpu_up_prepare,
    .cpu_dead             = svm_cpu_dead,
    .cpu_up               = svm_cpu_up,
    .cpu_down             = svm_cpu_down,
    .domain_initialise    = svm_domain_initialise,
    .vcpu_initialise      = svm_vcpu_initialise,
    .vcpu_destroy         = svm_vcpu_destroy,
    .save_cpu_ctxt        = svm_save_vmcb_ctxt,
    .load_cpu_ctxt        = svm_load_vmcb_ctxt,
    .get_interrupt_shadow = svm_get_interrupt_shadow,
    .set_interrupt_shadow = svm_set_interrupt_shadow,
    .guest_x86_mode       = svm_guest_x86_mode,
    .get_cpl              = svm_get_cpl,
    .get_segment_register = svm_get_segment_register,
    .set_segment_register = svm_set_segment_register,
    .get_shadow_gs_base   = svm_get_shadow_gs_base,
    .update_guest_cr      = svm_update_guest_cr,
    .update_guest_efer    = svm_update_guest_efer,
    .cpuid_policy_changed = svm_cpuid_policy_changed,
    .fpu_leave            = svm_fpu_leave,
    .set_guest_pat        = svm_set_guest_pat,
    .get_guest_pat        = svm_get_guest_pat,
    .set_tsc_offset       = svm_set_tsc_offset,
    .inject_event         = svm_inject_event,
    .init_hypercall_page  = svm_init_hypercall_page,
    .event_pending        = svm_event_pending,
    .get_pending_event    = svm_get_pending_event,
    .invlpg               = svm_invlpg,
    .wbinvd_intercept     = svm_wbinvd_intercept,
    .fpu_dirty_intercept  = svm_fpu_dirty_intercept,
    .msr_read_intercept   = svm_msr_read_intercept,
    .msr_write_intercept  = svm_msr_write_intercept,
    .enable_msr_interception = svm_enable_msr_interception,
    .set_rdtsc_exiting    = svm_set_rdtsc_exiting,
    .set_descriptor_access_exiting = svm_set_descriptor_access_exiting,
    .get_insn_bytes       = svm_get_insn_bytes,

    .nhvm_vcpu_initialise = nsvm_vcpu_initialise,
    .nhvm_vcpu_destroy = nsvm_vcpu_destroy,
    .nhvm_vcpu_reset = nsvm_vcpu_reset,
    .nhvm_vcpu_vmexit_event = nsvm_vcpu_vmexit_event,
    .nhvm_vcpu_p2m_base = nsvm_vcpu_hostcr3,
    .nhvm_vmcx_guest_intercepts_event = nsvm_vmcb_guest_intercepts_event,
    .nhvm_vmcx_hap_enabled = nsvm_vmcb_hap_enabled,
    .nhvm_intr_blocked = nsvm_intr_blocked,
    .nhvm_hap_walk_L1_p2m = nsvm_hap_walk_L1_p2m,

    .get_reg = svm_get_reg,
    .set_reg = svm_set_reg,

    .tsc_scaling = {
        .max_ratio = ~TSC_RATIO_RSVD_BITS,
    },
};

void svm_vmexit_handler(struct cpu_user_regs *regs)
{
    uint64_t exit_reason;
    struct vcpu *v = current;
    struct vmcb_struct *vmcb = v->arch.hvm.svm.vmcb;
    int insn_len, rc;
    vintr_t intr;
    bool_t vcpu_guestmode = 0;
    struct vlapic *vlapic = vcpu_vlapic(v);

    regs->rax = vmcb->rax;
    regs->rip = vmcb->rip;
    regs->rsp = vmcb->rsp;
    regs->rflags = vmcb->rflags;

    hvm_invalidate_regs_fields(regs);

    if ( paging_mode_hap(v->domain) )
        v->arch.hvm.guest_cr[3] = v->arch.hvm.hw_cr[3] = vmcb_get_cr3(vmcb);

    if ( nestedhvm_enabled(v->domain) && nestedhvm_vcpu_in_guestmode(v) )
        vcpu_guestmode = 1;

    /*
     * Before doing anything else, we need to sync up the VLAPIC's TPR with
     * SVM's vTPR. It's OK if the guest doesn't touch CR8 (e.g. 32-bit Windows)
     * because we update the vTPR on MMIO writes to the TPR.
     * NB. We need to preserve the low bits of the TPR to make checked builds
     * of Windows work, even though they don't actually do anything.
     */
    if ( !vcpu_guestmode && !vlapic_hw_disabled(vlapic) )
    {
        intr = vmcb_get_vintr(vmcb);
        vlapic_set_reg(vlapic, APIC_TASKPRI,
                   ((intr.fields.tpr & 0x0F) << 4) |
                   (vlapic_get_reg(vlapic, APIC_TASKPRI) & 0x0F));
    }

    exit_reason = vmcb->exitcode;

    if ( hvm_long_mode_active(v) )
        HVMTRACE_ND(VMEXIT64, vcpu_guestmode ? TRC_HVM_NESTEDFLAG : 0,
                    1/*cycles*/, exit_reason, TRC_PAR_LONG(regs->rip));
    else
        HVMTRACE_ND(VMEXIT, vcpu_guestmode ? TRC_HVM_NESTEDFLAG : 0,
                    1/*cycles*/, exit_reason, regs->eip);

    if ( vcpu_guestmode )
    {
        enum nestedhvm_vmexits nsret;
        struct nestedvcpu *nv = &vcpu_nestedhvm(v);
        struct vmcb_struct *ns_vmcb = nv->nv_vvmcx;
        uint64_t exitinfo1, exitinfo2;

        paging_update_nestedmode(v);

        /* Write real exitinfo1 back into virtual vmcb.
         * nestedsvm_check_intercepts() expects to have the correct
         * exitinfo1 value there.
         */
        exitinfo1 = ns_vmcb->exitinfo1;
        ns_vmcb->exitinfo1 = vmcb->exitinfo1;
        nsret = nestedsvm_check_intercepts(v, regs, exit_reason);
        switch ( nsret )
        {
        case NESTEDHVM_VMEXIT_CONTINUE:
            BUG();
            break;
        case NESTEDHVM_VMEXIT_HOST:
            break;
        case NESTEDHVM_VMEXIT_INJECT:
            /* Switch vcpu from l2 to l1 guest. We must perform
             * the switch here to have svm_do_resume() working
             * as intended.
             */
            exitinfo1 = vmcb->exitinfo1;
            exitinfo2 = vmcb->exitinfo2;
            nv->nv_vmswitch_in_progress = 1;
            nsret = nestedsvm_vmexit_n2n1(v, regs);
            nv->nv_vmswitch_in_progress = 0;
            switch ( nsret )
            {
            case NESTEDHVM_VMEXIT_DONE:
                /* defer VMEXIT injection */
                nestedsvm_vmexit_defer(v, exit_reason, exitinfo1, exitinfo2);
                goto out;
            case NESTEDHVM_VMEXIT_FATALERROR:
                gdprintk(XENLOG_ERR, "unexpected nestedsvm_vmexit() error\n");
                domain_crash(v->domain);
                goto out;
            default:
                BUG();
            case NESTEDHVM_VMEXIT_ERROR:
                break;
            }
            /* fallthrough */
        case NESTEDHVM_VMEXIT_ERROR:
            gdprintk(XENLOG_ERR,
                "nestedsvm_check_intercepts() returned NESTEDHVM_VMEXIT_ERROR\n");
            goto out;
        case NESTEDHVM_VMEXIT_FATALERROR:
            gdprintk(XENLOG_ERR,
                "unexpected nestedsvm_check_intercepts() error\n");
            domain_crash(v->domain);
            goto out;
        default:
            gdprintk(XENLOG_INFO, "nestedsvm_check_intercepts() returned %i\n",
                nsret);
            domain_crash(v->domain);
            goto out;
        }
    }

    if ( unlikely(exit_reason == VMEXIT_INVALID) )
    {
        gdprintk(XENLOG_ERR, "invalid VMCB state:\n");
        svm_vmcb_dump(__func__, vmcb);
        domain_crash(v->domain);
        goto out;
    }

    perfc_incra(svmexits, exit_reason);

    hvm_maybe_deassert_evtchn_irq();

    vmcb->cleanbits.raw = ~0u;

    /* Event delivery caused this intercept? Queue for redelivery. */
    if ( unlikely(vmcb->exit_int_info.v) &&
         hvm_event_needs_reinjection(vmcb->exit_int_info.type,
                                     vmcb->exit_int_info.vector) )
        vmcb->event_inj = vmcb->exit_int_info;

    switch ( exit_reason )
    {
    case VMEXIT_INTR:
        /* Asynchronous event, handled when we STGI'd after the VMEXIT. */
        HVMTRACE_0D(INTR);
        break;

    case VMEXIT_NMI:
        /* Asynchronous event, handled when we STGI'd after the VMEXIT. */
        HVMTRACE_0D(NMI);
        break;

    case VMEXIT_SMI:
        /* Asynchronous event, handled when we STGI'd after the VMEXIT. */
        HVMTRACE_0D(SMI);
        break;

    case VMEXIT_ICEBP:
    case VMEXIT_EXCEPTION_DB:
        if ( !v->domain->debugger_attached )
        {
            unsigned int trap_type;

            if ( likely(exit_reason != VMEXIT_ICEBP) )
            {
                trap_type = X86_EVENTTYPE_HW_EXCEPTION;
                insn_len = 0;
            }
            else
            {
                trap_type = X86_EVENTTYPE_PRI_SW_EXCEPTION;
                insn_len = svm_get_insn_len(v, INSTR_ICEBP);

                if ( !insn_len )
                    break;
            }

            rc = hvm_monitor_debug(regs->rip,
                                   HVM_MONITOR_DEBUG_EXCEPTION,
                                   trap_type, insn_len, 0);
            if ( rc < 0 )
                goto unexpected_exit_type;
            if ( !rc )
                hvm_inject_exception(TRAP_debug,
                                     trap_type, insn_len, X86_EVENT_NO_EC);
        }
        else
            domain_pause_for_debugger();
        break;

    case VMEXIT_EXCEPTION_BP:
        insn_len = svm_get_insn_len(v, INSTR_INT3);

        if ( insn_len == 0 )
             break;

        if ( v->domain->debugger_attached )
        {
            /* AMD Vol2, 15.11: INT3, INTO, BOUND intercepts do not update RIP. */
            __update_guest_eip(regs, insn_len);
            current->arch.gdbsx_vcpu_event = TRAP_int3;
            domain_pause_for_debugger();
        }
        else
        {
           rc = hvm_monitor_debug(regs->rip,
                                  HVM_MONITOR_SOFTWARE_BREAKPOINT,
                                  X86_EVENTTYPE_SW_EXCEPTION,
                                  insn_len, 0);
           if ( rc < 0 )
               goto unexpected_exit_type;
           if ( !rc )
               hvm_inject_exception(TRAP_int3,
                                    X86_EVENTTYPE_SW_EXCEPTION,
                                    insn_len, X86_EVENT_NO_EC);
        }
        break;

    case VMEXIT_EXCEPTION_NM:
        svm_fpu_dirty_intercept();
        break;

    case VMEXIT_EXCEPTION_PF:
    {
        unsigned long va;
        va = vmcb->exitinfo2;
        regs->error_code = vmcb->exitinfo1;
        HVM_DBG_LOG(DBG_LEVEL_VMMU,
                    "eax=%lx, ebx=%lx, ecx=%lx, edx=%lx, esi=%lx, edi=%lx",
                    regs->rax, regs->rbx, regs->rcx,
                    regs->rdx, regs->rsi, regs->rdi);

        if ( cpu_has_svm_decode )
            v->arch.hvm.svm.cached_insn_len = vmcb->guest_ins_len & 0xf;
        rc = paging_fault(va, regs);
        v->arch.hvm.svm.cached_insn_len = 0;

        if ( rc )
        {
            if ( trace_will_trace_event(TRC_SHADOW) )
                break;
            if ( hvm_long_mode_active(v) )
                HVMTRACE_LONG_2D(PF_XEN, regs->error_code, TRC_PAR_LONG(va));
            else
                HVMTRACE_2D(PF_XEN, regs->error_code, va);
            break;
        }

        hvm_inject_page_fault(regs->error_code, va);
        break;
    }

    case VMEXIT_EXCEPTION_AC:
        HVMTRACE_1D(TRAP, TRAP_alignment_check);
        hvm_inject_hw_exception(TRAP_alignment_check, vmcb->exitinfo1);
        break;

    case VMEXIT_EXCEPTION_UD:
        hvm_ud_intercept(regs);
        break;

    /* Asynchronous event, handled when we STGI'd after the VMEXIT. */
    case VMEXIT_EXCEPTION_MC:
        HVMTRACE_0D(MCE);
        svm_vmexit_mce_intercept(v, regs);
        break;

    case VMEXIT_VINTR:
    {
        u32 general1_intercepts = vmcb_get_general1_intercepts(vmcb);
        intr = vmcb_get_vintr(vmcb);

        intr.fields.irq = 0;
        general1_intercepts &= ~GENERAL1_INTERCEPT_VINTR;

        vmcb_set_vintr(vmcb, intr);
        vmcb_set_general1_intercepts(vmcb, general1_intercepts);
        break;
    }

    case VMEXIT_INVD:
    case VMEXIT_WBINVD:
        svm_vmexit_do_invalidate_cache(regs, exit_reason == VMEXIT_INVD);
        break;

    case VMEXIT_TASK_SWITCH:
        /*
         * All TASK_SWITCH intercepts have fault-like semantics.  NRIP is
         * never provided, even for instruction-induced task switches, but we
         * need to know the instruction length in order to set %eip suitably
         * in the outgoing TSS.
         *
         * For a task switch which vectored through the IDT, look at the type
         * to distinguish interrupts/exceptions from instruction based
         * switches.
         */
        insn_len = -1;
        if ( vmcb->exit_int_info.v )
        {
            switch ( vmcb->exit_int_info.type )
            {
                /*
                 * #BP and #OF are from INT3/INTO respectively.  #DB from
                 * ICEBP is handled specially, and already has fault
                 * semantics.
                 */
            case X86_EVENTTYPE_HW_EXCEPTION:
                if ( vmcb->exit_int_info.vector == TRAP_int3 ||
                     vmcb->exit_int_info.vector == TRAP_overflow )
                    break;
                /* Fallthrough */
            case X86_EVENTTYPE_EXT_INTR:
            case X86_EVENTTYPE_NMI:
                insn_len = 0;
                break;
            }

            /*
             * The common logic above will have forwarded the vectoring
             * information.  Undo this as we are going to emulate.
             */
            vmcb->event_inj.raw = 0;
        }

        /*
         * insn_len being -1 indicates that we have an instruction-induced
         * task switch.  Decode under %rip to find its length.
         */
        if ( insn_len < 0 && (insn_len = svm_get_task_switch_insn_len()) == 0 )
            goto crash_or_fault;

        hvm_task_switch(vmcb->ei.task_switch.sel,
                        vmcb->ei.task_switch.iret ? TSW_iret :
                        vmcb->ei.task_switch.jmp  ? TSW_jmp  : TSW_call_or_int,
                        vmcb->ei.task_switch.ev ? vmcb->ei.task_switch.ec : -1,
                        insn_len, vmcb->ei.task_switch.rf ? X86_EFLAGS_RF : 0);
        break;

    case VMEXIT_CPUID:
        if ( (insn_len = svm_get_insn_len(v, INSTR_CPUID)) == 0 )
            break;

        rc = hvm_vmexit_cpuid(regs, insn_len);

        if ( rc < 0 )
            goto unexpected_exit_type;
        if ( !rc )
            __update_guest_eip(regs, insn_len);
        break;

    case VMEXIT_HLT:
        svm_vmexit_do_hlt(vmcb, regs);
        break;

    case VMEXIT_IOIO:
        if ( (vmcb->exitinfo1 & (1u<<2)) == 0 )
        {
            uint16_t port = (vmcb->exitinfo1 >> 16) & 0xFFFF;
            int bytes = ((vmcb->exitinfo1 >> 4) & 0x07);
            int dir = (vmcb->exitinfo1 & 1) ? IOREQ_READ : IOREQ_WRITE;
            if ( handle_pio(port, bytes, dir) )
                __update_guest_eip(regs, vmcb->exitinfo2 - vmcb->rip);
        }
        else if ( !hvm_emulate_one_insn(x86_insn_is_portio, "port I/O") )
            hvm_inject_hw_exception(TRAP_gp_fault, 0);
        break;

    case VMEXIT_CR0_READ ... VMEXIT_CR15_READ:
    case VMEXIT_CR0_WRITE ... VMEXIT_CR15_WRITE:
        if ( cpu_has_svm_decode && (vmcb->exitinfo1 & (1ULL << 63)) )
            svm_vmexit_do_cr_access(vmcb, regs);
        else if ( !hvm_emulate_one_insn(x86_insn_is_cr_access, "CR access") )
            hvm_inject_hw_exception(TRAP_gp_fault, 0);
        break;

    case VMEXIT_INVLPG:
        if ( cpu_has_svm_decode )
        {
            svm_invlpg_intercept(vmcb->exitinfo1);
            __update_guest_eip(regs, vmcb->nextrip - vmcb->rip);
        }
        else if ( !hvm_emulate_one_insn(is_invlpg, "invlpg") )
            hvm_inject_hw_exception(TRAP_gp_fault, 0);
        break;

    case VMEXIT_INVLPGA:
        if ( !nsvm_efer_svm_enabled(v) )
        {
            hvm_inject_hw_exception(TRAP_invalid_op, X86_EVENT_NO_EC);
            break;
        }
        if ( (insn_len = svm_get_insn_len(v, INSTR_INVLPGA)) == 0 )
            break;
        svm_invlpga_intercept(v, regs->rax, regs->ecx);
        __update_guest_eip(regs, insn_len);
        break;

    case VMEXIT_VMMCALL:
        if ( (insn_len = svm_get_insn_len(v, INSTR_VMCALL)) == 0 )
            break;
        BUG_ON(vcpu_guestmode);
        HVMTRACE_1D(VMMCALL, regs->eax);

        if ( hvm_hypercall(regs) == HVM_HCALL_completed )
            __update_guest_eip(regs, insn_len);
        break;

    case VMEXIT_DR0_READ ... VMEXIT_DR7_READ:
    case VMEXIT_DR0_WRITE ... VMEXIT_DR7_WRITE:
        svm_dr_access(v, regs);
        break;

    case VMEXIT_MSR:
        svm_do_msr_access(regs);
        break;

    case VMEXIT_SHUTDOWN:
        hvm_triple_fault();
        break;

    case VMEXIT_RDTSCP:
    case VMEXIT_RDTSC:
        svm_vmexit_do_rdtsc(regs, exit_reason == VMEXIT_RDTSCP);
        break;

    case VMEXIT_MONITOR:
    case VMEXIT_MWAIT:
    case VMEXIT_SKINIT:
    case VMEXIT_RDPRU:
        hvm_inject_hw_exception(TRAP_invalid_op, X86_EVENT_NO_EC);
        break;

    case VMEXIT_VMRUN:
        svm_vmexit_do_vmrun(regs, v, regs->rax);
        break;
    case VMEXIT_VMLOAD:
        svm_vmexit_do_vmload(vmcb, regs, v, regs->rax);
        break;
    case VMEXIT_VMSAVE:
        svm_vmexit_do_vmsave(vmcb, regs, v, regs->rax);
        break;
    case VMEXIT_STGI:
        svm_vmexit_do_stgi(regs, v);
        break;
    case VMEXIT_CLGI:
        svm_vmexit_do_clgi(regs, v);
        break;

    case VMEXIT_XSETBV:
        if ( vmcb_get_cpl(vmcb) )
            hvm_inject_hw_exception(TRAP_gp_fault, 0);
        else if ( (insn_len = svm_get_insn_len(v, INSTR_XSETBV)) &&
                  hvm_handle_xsetbv(regs->ecx, msr_fold(regs)) == X86EMUL_OKAY )
            __update_guest_eip(regs, insn_len);
        break;

    case VMEXIT_NPF:
        perfc_incra(svmexits, VMEXIT_NPF_PERFC);
        if ( cpu_has_svm_decode )
            v->arch.hvm.svm.cached_insn_len = vmcb->guest_ins_len & 0xf;
        rc = vmcb->exitinfo1 & PFEC_page_present
             ? p2m_pt_handle_deferred_changes(vmcb->exitinfo2) : 0;
        if ( rc == 0 )
            /* If no recal adjustments were being made - handle this fault */
            svm_do_nested_pgfault(v, regs, vmcb->exitinfo1, vmcb->exitinfo2,
                                  !!vmcb->exit_int_info.v);
        else if ( rc < 0 )
        {
            printk(XENLOG_G_ERR
                   "%pv: Error %d handling NPF (gpa=%08lx ec=%04lx)\n",
                   v, rc, vmcb->exitinfo2, vmcb->exitinfo1);
            domain_crash(v->domain);
        }
        v->arch.hvm.svm.cached_insn_len = 0;
        break;

    case VMEXIT_IRET:
    {
        u32 general1_intercepts = vmcb_get_general1_intercepts(vmcb);

        /*
         * IRET clears the NMI mask. However because we clear the mask
         * /before/ executing IRET, we set the interrupt shadow to prevent
         * a pending NMI from being injected immediately. This will work
         * perfectly unless the IRET instruction faults: in that case we
         * may inject an NMI before the NMI handler's IRET instruction is
         * retired.
         */
        general1_intercepts &= ~GENERAL1_INTERCEPT_IRET;
        vmcb->int_stat.intr_shadow = 1;

        vmcb_set_general1_intercepts(vmcb, general1_intercepts);
        break;
    }

    case VMEXIT_PAUSE:
        svm_vmexit_do_pause(regs);
        break;

    case VMEXIT_IDTR_READ ... VMEXIT_TR_WRITE:
    {
        /*
         * Consecutive block of 8 exit codes (sadly not aligned).  Top bit
         * indicates write (vs read), bottom 2 bits map linearly to
         * VM_EVENT_DESC_* values.
         */
#define E2D(e)      ((((e)         - VMEXIT_IDTR_READ) & 3) + 1)
        bool write = ((exit_reason - VMEXIT_IDTR_READ) & 4);
        unsigned int desc = E2D(exit_reason);

        BUILD_BUG_ON(E2D(VMEXIT_IDTR_READ) != VM_EVENT_DESC_IDTR);
        BUILD_BUG_ON(E2D(VMEXIT_GDTR_READ) != VM_EVENT_DESC_GDTR);
        BUILD_BUG_ON(E2D(VMEXIT_LDTR_READ) != VM_EVENT_DESC_LDTR);
        BUILD_BUG_ON(E2D(VMEXIT_TR_READ)   != VM_EVENT_DESC_TR);
#undef E2D

        hvm_descriptor_access_intercept(0, 0, desc, write);
        break;
    }

    default:
    unexpected_exit_type:
        gprintk(XENLOG_ERR, "Unexpected vmexit: reason %#"PRIx64", "
                "exitinfo1 %#"PRIx64", exitinfo2 %#"PRIx64"\n",
                exit_reason, vmcb->exitinfo1, vmcb->exitinfo2);
    crash_or_fault:
        svm_crash_or_fault(v);
        break;
    }

  out:
    if ( vcpu_guestmode || vlapic_hw_disabled(vlapic) )
        return;

    /* The exit may have updated the TPR: reflect this in the hardware vtpr */
    intr = vmcb_get_vintr(vmcb);
    intr.fields.tpr =
        (vlapic_get_reg(vlapic, APIC_TASKPRI) & 0xFF) >> 4;
    vmcb_set_vintr(vmcb, intr);
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
