/*
 * arch/x86/hvm/monitor.c
 *
 * Arch-specific hardware virtual machine event abstractions.
 *
 * Copyright (c) 2004, Intel Corporation.
 * Copyright (c) 2005, International Business Machines Corporation.
 * Copyright (c) 2008, Citrix Systems, Inc.
 * Copyright (c) 2016, Bitdefender S.R.L.
 * Copyright (c) 2016, Tamas K Lengyel (tamas@tklengyel.com)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/vm_event.h>
#include <xen/mem_access.h>
#include <xen/monitor.h>
#include <asm/hvm/monitor.h>
#include <asm/hvm/nestedhvm.h>
#include <asm/altp2m.h>
#include <asm/monitor.h>
#include <asm/p2m.h>
#include <asm/paging.h>
#include <asm/vm_event.h>
#include <public/vm_event.h>

static void set_npt_base(struct vcpu *v, vm_event_request_t *req)
{
    if ( nestedhvm_enabled(v->domain) && nestedhvm_vcpu_in_guestmode(v) )
    {
        req->flags |= VM_EVENT_FLAG_NESTED_P2M;
        req->data.regs.x86.npt_base = nhvm_vcpu_p2m_base(v);
    }
}

bool hvm_monitor_cr(unsigned int index, unsigned long value, unsigned long old)
{
    struct vcpu *curr = current;
    struct arch_domain *ad = &curr->domain->arch;
    unsigned int ctrlreg_bitmask = monitor_ctrlreg_bitmask(index);

    if ( (ad->monitor.write_ctrlreg_enabled & ctrlreg_bitmask) &&
         (!(ad->monitor.write_ctrlreg_onchangeonly & ctrlreg_bitmask) ||
          value != old) &&
         ((value ^ old) & ~ad->monitor.write_ctrlreg_mask[index]) )
    {
        bool sync = ad->monitor.write_ctrlreg_sync & ctrlreg_bitmask;

        vm_event_request_t req = {
            .reason = VM_EVENT_REASON_WRITE_CTRLREG,
            .u.write_ctrlreg.index = index,
            .u.write_ctrlreg.new_value = value,
            .u.write_ctrlreg.old_value = old
        };

        set_npt_base(curr, &req);

        return monitor_traps(curr, sync, &req) >= 0 &&
               curr->domain->arch.monitor.control_register_values;
    }

    return false;
}

bool hvm_monitor_emul_unimplemented(void)
{
    struct vcpu *curr = current;

    /*
     * Send a vm_event to the monitor to signal that the current
     * instruction couldn't be emulated.
     */
    vm_event_request_t req = {
        .reason = VM_EVENT_REASON_EMUL_UNIMPLEMENTED,
        .vcpu_id  = curr->vcpu_id,
    };

    set_npt_base(curr, &req);

    return curr->domain->arch.monitor.emul_unimplemented_enabled &&
        monitor_traps(curr, true, &req) == 1;
}

bool hvm_monitor_msr(unsigned int msr, uint64_t new_value, uint64_t old_value)
{
    struct vcpu *curr = current;

    if ( monitored_msr(curr->domain, msr) &&
         (!monitored_msr_onchangeonly(curr->domain, msr) ||
           new_value != old_value) )
    {
        vm_event_request_t req = {
            .reason = VM_EVENT_REASON_MOV_TO_MSR,
            .u.mov_to_msr.msr = msr,
            .u.mov_to_msr.new_value = new_value,
            .u.mov_to_msr.old_value = old_value
        };

        set_npt_base(curr, &req);

        return monitor_traps(curr, 1, &req) >= 0 &&
               curr->domain->arch.monitor.control_register_values;
    }

    return false;
}

void hvm_monitor_descriptor_access(uint64_t exit_info,
                                   uint64_t vmx_exit_qualification,
                                   uint8_t descriptor, bool is_write)
{
    struct vcpu *curr = current;
    vm_event_request_t req = {
        .reason = VM_EVENT_REASON_DESCRIPTOR_ACCESS,
        .u.desc_access.descriptor = descriptor,
        .u.desc_access.is_write = is_write,
    };

    if ( cpu_has_vmx )
    {
        req.u.desc_access.arch.vmx.instr_info = exit_info;
        req.u.desc_access.arch.vmx.exit_qualification = vmx_exit_qualification;
    }

    set_npt_base(curr, &req);

    monitor_traps(curr, true, &req);
}

static inline unsigned long gfn_of_rip(unsigned long rip)
{
    struct vcpu *curr = current;
    struct segment_register sreg;
    uint32_t pfec = PFEC_page_present | PFEC_insn_fetch;

    if ( hvm_get_cpl(curr) == 3 )
        pfec |= PFEC_user_mode;

    hvm_get_segment_register(curr, x86_seg_cs, &sreg);

    return paging_gva_to_gfn(curr, sreg.base + rip, &pfec);
}

int hvm_monitor_debug(unsigned long rip, enum hvm_monitor_debug_type type,
                      unsigned int trap_type, unsigned int insn_length,
                      unsigned int pending_dbg)
{
   /*
    * rc < 0 error in monitor/vm_event, crash
    * !rc    continue normally
    * rc > 0 paused waiting for response, work here is done
    */
    struct vcpu *curr = current;
    struct arch_domain *ad = &curr->domain->arch;
    vm_event_request_t req = {};
    bool sync;

    switch ( type )
    {
    case HVM_MONITOR_SOFTWARE_BREAKPOINT:
        if ( !ad->monitor.software_breakpoint_enabled )
            return 0;
        req.reason = VM_EVENT_REASON_SOFTWARE_BREAKPOINT;
        req.u.software_breakpoint.gfn = gfn_of_rip(rip);
        req.u.software_breakpoint.type = trap_type;
        req.u.software_breakpoint.insn_length = insn_length;
        sync = true;
        break;

    case HVM_MONITOR_SINGLESTEP_BREAKPOINT:
        if ( !ad->monitor.singlestep_enabled )
            return 0;
        if ( curr->arch.hvm.fast_single_step.enabled )
        {
            p2m_altp2m_check(curr, curr->arch.hvm.fast_single_step.p2midx);
            curr->arch.hvm.single_step = false;
            curr->arch.hvm.fast_single_step.enabled = false;
            curr->arch.hvm.fast_single_step.p2midx = 0;
            return 0;
        }
        req.reason = VM_EVENT_REASON_SINGLESTEP;
        req.u.singlestep.gfn = gfn_of_rip(rip);
        sync = true;
        break;

    case HVM_MONITOR_DEBUG_EXCEPTION:
        if ( !ad->monitor.debug_exception_enabled )
            return 0;
        req.reason = VM_EVENT_REASON_DEBUG_EXCEPTION;
        req.u.debug_exception.gfn = gfn_of_rip(rip);
        req.u.debug_exception.pending_dbg = pending_dbg;
        req.u.debug_exception.type = trap_type;
        req.u.debug_exception.insn_length = insn_length;
        sync = !!ad->monitor.debug_exception_sync;
        break;

    default:
        return -EOPNOTSUPP;
    }

    set_npt_base(curr, &req);

    return monitor_traps(curr, sync, &req);
}

int hvm_monitor_cpuid(unsigned long insn_length, unsigned int leaf,
                      unsigned int subleaf)
{
    struct vcpu *curr = current;
    struct arch_domain *ad = &curr->domain->arch;
    vm_event_request_t req = {};

    if ( !ad->monitor.cpuid_enabled )
        return 0;

    req.reason = VM_EVENT_REASON_CPUID;
    req.u.cpuid.insn_length = insn_length;
    req.u.cpuid.leaf = leaf;
    req.u.cpuid.subleaf = subleaf;

    set_npt_base(curr, &req);

    return monitor_traps(curr, 1, &req);
}

void hvm_monitor_interrupt(unsigned int vector, unsigned int type,
                           unsigned int err, uint64_t cr2)
{
    struct vcpu *curr = current;
    vm_event_request_t req = {
        .reason = VM_EVENT_REASON_INTERRUPT,
        .u.interrupt.x86.vector = vector,
        .u.interrupt.x86.type = type,
        .u.interrupt.x86.error_code = err,
        .u.interrupt.x86.cr2 = cr2,
    };

    set_npt_base(curr, &req);

    monitor_traps(curr, 1, &req);
}

/*
 * Send memory access vm_events based on pfec. Returns true if the event was
 * sent and false for p2m_get_mem_access() error, no violation and event send
 * error. Assumes the caller will enable/disable arch.vm_event->send_event.
 */
bool hvm_monitor_check_p2m(unsigned long gla, gfn_t gfn, uint32_t pfec,
                           uint16_t kind)
{
    xenmem_access_t access;
    struct vcpu *curr = current;
    vm_event_request_t req = {};
    paddr_t gpa = (gfn_to_gaddr(gfn) | (gla & ~PAGE_MASK));
    int rc;

    ASSERT(curr->arch.vm_event->send_event);

    /*
     * p2m_get_mem_access() can fail from a invalid MFN and return -ESRCH
     * in which case access must be restricted.
     */
    rc = p2m_get_mem_access(curr->domain, gfn, &access, altp2m_vcpu_idx(curr));

    if ( rc == -ESRCH )
        access = XENMEM_access_n;
    else if ( rc )
        return false;

    switch ( access )
    {
    case XENMEM_access_x:
    case XENMEM_access_rx:
        if ( pfec & PFEC_write_access )
            req.u.mem_access.flags = MEM_ACCESS_R | MEM_ACCESS_W;
        break;

    case XENMEM_access_w:
    case XENMEM_access_rw:
        if ( pfec & PFEC_insn_fetch )
            req.u.mem_access.flags = MEM_ACCESS_X;
        break;

    case XENMEM_access_r:
    case XENMEM_access_n:
        if ( pfec & PFEC_write_access )
            req.u.mem_access.flags |= MEM_ACCESS_R | MEM_ACCESS_W;
        if ( pfec & PFEC_insn_fetch )
            req.u.mem_access.flags |= MEM_ACCESS_X;
        break;

    case XENMEM_access_wx:
    case XENMEM_access_rwx:
    case XENMEM_access_rx2rw:
    case XENMEM_access_n2rwx:
    case XENMEM_access_default:
        break;
    }

    if ( !req.u.mem_access.flags )
        return false; /* no violation */

    if ( kind == npfec_kind_with_gla )
        req.u.mem_access.flags |= MEM_ACCESS_FAULT_WITH_GLA |
                                  MEM_ACCESS_GLA_VALID;
    else if ( kind == npfec_kind_in_gpt )
        req.u.mem_access.flags |= MEM_ACCESS_FAULT_IN_GPT |
                                  MEM_ACCESS_GLA_VALID;


    req.reason = VM_EVENT_REASON_MEM_ACCESS;
    req.u.mem_access.gfn = gfn_x(gfn);
    req.u.mem_access.gla = gla;
    req.u.mem_access.offset = gpa & ~PAGE_MASK;

    set_npt_base(curr, &req);

    return monitor_traps(curr, true, &req) >= 0;
}

int hvm_monitor_vmexit(unsigned long exit_reason,
                       unsigned long exit_qualification,
                       unsigned long data)
{
   /*
    * !rc    continue normally
    * rc     paused waiting for response, work here is done
    */
    struct vcpu *curr = current;
    struct arch_domain *ad = &curr->domain->arch;
    vm_event_request_t req = {};

    req.reason = VM_EVENT_REASON_VMEXIT;
    req.u.vmexit.reason = exit_reason;
    req.u.vmexit.qualification = exit_qualification;
    req.u.vmexit.u.data = data;

    set_npt_base(curr, &req);

    hvm_maybe_deassert_evtchn_irq();

    return monitor_traps(curr, !!ad->monitor.vmexit_sync, &req);
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
