/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Nested HVM
 * Copyright (c) 2011, Advanced Micro Devices, Inc.
 * Author: Christoph Egger <Christoph.Egger@amd.com>
 */

#ifndef _HVM_NESTEDHVM_H
#define _HVM_NESTEDHVM_H

#include <xen/types.h>         /* for uintNN_t */
#include <xen/sched.h>         /* for struct vcpu, struct domain */
#include <asm/hvm/vcpu.h>      /* for vcpu_nestedhvm */
#include <public/hvm/params.h>

enum nestedhvm_vmexits {
    NESTEDHVM_VMEXIT_ERROR = 0, /* inject VMEXIT w/ invalid VMCB */
    NESTEDHVM_VMEXIT_FATALERROR = 1, /* crash first level guest */
    NESTEDHVM_VMEXIT_HOST = 2,  /* exit handled on host level */
    NESTEDHVM_VMEXIT_CONTINUE = 3, /* further handling */
    NESTEDHVM_VMEXIT_INJECT = 4, /* inject VMEXIT */
    NESTEDHVM_VMEXIT_DONE = 5, /* VMEXIT handled */
};

/* Nested HVM on/off per domain */
static inline bool nestedhvm_enabled(const struct domain *d)
{
    return IS_ENABLED(CONFIG_HVM) && (d->options & XEN_DOMCTL_CDF_nested_virt);
}

/* Nested VCPU */
int nestedhvm_vcpu_initialise(struct vcpu *v);
void nestedhvm_vcpu_destroy(struct vcpu *v);
void nestedhvm_vcpu_reset(struct vcpu *v);
bool nestedhvm_vcpu_in_guestmode(struct vcpu *v);
#define nestedhvm_vcpu_enter_guestmode(v) \
    vcpu_nestedhvm(v).nv_guestmode = 1
#define nestedhvm_vcpu_exit_guestmode(v)  \
    vcpu_nestedhvm(v).nv_guestmode = 0

/* Nested paging */
#define NESTEDHVM_PAGEFAULT_DONE       0
#define NESTEDHVM_PAGEFAULT_INJECT     1
#define NESTEDHVM_PAGEFAULT_L1_ERROR   2
#define NESTEDHVM_PAGEFAULT_L0_ERROR   3
#define NESTEDHVM_PAGEFAULT_MMIO       4
#define NESTEDHVM_PAGEFAULT_RETRY      5
#define NESTEDHVM_PAGEFAULT_DIRECT_MMIO 6
int nestedhvm_hap_nested_page_fault(struct vcpu *v, paddr_t *L2_gpa,
                                    struct npfec npfec);

/* IO permission map */
unsigned long *nestedhvm_vcpu_iomap_get(bool ioport_80, bool ioport_ed);

/* Misc */
#define nestedhvm_paging_mode_hap(v) (!!nhvm_vmcx_hap_enabled(v))
#define nestedhvm_vmswitch_in_progress(v)   \
    (!!vcpu_nestedhvm((v)).nv_vmswitch_in_progress)

void nestedhvm_vmcx_flushtlb(struct p2m_domain *p2m);

static inline bool nestedhvm_is_n2(struct vcpu *v)
{
    if ( !nestedhvm_enabled(v->domain) ||
        nestedhvm_vmswitch_in_progress(v) ||
        !nestedhvm_paging_mode_hap(v) )
        return false;

    return nestedhvm_vcpu_in_guestmode(v);
}

static inline void nestedhvm_set_cr(struct vcpu *v, unsigned int cr,
                                    unsigned long value)
{
    if ( !nestedhvm_vmswitch_in_progress(v) &&
         nestedhvm_vcpu_in_guestmode(v) )
        v->arch.hvm.nvcpu.guest_cr[cr] = value;
}

static inline bool vvmcx_valid(const struct vcpu *v)
{
    return vcpu_nestedhvm(v).nv_vvmcxaddr != INVALID_PADDR;
}


void start_nested_svm(struct hvm_function_table *);
void start_nested_vmx(struct hvm_function_table *);

#endif /* _HVM_NESTEDHVM_H */
