#ifndef __ASM_ARM_ARM64_FLUSHTLB_H__
#define __ASM_ARM_ARM64_FLUSHTLB_H__

/* Flush local TLBs, current VMID only */
static inline void flush_tlb_local(void)
{
    asm volatile(
        "dsb sy;"
        "tlbi vmalls12e1;"
        "dsb sy;"
        "isb;"
        : : : "memory");
}

/* Flush local TLBs by IPA, Stage 2, Last Level, EL1, Inner Shareable */
static inline void flush_tlb_ipas2le1is(unsigned long ipa)
{
    asm volatile(
        "dsb sy;"
        "tlbi ipas2le1is, %0;"
        "dsb sy;"
        "isb;"
        : : "r" (ipa) : "memory");
}
/* Flush local TLBs by VA, All ASID, Last Level, E1, Inner Shareable */
static inline void flush_tlb_vaale1is(unsigned long va)
{
    asm volatile(
        "dsb sy;"
        "tlbi vaale1is, %0;"
        "dsb sy;"
        "isb;"
        : : "r" (va) : "memory");
}

/* Flush innershareable TLBs, current VMID only */
static inline void flush_tlb(void)
{
    asm volatile(
        "dsb sy;"
        "tlbi vmalls12e1is;"
        "dsb sy;"
        "isb;"
        : : : "memory");
}

/* Flush local TLBs, all VMIDs, non-hypervisor mode */
static inline void flush_tlb_all_local(void)
{
    asm volatile(
        "dsb sy;"
        "tlbi alle1;"
        "dsb sy;"
        "isb;"
        : : : "memory");
}

/* Flush innershareable TLBs, all VMIDs, non-hypervisor mode */
static inline void flush_tlb_all(void)
{
    asm volatile(
        "dsb sy;"
        "tlbi alle1is;"
        "dsb sy;"
        "isb;"
        : : : "memory");
}

#endif /* __ASM_ARM_ARM64_FLUSHTLB_H__ */
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
