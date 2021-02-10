/*
 * fixmap.h: compile-time virtual memory allocation
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1998 Ingo Molnar
 * Modifications for Xen are copyright (c) 2002-2004, K A Fraser
 */

#ifndef _ASM_FIXMAP_H
#define _ASM_FIXMAP_H

#include <xen/page-size.h>

#define FIXADDR_TOP (VMAP_VIRT_END - PAGE_SIZE)
#define FIXADDR_X_TOP (XEN_VIRT_END - PAGE_SIZE)

#ifndef __ASSEMBLY__

#include <xen/acpi.h>
#include <xen/pfn.h>
#include <asm/apicdef.h>
#include <asm/msi.h>
#include <acpi/apei.h>

#define MAX_XHCI_PAGES 16

/*
 * Here we define all the compile-time 'special' virtual
 * addresses. The point is to have a constant address at
 * compile time, but to set the physical address only
 * in the boot process. We allocate these special addresses
 * from the end of virtual memory backwards.
 */
enum fixed_addresses {
    /* Index 0 is reserved since fix_to_virt(0) == FIXADDR_TOP. */
    FIX_RESERVED,
    /*
     * Indexes using the page tables set up before entering __start_xen()
     * must be among the first (L1_PAGETABLE_ENTRIES - 1) entries.
     * These are generally those needed by the various console drivers.
     */
    FIX_COM_BEGIN,
    FIX_COM_END,
    FIX_EHCI_DBGP,
    FIX_XHCI_BEGIN,
    FIX_XHCI_END = FIX_XHCI_BEGIN + MAX_XHCI_PAGES - 1,
#ifdef CONFIG_XEN_GUEST
    FIX_PV_CONSOLE,
    FIX_XEN_SHARED_INFO,
#endif /* CONFIG_XEN_GUEST */
    /* Everything else should go further down. */
    FIX_APIC_BASE,
    FIX_IO_APIC_BASE_0,
    FIX_IO_APIC_BASE_END = FIX_IO_APIC_BASE_0 + MAX_IO_APICS-1,
    FIX_ACPI_BEGIN,
    FIX_ACPI_END = FIX_ACPI_BEGIN + NUM_FIXMAP_ACPI_PAGES - 1,
    FIX_HPET_BASE,
    FIX_TBOOT_SHARED_BASE,
    FIX_MSIX_IO_RESERV_BASE,
    FIX_MSIX_IO_RESERV_END = FIX_MSIX_IO_RESERV_BASE + FIX_MSIX_MAX_PAGES -1,
    FIX_TBOOT_MAP_ADDRESS,
    FIX_APEI_RANGE_BASE,
    FIX_APEI_RANGE_END = FIX_APEI_RANGE_BASE + FIX_APEI_RANGE_MAX -1,
    FIX_EFI_MPF,
    __end_of_fixed_addresses
};

#define FIXADDR_SIZE  (__end_of_fixed_addresses << PAGE_SHIFT)
#define FIXADDR_START (FIXADDR_TOP - FIXADDR_SIZE)

extern void __set_fixmap(
    enum fixed_addresses idx, unsigned long mfn, unsigned long flags);

#define set_fixmap(idx, phys) \
    __set_fixmap(idx, (phys)>>PAGE_SHIFT, PAGE_HYPERVISOR)

#define set_fixmap_nocache(idx, phys) \
    __set_fixmap(idx, (phys)>>PAGE_SHIFT, PAGE_HYPERVISOR_UCMINUS)

#define clear_fixmap(idx) __set_fixmap(idx, 0, 0)

#define __fix_to_virt(x) (FIXADDR_TOP - ((x) << PAGE_SHIFT))
#define __virt_to_fix(x) ((FIXADDR_TOP - ((x)&PAGE_MASK)) >> PAGE_SHIFT)

#define fix_to_virt(x)   ((void *)__fix_to_virt(x))

static inline unsigned long virt_to_fix(const unsigned long vaddr)
{
    BUG_ON(vaddr >= FIXADDR_TOP || vaddr < FIXADDR_START);
    return __virt_to_fix(vaddr);
}

enum fixed_addresses_x {
    /* Index 0 is reserved since fix_x_to_virt(0) == FIXADDR_X_TOP. */
    FIX_X_RESERVED,
#ifdef CONFIG_HYPERV_GUEST
    FIX_X_HYPERV_HCALL,
#endif
    __end_of_fixed_addresses_x
};

#define FIXADDR_X_SIZE  (__end_of_fixed_addresses_x << PAGE_SHIFT)
#define FIXADDR_X_START (FIXADDR_X_TOP - FIXADDR_X_SIZE)

extern void __set_fixmap_x(
    enum fixed_addresses_x idx, unsigned long mfn, unsigned long flags);

#define set_fixmap_x(idx, phys) \
    __set_fixmap_x(idx, (phys)>>PAGE_SHIFT, PAGE_HYPERVISOR_RX | MAP_SMALL_PAGES)

#define clear_fixmap_x(idx) __set_fixmap_x(idx, 0, 0)

#define __fix_x_to_virt(x) (FIXADDR_X_TOP - ((x) << PAGE_SHIFT))
#define fix_x_to_virt(x)   ((void *)__fix_x_to_virt(x))

#endif /* __ASSEMBLY__ */

#endif
