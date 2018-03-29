/*
 * Architecture specific implementation for EFI boot code.  This file
 * is intended to be included by common/efi/boot.c _only_, and
 * therefore can define arch specific global variables.
 */
#include <xen/vga.h>
#include <asm/e820.h>
#include <asm/edd.h>
#include <asm/msr.h>
#include <asm/processor.h>
#include <xen/libelf.h>
#include <xen/multiboot2.h>
#include <acpi/acconfig.h>
#include <acpi/actbl.h>

static struct file __initdata ucode;
static struct file __initdata tboot_file;
static u32 __initdata tboot_entry;
static CHAR16* __initdata xen_self_filename;
static multiboot_info_t __initdata mbi = {
    .flags = MBI_MODULES | MBI_LOADERNAME
};

static u64 __initdata mbi2_data[0x1000];

#define MULTIBOOT2_TAG_TYPE_XENEFI 0x58454301
typedef struct {
    u32 type;
    u32 size;
    unsigned int efi_version, efi_fw_revision;
    struct xen_vga_console_info vga_console_info;
    const void* efi_ct;
    unsigned int efi_num_ct;
    UINTN efi_memmap_size;
    UINTN efi_mdesc_size;
    void* efi_memmap;
    const void* efi_rs;
    const struct efi_pci_rom *efi_pci_roms;
    const CHAR16* efi_fw_vendor;
} multiboot2_tag_xenefi_t;

/*
 * The array size needs to be one larger than the number of modules we
 * support - see __start_xen().
 */
#define MB_MAX_MODULES 30
static module_t __initdata mb_modules[MB_MAX_MODULES + 1];

static void __init edd_put_string(u8 *dst, size_t n, const char *src)
{
    while ( n-- && *src )
       *dst++ = *src++;
    if ( *src )
       PrintErrMesg(L"Internal error populating EDD info",
                    EFI_BUFFER_TOO_SMALL);
    while ( n-- )
       *dst++ = ' ';
}
#define edd_put_string(d, s) edd_put_string(d, ARRAY_SIZE(d), s)

extern const intpte_t __page_tables_start[], __page_tables_end[];
#define in_page_tables(v) ((intpte_t *)(v) >= __page_tables_start && \
                           (intpte_t *)(v) < __page_tables_end)

#define PE_BASE_RELOC_ABS      0
#define PE_BASE_RELOC_HIGHLOW  3
#define PE_BASE_RELOC_DIR64   10

extern const struct pe_base_relocs {
    u32 rva;
    u32 size;
    u16 entries[];
} __base_relocs_start[], __base_relocs_end[];

static void __init efi_arch_relocate_image(unsigned long delta)
{
    const struct pe_base_relocs *base_relocs;

    for ( base_relocs = __base_relocs_start; base_relocs < __base_relocs_end; )
    {
        unsigned int i = 0, n;

        n = (base_relocs->size - sizeof(*base_relocs)) /
            sizeof(*base_relocs->entries);

        /*
         * Relevant l{2,3}_bootmap entries get initialized explicitly in
         * efi_arch_memory_setup(), so we must not apply relocations there.
         * l2_identmap's first slot, otoh, should be handled normally, as
         * efi_arch_memory_setup() won't touch it (xen_phys_start should
         * never be zero).
         */
        if ( xen_phys_start + base_relocs->rva == (unsigned long)l3_bootmap ||
             xen_phys_start + base_relocs->rva == (unsigned long)l2_bootmap )
            i = n;

        for ( ; i < n; ++i )
        {
            unsigned long addr = xen_phys_start + base_relocs->rva +
                                 (base_relocs->entries[i] & 0xfff);

            switch ( base_relocs->entries[i] >> 12 )
            {
            case PE_BASE_RELOC_ABS:
                break;
            case PE_BASE_RELOC_HIGHLOW:
                if ( delta )
                {
                    *(u32 *)addr += delta;
                    if ( in_page_tables(addr) )
                        *(u32 *)addr += xen_phys_start;
                }
                break;
            case PE_BASE_RELOC_DIR64:
                if ( in_page_tables(addr) )
                    blexit(L"Unexpected relocation type");
                if ( delta )
                    *(u64 *)addr += delta;
                break;
            default:
                blexit(L"Unsupported relocation type");
            }
        }
        base_relocs = (const void *)(base_relocs->entries + i + (i & 1));
    }
}

extern const s32 __trampoline_rel_start[], __trampoline_rel_stop[];
extern const s32 __trampoline_seg_start[], __trampoline_seg_stop[];

static void __init relocate_trampoline(unsigned long phys)
{
    const s32 *trampoline_ptr;

    trampoline_phys = phys;

    if ( !efi_enabled(EFI_LOADER) )
        return;

    /* Apply relocations to trampoline. */
    for ( trampoline_ptr = __trampoline_rel_start;
          trampoline_ptr < __trampoline_rel_stop;
          ++trampoline_ptr )
        *(u32 *)(*trampoline_ptr + (long)trampoline_ptr) += phys;
    for ( trampoline_ptr = __trampoline_seg_start;
          trampoline_ptr < __trampoline_seg_stop;
          ++trampoline_ptr )
        *(u16 *)(*trampoline_ptr + (long)trampoline_ptr) = phys >> 4;
}

static void __init place_string(u32 *addr, const char *s)
{
    char *alloc = NULL;

    if ( s && *s )
    {
        size_t len1 = strlen(s) + 1;
        const char *old = (char *)(long)*addr;
        size_t len2 = *addr ? strlen(old) + 1 : 0;

        alloc = ebmalloc(len1 + len2);
        /*
         * Insert new string before already existing one. This is needed
         * for options passed on the command line to override options from
         * the configuration file.
         */
        memcpy(alloc, s, len1);
        if ( *addr )
        {
            alloc[len1 - 1] = ' ';
            memcpy(alloc + len1, old, len2);
        }
    }
    *addr = (long)alloc;
}

static void __init efi_arch_process_memory_map(EFI_SYSTEM_TABLE *SystemTable,
                                               void *map,
                                               UINTN map_size,
                                               UINTN desc_size,
                                               UINT32 desc_ver)
{
    struct e820entry *e;
    unsigned int i;

    /* Populate E820 table and check trampoline area availability. */
    e = e820_raw.map - 1;
    for ( e820_raw.nr_map = i = 0; i < map_size; i += desc_size )
    {
        EFI_MEMORY_DESCRIPTOR *desc = map + i;
        u64 len = desc->NumberOfPages << EFI_PAGE_SHIFT;
        u32 type;

        switch ( desc->Type )
        {
        case EfiBootServicesCode:
        case EfiBootServicesData:
            if ( map_bs )
            {
        default:
                type = E820_RESERVED;
                break;
            }
            /* fall through */
        case EfiConventionalMemory:
            if ( !trampoline_phys && desc->PhysicalStart + len <= 0x100000 &&
                 len >= cfg.size && desc->PhysicalStart + len > cfg.addr )
                cfg.addr = (desc->PhysicalStart + len - cfg.size) & PAGE_MASK;
            /* fall through */
        case EfiLoaderCode:
        case EfiLoaderData:
            if ( desc->Attribute & EFI_MEMORY_WB )
                type = E820_RAM;
            else
        case EfiUnusableMemory:
                type = E820_UNUSABLE;
            break;
        case EfiACPIReclaimMemory:
            type = E820_ACPI;
            break;
        case EfiACPIMemoryNVS:
            type = E820_NVS;
            break;
        }
        if ( e820_raw.nr_map && type == e->type &&
             desc->PhysicalStart == e->addr + e->size )
            e->size += len;
        else if ( !len || e820_raw.nr_map >= ARRAY_SIZE(e820_raw.map) )
            continue;
        else
        {
            ++e;
            e->addr = desc->PhysicalStart;
            e->size = len;
            e->type = type;
            ++e820_raw.nr_map;
        }
    }

}

static void __init mbi2_init(void)
{
    multiboot2_fixed_t *hdr = (void*)mbi2_data;
    hdr->total_size = sizeof(*hdr);
    hdr->reserved = 0;
}

static void* __init mbi2_add_entry(size_t size)
{
    multiboot2_fixed_t *hdr = (void*)mbi2_data;
    u32 offset = hdr->total_size;
    multiboot2_tag_t *tag = offset + (void*)mbi2_data;

    size = (size + 7) & ~7;
    hdr->total_size += size;
    tag->size = size;

    return tag;
}

static u32 __init setup_tboot_mbi(void)
{
    int i;
    u32 len;
    multiboot2_tag_string_t *tag_str;
    multiboot2_tag_module_t *module;
    multiboot2_tag_mmap_t *mmap;
    multiboot2_tag_xenefi_t *xenmbi;
    void* str;

    /* We construct a multiboot2 header for TBOOT: */
    mbi2_init();

    /* Command line */
    str = (void*)(u64)mbi.cmdline;
    len = strlen(str) + 1;
    tag_str = mbi2_add_entry(sizeof(*tag_str) + len);
    tag_str->type = MULTIBOOT2_TAG_TYPE_CMDLINE;
    memcpy(tag_str->string, str, len);

    /* Memory map */
    len = e820_raw.nr_map * sizeof(multiboot2_memory_map_t);
    mmap = mbi2_add_entry(sizeof(*mmap) + len);
    mmap->type = MULTIBOOT2_TAG_TYPE_MMAP;
    mmap->entry_size = sizeof(multiboot2_memory_map_t);
    mmap->entry_version = 0;

    for(i = 0; i < e820_raw.nr_map; i++) {
        mmap->entries[i].addr = e820_raw.map[i].addr;
        mmap->entries[i].len = e820_raw.map[i].size;
        mmap->entries[i].type = e820_raw.map[i].type;
        mmap->entries[i].zero = 0;
    }

    /* Modules */
    for(i=0; i < mbi.mods_count; i++) {
        str = (void*)(u64)mb_modules[i].string;
        len = strlen(str) + 1;
        module = mbi2_add_entry(sizeof(*module) + len);
        module->type = MULTIBOOT2_TAG_TYPE_MODULE;
        module->mod_start = mb_modules[i].mod_start << PAGE_SHIFT;
        module->mod_end = module->mod_start + mb_modules[i].mod_end;
        memcpy(module->cmdline, str, len + 1);
    }

    /* ACPI Root System Descriptor Pointer */
    if ( efi.acpi20 ) {
        len = sizeof(struct acpi_table_rsdp);
        tag_str = mbi2_add_entry(sizeof(*tag_str) + len);
        tag_str->type = MULTIBOOT2_TAG_TYPE_ACPI_NEW;
        memcpy(tag_str->string, (void*)efi.acpi20, len);
    }

    if ( efi.acpi ) {
        len = ACPI_RSDP_REV0_SIZE;
        tag_str = mbi2_add_entry(sizeof(*tag_str) + len);
        tag_str->type = MULTIBOOT2_TAG_TYPE_ACPI_OLD;
        memcpy(tag_str->string, (void*)efi.acpi, len);
    }

    /* Other variables to pass to post-SINIT Xen */
    xenmbi = mbi2_add_entry(sizeof(*xenmbi));
    xenmbi->type = MULTIBOOT2_TAG_TYPE_XENEFI;

    xenmbi->efi_version = efi_version;
    xenmbi->efi_fw_revision = efi_fw_revision;
    xenmbi->vga_console_info = vga_console_info;
    xenmbi->efi_ct = efi_ct;
    xenmbi->efi_num_ct = efi_num_ct;
    xenmbi->efi_memmap_size = efi_memmap_size;
    xenmbi->efi_mdesc_size = efi_mdesc_size;
    xenmbi->efi_memmap = efi_memmap;
    xenmbi->efi_rs = efi_rs;
    xenmbi->efi_pci_roms = efi_pci_roms;
    xenmbi->efi_fw_vendor = efi_fw_vendor;

    /* Empty */
    tag_str = mbi2_add_entry(sizeof(*tag_str));
    tag_str->type = MULTIBOOT2_TAG_TYPE_END;

    return (u64)mbi2_data;
}

static void __init read_tboot_mbi(void* data)
{
    multiboot2_fixed_t *fixed_hdr = data;
    multiboot2_tag_t *tag;
    unsigned int i;

    /* Copy the info inside Xen's address space so that any pointers inside the
     * structure are accessible in __start_xen where only memory <16MB and Xen
     * itself are present in the directmap.
     */
    memcpy(mbi2_data, data, fixed_hdr->total_size);
    data = mbi2_data;

    data += sizeof(*fixed_hdr);
    tag = data;

    mbi.mods_addr = __pa(mb_modules);
    mbi.boot_loader_name = __pa("TBOOT");

    while ( 1 )
    {
        multiboot2_tag_string_t *tag_str = data;
        multiboot2_tag_module_t *module = data;
        multiboot2_tag_mmap_t *mmap = data;
        multiboot2_tag_xenefi_t *xenmbi = data;

        switch ( tag->type )
        {
        case MULTIBOOT2_TAG_TYPE_MMAP:
            e820_raw.nr_map = (mmap->size - sizeof(*mmap)) / sizeof(mmap->entries[0]);
            for ( i = 0; i < e820_raw.nr_map; i++ )
            {
                e820_raw.map[i].addr = mmap->entries[i].addr;
                e820_raw.map[i].size = mmap->entries[i].len;
                e820_raw.map[i].type = mmap->entries[i].type;
            }
            break;
        case MULTIBOOT2_TAG_TYPE_CMDLINE:
            mbi.cmdline = __pa(tag_str->string);
            mbi.flags |= MBI_CMDLINE;
            break;
        case MULTIBOOT2_TAG_TYPE_MODULE:
            /* Xen's mb_modules format assumes that modules that are aligned to
             * page boundaries, but tboot doesn't verify that while hashing.
             */
            if ( module->mod_start & (PAGE_SIZE - 1) )
                break;
            if ( mbi.mods_count >= MB_MAX_MODULES )
                break;
            mb_modules[mbi.mods_count].mod_start = module->mod_start >> PAGE_SHIFT;
            mb_modules[mbi.mods_count].mod_end = module->mod_end - module->mod_start;
            mb_modules[mbi.mods_count].string = __pa(module->cmdline);
            mbi.mods_count++;
            break;
        case MULTIBOOT2_TAG_TYPE_ACPI_OLD:
            /* We could verify that TBOOT and Xen both used the same ACPI
             * tables, but tboot_parse_dmar_table implies it won't matter since
             * important values are fixed up from the TXT heap and we can't
             * validate everything anyway.
             */
            /* memcmp(efi.acpi, tag_str->string) */
            break;
        case MULTIBOOT2_TAG_TYPE_ACPI_NEW:
            /* memcmp(efi.acpi20, tag_str->string) */
            break;
        case MULTIBOOT2_TAG_TYPE_XENEFI:
            if ( xenmbi->size != sizeof(*xenmbi) )
                return;

            /* These are integer fields that mostly don't need validation */
            efi_version = xenmbi->efi_version;
            efi_fw_revision = xenmbi->efi_fw_revision;
            vga_console_info = xenmbi->vga_console_info;

            /* The EFI configuration table is parsed by Xen in efi_tables()
             * and is also used by Linux to find ACPI tables.
             */
            efi_ct = xenmbi->efi_ct;
            efi_num_ct = xenmbi->efi_num_ct;

            /* This EFI memory map is the pre-validation source of the e820 map
             * that will be parsed in read_tboot_mbi.  The only use for the old
             * copy is to see the EFI memory types which have more granularity
             * than the e820 memory types, or to allow EFI runtime services to
             * work as expected.  While the table is exposed by a platform
             * hypercall, Linux does not use it.
             */
            efi_memmap_size = xenmbi->efi_memmap_size;
            efi_mdesc_size = xenmbi->efi_mdesc_size;
            efi_memmap = xenmbi->efi_memmap;

            efi_rs = xenmbi->efi_rs;

            /* Disabled until needed */
            /* efi_pci_roms = xenmbi->efi_pci_roms; */
            efi_fw_vendor = xenmbi->efi_fw_vendor;

            break;
        case MULTIBOOT2_TAG_TYPE_END:
            return;
        }
        data += ((tag->size + 7) & ~7);
        tag = data;
    }
}

static void *__init efi_arch_allocate_mmap_buffer(UINTN map_size)
{
    return ebmalloc(map_size);
}

static void __init efi_arch_pre_exit_boot(void)
{
    if ( !trampoline_phys )
    {
        if ( !cfg.addr )
            blexit(L"No memory for trampoline");
        relocate_trampoline(cfg.addr);
    }
}

static void __init noreturn do_sinit(void)
{
    u32 mbi_addr = setup_tboot_mbi();

    asm volatile(
        "cli\n"

        // We need to use Xen's GDT to switch back to 32-bit mode
        "lgdt   gdt_descr(%%rip)\n"

        // this push and call are consumed by lretq, producing a mov-to-cs
        "pushq  %[cs]\n"
        "call   1f\n"
        ".code32\n"

        // Disable paging; we are identity mapped
        "mov    %[cr0], %%eax\n"
        "mov    %%eax, %%cr0\n"

        // Clear LME bit of the EFER MSR
        "movl   %[efer], %%ecx\n"
        "rdmsr\n"
        "and    %[lme_mask], %%eax\n"
        "wrmsr\n"

        // Set up arguments (ebx already set)
        "movl   %[mb_magic], %%eax\n"

        // Jump to tboot's entry point; it will return control to the copy of
        // xen.efi passed via its first multiboot argument
        "jmp *%%esi\n"

        ".code64\n"
        "1: lretq\n"
        ::
         [cs] "i" (__HYPERVISOR_CS32),
         [cr0] "i" (X86_CR0_PE | X86_CR0_MP | X86_CR0_ET | X86_CR0_NE),
         [efer] "i" (MSR_EFER),
         [lme_mask] "i" (~EFER_LME),
         [mb_magic] "i" (MULTIBOOT2_BOOTLOADER_MAGIC),
         "b" (mbi_addr),
         "S" (tboot_entry)
        : "memory"
    );
    unreachable();
}

static void __init noreturn enter_xen_context(unsigned long mbi_p, unsigned long cr3)
{
    u64 cr4 = XEN_MINIMAL_CR4 & ~X86_CR4_PGE, efer;

    /* Set system registers and transfer control. */
    asm volatile("pushq $0\n\tpopfq");
    rdmsrl(MSR_EFER, efer);
    efer |= EFER_SCE;
    if ( cpuid_ext_features & cpufeat_mask(X86_FEATURE_NX) )
        efer |= EFER_NX;
    wrmsrl(MSR_EFER, efer);
    write_cr0(X86_CR0_PE | X86_CR0_MP | X86_CR0_ET | X86_CR0_NE | X86_CR0_WP |
              X86_CR0_AM | X86_CR0_PG);
    asm volatile ( "mov    %[cr4], %%cr4\n\t"
                   "mov    %[cr3], %%cr3\n\t"
#if XEN_MINIMAL_CR4 & X86_CR4_PGE
                   "or     $"__stringify(X86_CR4_PGE)", %[cr4]\n\t"
                   "mov    %[cr4], %%cr4\n\t"
#endif
                   "movabs $__start_xen, %[rip]\n\t"
                   "lgdt   gdt_descr(%%rip)\n\t"
                   "mov    stack_start(%%rip), %%rsp\n\t"
                   "mov    %[ds], %%ss\n\t"
                   "mov    %[ds], %%ds\n\t"
                   "mov    %[ds], %%es\n\t"
                   "mov    %[ds], %%fs\n\t"
                   "mov    %[ds], %%gs\n\t"
                   "movl   %[cs], 8(%%rsp)\n\t"
                   "mov    %[rip], (%%rsp)\n\t"
                   "lretq  %[stkoff]-16"
                   : [rip] "=&r" (efer/* any dead 64-bit variable */),
                     [cr4] "+&r" (cr4)
                   : [cr3] "r" (cr3),
                     [cs] "ir" (__HYPERVISOR_CS),
                     [ds] "r" (__HYPERVISOR_DS),
                     [stkoff] "i" (STACK_SIZE - sizeof(struct cpu_info)),
                     "D" (mbi_p)
                   : "memory" );
    for( ; ; ); /* not reached */
}

static void __init noreturn efi_arch_post_exit_boot(void)
{
    if ( tboot_file.size )
        do_sinit();

    efi_arch_relocate_image(__XEN_VIRT_START - xen_phys_start);
    memcpy((void *)trampoline_phys, trampoline_start, cfg.size);

    enter_xen_context((unsigned long)&mbi, (unsigned long)idle_pg_table);
}

static void __init efi_arch_cfg_file_early(EFI_FILE_HANDLE dir_handle, char *section)
{
}

static void __init efi_arch_cfg_file_late(EFI_FILE_HANDLE dir_handle, char *section,
                                          EFI_SHIM_LOCK_PROTOCOL *shim_lock)
{
    union string name;
    EFI_STATUS status;

    name.s = get_value(&cfg, section, "ucode");
    if ( !name.s )
        name.s = get_value(&cfg, "global", "ucode");
    if ( name.s )
    {
        microcode_set_module(mbi.mods_count);
        split_string(name.s);
        read_file(dir_handle, s2w(&name), &ucode, NULL);
        efi_bs->FreePool(name.w);
    }

    name.s = get_value(&cfg, section, "tboot");
    if ( !name.s )
        name.s = get_value(&cfg, "global", "tboot");
    if ( name.s )
    {
        struct elf_binary elf;
        struct file xen_self;
        module_t tmp;
        u32 tboot_cmdline;
        char *option_str = split_string(name.s);

        read_file(dir_handle, s2w(&name), &tboot_file, option_str);
        efi_bs->FreePool(name.w);

        /* tboot is not yet SecureBoot compatible (it's still in ELF format) */
        if ( shim_lock &&
            (status = shim_lock->Measure(tboot_file.ptr, tboot_file.size, 4))
            != EFI_SUCCESS )
                PrintErrMesg(L"tboot could not be measured", status);

        // Remove tboot from the mb_modules list; save its cmdline
        mbi.mods_count--;
        tboot_cmdline = mb_modules[mbi.mods_count].string;

        if ( elf_init(&elf, tboot_file.ptr, tboot_file.size) ) {
            PrintStr(L"Could init tboot ELF parsing.\r\n");
            tboot_file.size = 0;
            return;
        }
        elf_parse_binary(&elf);

        tboot_entry = elf_uval(&elf, elf.ehdr, e_entry);

        // XXX tboot must be loaded at a constant physical address.
        // Check if it's free in the e820 and error out if not?
        elf.dest_base = (void*)elf.pstart;
        elf.dest_size = elf.pend - elf.pstart;

        if ( elf_load_binary_raw(&elf) ) {
            PrintStr(L"Could not lay out tboot in memory.\r\n");
            tboot_file.size = 0;
            return;
        }

        // Free the ELF binary for tboot now that it's been relocated
        efi_bs->FreePages(tboot_file.addr, PFN_UP(tboot_file.size));

        // Read in xen.efi and then move it to the first module slot
        read_file(dir_handle, xen_self_filename, &xen_self, NULL);

        if ( shim_lock )
        {
            if ( efi_secureboot_enabled() )
            {
                if ( (status = shim_lock->Verify(xen_self.ptr, xen_self.size))
                    != EFI_SUCCESS )
                    PrintErrMesg(L"Second copy of Xen couldn't be verified", status);
            }
            else
            {
                if ( (status = shim_lock->Measure(xen_self.ptr, xen_self.size, 4))
                    != EFI_SUCCESS )
                    PrintErrMesg(L"Second copy of Xen couldn't be measured", status);
            }
        }

        tmp = mb_modules[mbi.mods_count - 1];
        memmove(&mb_modules[1], &mb_modules[0], (mbi.mods_count - 1)*sizeof(mb_modules[0]));

        // Move our command line to the module, and replace it with tboot's
        tmp.string = mbi.cmdline;
        mbi.cmdline = tboot_cmdline;

        mb_modules[0] = tmp;
    }

    name.s = get_value(&cfg, section, "sinit");
    if ( !name.s )
        name.s = get_value(&cfg, "global", "sinit");
    while ( name.s && mbi.mods_count < MB_MAX_MODULES )
    {
        struct file sinit;
        char* next_name = split_string(name.s);
        read_file(dir_handle, s2w(&name), &sinit, NULL);
        efi_bs->FreePool(name.w);
        name.s = next_name;
    }
}

static void __init efi_arch_handle_xen_filename(EFI_FILE_HANDLE dir_handle, CHAR16 *file_name)
{
    size_t len = (wstrlen(file_name) + 1) * sizeof(*file_name);
    if ( efi_bs->AllocatePool(EfiLoaderData, len,
                              (void**)&xen_self_filename) != EFI_SUCCESS )
        return;

    memcpy(xen_self_filename, file_name, len);
}

static void __init efi_arch_handle_cmdline(CHAR16 *image_name,
                                           CHAR16 *cmdline_options,
                                           char *cfgfile_options)
{
    union string name;

    if ( cmdline_options )
    {
        name.w = cmdline_options;
        w2s(&name);
        place_string(&mbi.cmdline, name.s);
    }
    if ( cfgfile_options )
        place_string(&mbi.cmdline, cfgfile_options);
    /* Insert image name last, as it gets prefixed to the other options. */
    if ( image_name )
    {
        name.w = image_name;
        w2s(&name);
    }
    else
        name.s = "xen";
    place_string(&mbi.cmdline, name.s);

    if ( mbi.cmdline )
        mbi.flags |= MBI_CMDLINE;
    /*
     * These must not be initialized statically, since the value must
     * not get relocated when processing base relocations later.
     */
    mbi.boot_loader_name = (long)"EFI";
    mbi.mods_addr = (long)mb_modules;
}

static void __init efi_arch_edd(void)
{
    static EFI_GUID __initdata bio_guid = BLOCK_IO_PROTOCOL;
    static EFI_GUID __initdata devp_guid = DEVICE_PATH_PROTOCOL;
    EFI_HANDLE *handles = NULL;
    unsigned int i;
    UINTN size;
    EFI_STATUS status;

    /* Collect EDD info. */
    BUILD_BUG_ON(offsetof(struct edd_info, edd_device_params) != EDDEXTSIZE);
    BUILD_BUG_ON(sizeof(struct edd_device_params) != EDDPARMSIZE);
    size = 0;
    status = efi_bs->LocateHandle(ByProtocol, &bio_guid, NULL, &size, NULL);
    if ( status == EFI_BUFFER_TOO_SMALL )
        status = efi_bs->AllocatePool(EfiLoaderData, size, (void **)&handles);
    if ( !EFI_ERROR(status) )
        status = efi_bs->LocateHandle(ByProtocol, &bio_guid, NULL, &size,
                                      handles);
    if ( EFI_ERROR(status) )
        size = 0;
    for ( i = 0; i < size / sizeof(*handles); ++i )
    {
        EFI_BLOCK_IO *bio;
        EFI_DEV_PATH_PTR devp;
        struct edd_info *info = boot_edd_info + boot_edd_info_nr;
        struct edd_device_params *params = &info->edd_device_params;
        enum { root, acpi, pci, ctrlr } state = root;

        status = efi_bs->HandleProtocol(handles[i], &bio_guid, (void **)&bio);
        if ( EFI_ERROR(status) ||
             bio->Media->RemovableMedia ||
             bio->Media->LogicalPartition )
            continue;
        if ( boot_edd_info_nr < EDD_INFO_MAX )
        {
            info->device = 0x80 + boot_edd_info_nr; /* fake */
            info->version = 0x11;
            params->length = offsetof(struct edd_device_params, dpte_ptr);
            params->number_of_sectors = bio->Media->LastBlock + 1;
            params->bytes_per_sector = bio->Media->BlockSize;
            params->dpte_ptr = ~0;
        }
        ++boot_edd_info_nr;
        status = efi_bs->HandleProtocol(handles[i], &devp_guid,
                                        (void **)&devp);
        if ( EFI_ERROR(status) )
            continue;
        for ( ; !IsDevicePathEnd(devp.DevPath);
              devp.DevPath = NextDevicePathNode(devp.DevPath) )
        {
            switch ( DevicePathType(devp.DevPath) )
            {
                const u8 *p;

            case ACPI_DEVICE_PATH:
                if ( state != root || boot_edd_info_nr > EDD_INFO_MAX )
                    break;
                switch ( DevicePathSubType(devp.DevPath) )
                {
                case ACPI_DP:
                    if ( devp.Acpi->HID != EISA_PNP_ID(0xA03) &&
                         devp.Acpi->HID != EISA_PNP_ID(0xA08) )
                        break;
                    params->interface_path.pci.bus = devp.Acpi->UID;
                    state = acpi;
                    break;
                case EXPANDED_ACPI_DP:
                    /* XXX */
                    break;
                }
                break;
            case HARDWARE_DEVICE_PATH:
                if ( state != acpi ||
                     DevicePathSubType(devp.DevPath) != HW_PCI_DP ||
                     boot_edd_info_nr > EDD_INFO_MAX )
                    break;
                state = pci;
                edd_put_string(params->host_bus_type, "PCI");
                params->interface_path.pci.slot = devp.Pci->Device;
                params->interface_path.pci.function = devp.Pci->Function;
                break;
            case MESSAGING_DEVICE_PATH:
                if ( state != pci || boot_edd_info_nr > EDD_INFO_MAX )
                    break;
                state = ctrlr;
                switch ( DevicePathSubType(devp.DevPath) )
                {
                case MSG_ATAPI_DP:
                    edd_put_string(params->interface_type, "ATAPI");
                    params->interface_path.pci.channel =
                        devp.Atapi->PrimarySecondary;
                    params->device_path.atapi.device = devp.Atapi->SlaveMaster;
                    params->device_path.atapi.lun = devp.Atapi->Lun;
                    break;
                case MSG_SCSI_DP:
                    edd_put_string(params->interface_type, "SCSI");
                    params->device_path.scsi.id = devp.Scsi->Pun;
                    params->device_path.scsi.lun = devp.Scsi->Lun;
                    break;
                case MSG_FIBRECHANNEL_DP:
                    edd_put_string(params->interface_type, "FIBRE");
                    params->device_path.fibre.wwid = devp.FibreChannel->WWN;
                    params->device_path.fibre.lun = devp.FibreChannel->Lun;
                    break;
                case MSG_1394_DP:
                    edd_put_string(params->interface_type, "1394");
                    params->device_path.i1394.eui = devp.F1394->Guid;
                    break;
                case MSG_USB_DP:
                case MSG_USB_CLASS_DP:
                    edd_put_string(params->interface_type, "USB");
                    break;
                case MSG_I2O_DP:
                    edd_put_string(params->interface_type, "I2O");
                    params->device_path.i2o.identity_tag = devp.I2O->Tid;
                    break;
                default:
                    continue;
                }
                info->version = 0x30;
                params->length = sizeof(struct edd_device_params);
                params->key = 0xbedd;
                params->device_path_info_length =
                    sizeof(struct edd_device_params) -
                    offsetof(struct edd_device_params, key);
                for ( p = (const u8 *)&params->key; p < &params->checksum; ++p )
                    params->checksum -= *p;
                break;
            case MEDIA_DEVICE_PATH:
                if ( DevicePathSubType(devp.DevPath) == MEDIA_HARDDRIVE_DP &&
                     devp.HardDrive->MBRType == MBR_TYPE_PCAT &&
                     boot_mbr_signature_nr < EDD_MBR_SIG_MAX )
                {
                    struct mbr_signature *sig = boot_mbr_signature +
                                                boot_mbr_signature_nr;

                    sig->device = 0x80 + boot_edd_info_nr; /* fake */
                    memcpy(&sig->signature, devp.HardDrive->Signature,
                           sizeof(sig->signature));
                    ++boot_mbr_signature_nr;
                }
                break;
            }
        }
    }
    if ( handles )
        efi_bs->FreePool(handles);
    if ( boot_edd_info_nr > EDD_INFO_MAX )
        boot_edd_info_nr = EDD_INFO_MAX;
}

static void __init efi_arch_console_init(UINTN cols, UINTN rows)
{
#ifdef CONFIG_VIDEO
    vga_console_info.video_type = XEN_VGATYPE_TEXT_MODE_3;
    vga_console_info.u.text_mode_3.columns = cols;
    vga_console_info.u.text_mode_3.rows = rows;
    vga_console_info.u.text_mode_3.font_height = 16;
#endif
}

static void __init efi_arch_video_init(EFI_GRAPHICS_OUTPUT_PROTOCOL *gop,
                                       UINTN info_size,
                                       EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *mode_info)
{
#ifdef CONFIG_VIDEO
    int bpp = 0;

    switch ( mode_info->PixelFormat )
    {
    case PixelRedGreenBlueReserved8BitPerColor:
        vga_console_info.u.vesa_lfb.red_pos = 0;
        vga_console_info.u.vesa_lfb.red_size = 8;
        vga_console_info.u.vesa_lfb.green_pos = 8;
        vga_console_info.u.vesa_lfb.green_size = 8;
        vga_console_info.u.vesa_lfb.blue_pos = 16;
        vga_console_info.u.vesa_lfb.blue_size = 8;
        vga_console_info.u.vesa_lfb.rsvd_pos = 24;
        vga_console_info.u.vesa_lfb.rsvd_size = 8;
        bpp = 32;
        break;
    case PixelBlueGreenRedReserved8BitPerColor:
        vga_console_info.u.vesa_lfb.red_pos = 16;
        vga_console_info.u.vesa_lfb.red_size = 8;
        vga_console_info.u.vesa_lfb.green_pos = 8;
        vga_console_info.u.vesa_lfb.green_size = 8;
        vga_console_info.u.vesa_lfb.blue_pos = 0;
        vga_console_info.u.vesa_lfb.blue_size = 8;
        vga_console_info.u.vesa_lfb.rsvd_pos = 24;
        vga_console_info.u.vesa_lfb.rsvd_size = 8;
        bpp = 32;
        break;
    case PixelBitMask:
        bpp = set_color(mode_info->PixelInformation.RedMask, bpp,
                        &vga_console_info.u.vesa_lfb.red_pos,
                        &vga_console_info.u.vesa_lfb.red_size);
        bpp = set_color(mode_info->PixelInformation.GreenMask, bpp,
                        &vga_console_info.u.vesa_lfb.green_pos,
                        &vga_console_info.u.vesa_lfb.green_size);
        bpp = set_color(mode_info->PixelInformation.BlueMask, bpp,
                        &vga_console_info.u.vesa_lfb.blue_pos,
                        &vga_console_info.u.vesa_lfb.blue_size);
        bpp = set_color(mode_info->PixelInformation.ReservedMask, bpp,
                        &vga_console_info.u.vesa_lfb.rsvd_pos,
                        &vga_console_info.u.vesa_lfb.rsvd_size);
        if ( bpp > 0 )
            break;
        /* fall through */
    default:
        PrintErr(L"Current graphics mode is unsupported!\r\n");
        bpp  = 0;
        break;
    }
    if ( bpp > 0 )
    {
        vga_console_info.video_type = XEN_VGATYPE_EFI_LFB;
        vga_console_info.u.vesa_lfb.gbl_caps = 2; /* possibly non-VGA */
        vga_console_info.u.vesa_lfb.width =
            mode_info->HorizontalResolution;
        vga_console_info.u.vesa_lfb.height = mode_info->VerticalResolution;
        vga_console_info.u.vesa_lfb.bits_per_pixel = bpp;
        vga_console_info.u.vesa_lfb.bytes_per_line =
            (mode_info->PixelsPerScanLine * bpp + 7) >> 3;
        vga_console_info.u.vesa_lfb.lfb_base = gop->Mode->FrameBufferBase;
        vga_console_info.u.vesa_lfb.lfb_size =
            (gop->Mode->FrameBufferSize + 0xffff) >> 16;
    }
#endif
}

static void __init efi_arch_memory_setup(void)
{
    unsigned int i;
    EFI_STATUS status;

    /* Don't allocate if we are going to relaunch ourselves */
    if ( tboot_file.size )
        return;

    /* Allocate space for trampoline (in first Mb). */
    cfg.addr = 0x100000;

    if ( efi_enabled(EFI_LOADER) )
        cfg.size = trampoline_end - trampoline_start;
    else
        cfg.size = TRAMPOLINE_SPACE + TRAMPOLINE_STACK_SPACE;

    status = efi_bs->AllocatePages(AllocateMaxAddress, EfiLoaderData,
                                   PFN_UP(cfg.size), &cfg.addr);
    if ( status == EFI_SUCCESS )
        relocate_trampoline(cfg.addr);
    else
    {
        cfg.addr = 0;
        PrintStr(L"Trampoline space cannot be allocated; will try fallback.\r\n");
    }

    if ( !efi_enabled(EFI_LOADER) )
        return;

    /* Initialise L2 identity-map and boot-map page table entries (16MB). */
    for ( i = 0; i < 8; ++i )
    {
        unsigned int slot = (xen_phys_start >> L2_PAGETABLE_SHIFT) + i;
        paddr_t addr = slot << L2_PAGETABLE_SHIFT;

        l2_identmap[slot] = l2e_from_paddr(addr, PAGE_HYPERVISOR|_PAGE_PSE);
        slot &= L2_PAGETABLE_ENTRIES - 1;
        l2_bootmap[slot] = l2e_from_paddr(addr, __PAGE_HYPERVISOR|_PAGE_PSE);
    }
    /* Initialise L3 boot-map page directory entries. */
    l3_bootmap[l3_table_offset(xen_phys_start)] =
        l3e_from_paddr((UINTN)l2_bootmap, __PAGE_HYPERVISOR);
    l3_bootmap[l3_table_offset(xen_phys_start + (8 << L2_PAGETABLE_SHIFT) - 1)] =
        l3e_from_paddr((UINTN)l2_bootmap, __PAGE_HYPERVISOR);
}

static void __init efi_arch_handle_module(struct file *file, const CHAR16 *name,
                                          char *options)
{
    union string local_name;
    void *ptr;

    /*
     * Make a copy, as conversion is destructive, and caller still wants
     * wide string available after this call returns.
     */
    if ( efi_bs->AllocatePool(EfiLoaderData, (wstrlen(name) + 1) * sizeof(*name),
                              &ptr) != EFI_SUCCESS )
        blexit(L"Unable to allocate string buffer");

    local_name.w = ptr;
    wstrcpy(local_name.w, name);
    w2s(&local_name);

    /*
     * If options are provided, put them in
     * mb_modules[mbi.mods_count].string after the filename, with a space
     * separating them.  place_string() prepends strings and adds separating
     * spaces, so the call order is reversed.
     */
    if ( options )
        place_string(&mb_modules[mbi.mods_count].string, options);
    place_string(&mb_modules[mbi.mods_count].string, local_name.s);
    mb_modules[mbi.mods_count].mod_start = file->addr >> PAGE_SHIFT;
    mb_modules[mbi.mods_count].mod_end = file->size;
    ++mbi.mods_count;
    efi_bs->FreePool(ptr);
}

static void __init efi_arch_cpu(void)
{
    uint32_t eax = cpuid_eax(0x80000000);

    if ( (eax >> 16) == 0x8000 && eax > 0x80000000 )
    {
        cpuid_ext_features = cpuid_edx(0x80000001);
        boot_cpu_data.x86_capability[cpufeat_word(X86_FEATURE_SYSCALL)]
            = cpuid_ext_features;
    }
}

static void __init efi_arch_blexit(void)
{
    if ( ucode.addr )
        efi_bs->FreePages(ucode.addr, PFN_UP(ucode.size));
}

static void __init efi_arch_halt(void)
{
    local_irq_disable();
    for ( ; ; )
        halt();
}

static void __init efi_arch_load_addr_check(EFI_LOADED_IMAGE *loaded_image)
{
    xen_phys_start = (UINTN)loaded_image->ImageBase;
    if ( (xen_phys_start + loaded_image->ImageSize - 1) >> 32 )
        blexit(L"Xen must be loaded below 4Gb.");
    if ( xen_phys_start & ((1 << L2_PAGETABLE_SHIFT) - 1) )
        blexit(L"Xen must be loaded at a 2Mb boundary.");
    trampoline_xen_phys_start = xen_phys_start;
}

static bool __init efi_arch_use_config_file(EFI_SYSTEM_TABLE *SystemTable)
{
    return true; /* x86 always uses a config file */
}

static void __init efi_arch_flush_dcache_area(const void *vaddr, UINTN size) { }

void __init efi_multiboot2(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_GRAPHICS_OUTPUT_PROTOCOL *gop;
    UINTN cols, gop_mode = ~0, rows;

    __set_bit(EFI_BOOT, &efi_flags);
    __set_bit(EFI_RS, &efi_flags);

    efi_init(ImageHandle, SystemTable);

    efi_console_set_mode();

    if ( StdOut->QueryMode(StdOut, StdOut->Mode->Mode,
                           &cols, &rows) == EFI_SUCCESS )
        efi_arch_console_init(cols, rows);

    gop = efi_get_gop();

    if ( gop )
        gop_mode = efi_find_gop_mode(gop, 0, 0, 0);

    efi_arch_edd();
    efi_arch_cpu();

    efi_tables();
    setup_efi_pci();
    efi_variables();
    efi_arch_memory_setup();

    if ( gop )
        efi_set_gop_mode(gop, gop_mode);

    efi_exit_boot(ImageHandle, SystemTable);
}

static void __init relocate_pagetables_only(void)
{
    u64 *ptr;
    unsigned int i;

    /* Instead of walking the PE relocation tables, rely on the fact that page
     * tables have a well-known structure and relocate all present entries.
     */
    for ( ptr = (void *)__page_tables_start; ptr != __page_tables_end; ptr++)
    {
        if ( !(*ptr & _PAGE_PRESENT) )
            continue;

        *ptr += xen_phys_start;
    }

    /* The above loop also adjusted l2_identmap, but that mostly contains a 1:1
     * mapping that should not have been relocated.  The first entry of that
     * table is already correct; re-generate the rest now.
     */
    for ( i = 1; i < 8; i++ )
    {
        paddr_t addr = i << L2_PAGETABLE_SHIFT;
        l2_identmap[i] = l2e_from_paddr(addr, PAGE_HYPERVISOR|_PAGE_PSE);
    }

    /* Map 16MB starting at xen_phys_start, as expected by __start_xen */
    for ( i = 0; i < 8; i++ )
    {
        paddr_t addr = (i << L2_PAGETABLE_SHIFT) + xen_phys_start;
        unsigned int slot = addr >> L2_PAGETABLE_SHIFT;
        l2_identmap[slot] = l2e_from_paddr(addr, PAGE_HYPERVISOR|_PAGE_PSE);
    }
}

static void __init relocate_trampoline_e820(void)
{
    unsigned long trampoline_size, trampoline_addr;
    unsigned int i;

    /* Allocate trampoline from memory below the legacy video buffers at
     * 0xA0000, which might end up clobbered by the VGA driver if that
     * is improperly enabled (Xen might write to 0xB8000-0xC0000).
     */
    trampoline_size = trampoline_end - trampoline_start;
    trampoline_addr = 0;
    for ( i = 0; i < e820_raw.nr_map; i++ )
    {
        unsigned long trampoline_max_start = 0xa0000 - trampoline_size;
        trampoline_max_start &= PAGE_MASK;
        if ( e820_raw.map[i].type == E820_RAM &&
             e820_raw.map[i].addr <= trampoline_max_start &&
             e820_raw.map[i].size >= trampoline_size )
        {
            unsigned long end = e820_raw.map[i].addr + e820_raw.map[i].size;
            trampoline_addr = (end - trampoline_size) & PAGE_MASK;
        }
    }
    relocate_trampoline(trampoline_addr);
    memcpy((void *)trampoline_phys, trampoline_start, trampoline_size);
}

struct tboot_table {
    char magic[8];        // "TBOOT_PE"
    uint64_t phys_start;
};

/* This function is invoked by the PE entry point when the EFI system table's
 * header does not have the correct signature.  It handles the case where Xen is
 * being re-entered after invoking tboot (see do_sinit above).
 *
 * On return from tboot, we do not run 1:1 mapped, although our physical and
 * virtual memory layouts are identical except for an offset.  Our physical
 * start address is provided by tboot in a second information table.
 *
 * Be careful when calling other functions in this file; many of them assume
 * that Xen is 1:1 mapped and omit calls to __pa() when using Xen symbols.
 *
 * Note that Xen's directmap is not available until we switch page tables in
 * enter_xen_context. The lower 4GB of memory is 1:1 mapped, and that is where
 * this function's arguments reside.
 */
static void __init arch_pe_entry(EFI_HANDLE ImageHandle,
                                 EFI_SYSTEM_TABLE *SystemTable)
{
    struct tboot_table *tboot_table = (void *)SystemTable;

    if ( SystemTable->Hdr.Signature == EFI_SYSTEM_TABLE_SIGNATURE )
        return;

    xen_phys_start = tboot_table->phys_start;
    trampoline_xen_phys_start = xen_phys_start;

    read_tboot_mbi(ImageHandle);

    /* Runtime services are implemented via unmeasured code that the hypervisor
     * jumps to in ring-0 context.  This is nearly impossible to secure.
     *
     * Disable them even if SINIT failed to simplify debugging problems that are
     * purely due to not having access to runtime services.
     */
    __clear_bit(EFI_RS, &efi_flags);

    /* Relocate the pointers we use to their 1:1 map instead of using the
     * directmap (which is not present until we switch page tables)
     */
    efi_ct = (void *)efi_ct - DIRECTMAP_VIRT_START;

    efi_arch_cpu();
    efi_tables();

    efi_ct = (void *)efi_ct + DIRECTMAP_VIRT_START;

    relocate_pagetables_only();
    relocate_trampoline_e820();

    enter_xen_context(__pa(&mbi), __pa(idle_pg_table));
}

/* This function is called after Xen is started and verifies that the various
 * data structures that bypassed tboot are located in RAM.
 */
void __init efi_tboot_verify_memory(bool (*not_ram)(const void*, size_t, void*), void* data)
{
    const struct efi_pci_rom *pci = efi_pci_roms;

    /* Bail if we are not under UEFI */
    if ( !efi_enabled(EFI_BOOT) || !efi_enabled(EFI_LOADER) )
        return;

    BUG_ON(not_ram(efi_ct, efi_num_ct * sizeof(*efi_ct), data));
    BUG_ON(not_ram(efi_memmap, efi_memmap_size * efi_mdesc_size, data));

    while ( pci != NULL )
    {
        BUG_ON(not_ram(pci, sizeof(*pci) + pci->size, data));
        pci = pci->next;
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
