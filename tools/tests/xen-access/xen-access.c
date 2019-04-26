/*
 * xen-access.c
 *
 * Exercises the basic per-page access mechanisms
 *
 * Copyright (c) 2011 Virtuata, Inc.
 * Copyright (c) 2009 by Citrix Systems, Inc. (Patrick Colp), based on
 *   xenpaging.c
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <poll.h>
#include <getopt.h>

#include <xen-tools/libs.h>

#if defined(__arm__) || defined(__aarch64__)
#include <xen/arch-arm.h>
#define START_PFN (GUEST_RAM0_BASE >> 12)
#elif defined(__i386__) || defined(__x86_64__)
#define START_PFN 0ULL
#endif

#include "xen-access.h"

/* From xen/include/asm-x86/processor.h */
#define X86_TRAP_DEBUG  1
#define X86_TRAP_INT3   3

/* From xen/include/asm-x86/x86-defns.h */
#define X86_CR4_PGE        0x00000080 /* enable global pages */

static int interrupted;

static void close_handler(int sig)
{
    interrupted = sig;
}

static int xc_wait_for_event_or_timeout(xc_interface *xch, xenevtchn_handle *xce, unsigned long ms)
{
    struct pollfd fd = { .fd = xenevtchn_fd(xce), .events = POLLIN | POLLERR };
    int port;
    int rc;

    rc = poll(&fd, 1, ms);
    if ( rc == -1 )
    {
        if (errno == EINTR)
            return 0;

        ERROR("Poll exited with an error");
        goto err;
    }

    if ( rc == 1 )
    {
        port = xenevtchn_pending(xce);
        if ( port == -1 )
        {
            ERROR("Failed to read port from event channel");
            goto err;
        }

        rc = xenevtchn_unmask(xce, port);
        if ( rc != 0 )
        {
            ERROR("Failed to unmask event channel port");
            goto err;
        }
    }
    else
        port = -1;

    return port;

 err:
    return -errno;
}

static int vm_event_teardown(vm_event_t *vm_event)
{
    int rc;

    if ( vm_event == NULL )
        return 0;

    rc = vm_event->ops->teardown(vm_event);
    if ( rc != 0 )
        return rc;

    /* Close event channel */
    rc = xenevtchn_close(vm_event->xce);
    if ( rc != 0 )
    {
        ERROR("Error closing event channel");
        return rc;
    }

    /* Close connection to Xen */
    rc = xc_interface_close(vm_event->xch);
    if ( rc != 0 )
    {
        ERROR("Error closing connection to xen");
        return rc;
    }

    return 0;
}

static vm_event_t *vm_event_init(domid_t domain_id, vm_event_ops_t *ops)
{
    vm_event_t *vm_event;
    xc_interface *xch;
    xenevtchn_handle *xce;
    xen_pfn_t max_gpfn;
    int rc;

    if ( ops == NULL )
        return NULL;

    xch = xc_interface_open(NULL, NULL, 0);
    if ( xch == NULL )
        goto err;

    DPRINTF("xenaccess init\n");

    /* Open event channel */
    xce = xenevtchn_open(NULL, 0);
    if ( xce == NULL )
    {
        ERROR("Failed to open event channel");
        goto err;
    }

    /* Get max_gpfn */
    rc = xc_domain_maximum_gpfn(xch, domain_id, &max_gpfn);
    if ( rc )
    {
        ERROR("Failed to get max gpfn");
        goto err;
    }
    DPRINTF("max_gpfn = %"PRI_xen_pfn"\n", max_gpfn);

    rc = ops->init(xch, xce, domain_id, ops, &vm_event);
    if ( rc < 0 )
        goto err;

    vm_event->xch = xch;
    vm_event->xce = xce;
    vm_event->domain_id = domain_id;
    vm_event->ops = ops;
    vm_event->max_gpfn = max_gpfn;

    return vm_event;

 err:
    xenevtchn_close(xce);
    xc_interface_close(xch);

    return NULL;
}

static inline int control_singlestep(xc_interface *xch, domid_t domain_id,
                                     unsigned long vcpu, bool enable)
{
    uint32_t op = enable ?
        XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_ON : XEN_DOMCTL_DEBUG_OP_SINGLE_STEP_OFF;

    return xc_domain_debug_control(xch, domain_id, op, vcpu);
}

/*
 * X86 control register names
 */
static const char* get_x86_ctrl_reg_name(uint32_t index)
{
    static const char* names[] = {
        [VM_EVENT_X86_CR0]  = "CR0",
        [VM_EVENT_X86_CR3]  = "CR3",
        [VM_EVENT_X86_CR4]  = "CR4",
        [VM_EVENT_X86_XCR0] = "XCR0",
    };

    if ( index >= ARRAY_SIZE(names) || names[index] == NULL )
        return "";

    return names[index];
}

void usage(char* progname)
{
    fprintf(stderr, "Usage: %s [-m] [-n] <domain_id> write|exec", progname);
#if defined(__i386__) || defined(__x86_64__)
    fprintf(stderr, "|breakpoint|altp2m_write|altp2m_exec|debug|cpuid|desc_access|write_ctrlreg_cr4|altp2m_write_no_gpt");
#elif defined(__arm__) || defined(__aarch64__)
    fprintf(stderr, "|privcall");
#endif
    fprintf(stderr,
            "\n"
            "Logs first page writes, execs, or breakpoint traps that occur on the domain.\n"
            "\n"
            "-m requires this program to run, or else the domain may pause\n"
            "-n uses the per-vcpu channels vm_event interface\n");
}

extern vm_event_ops_t ring_ops;
extern vm_event_ops_t channel_ops;

int main(int argc, char *argv[])
{
    struct sigaction act;
    domid_t domain_id;
    vm_event_t *vm_event;
    vm_event_request_t req;
    vm_event_response_t rsp;
    int rc = -1;
    int rc1;
    xenmem_access_t default_access = XENMEM_access_rwx;
    xenmem_access_t after_first_access = XENMEM_access_rwx;
    int memaccess = 0;
    int required = 0;
    int breakpoint = 0;
    int shutting_down = 0;
    int privcall = 0;
    int altp2m = 0;
    int debug = 0;
    int cpuid = 0;
    int desc_access = 0;
    int write_ctrlreg_cr4 = 0;
    int altp2m_write_no_gpt = 0;
    uint16_t altp2m_view_id = 0;
    int new_interface = 0;

    char* progname = argv[0];
    char* command;
    int c;
    int option_index;
    struct option long_options[] =
    {
        { "mem-access-listener", no_argument, 0, 'm' },
        { "new-interface", no_argument, 0, 'n' },
    };

    while ( 1 )
    {
        c = getopt_long(argc, argv, "mn", long_options, &option_index);
        if ( c == -1 )
            break;

        switch ( c )
        {
        case 'm':
            required = 1;
            break;

        case 'n':
            new_interface = 1;
            break;

        default:
            usage(progname);
            return -1;
        }
    }

    if ( argc - optind != 2 )
    {
        usage(progname);
        return -1;
    }

    domain_id = atoi(argv[optind++]);
    command = argv[optind];

    if ( !strcmp(command, "write") )
    {
        default_access = XENMEM_access_rx;
        after_first_access = XENMEM_access_rwx;
        memaccess = 1;
    }
    else if ( !strcmp(command, "exec") )
    {
        default_access = XENMEM_access_rw;
        after_first_access = XENMEM_access_rwx;
        memaccess = 1;
    }
#if defined(__i386__) || defined(__x86_64__)
    else if ( !strcmp(command, "breakpoint") )
    {
        breakpoint = 1;
    }
    else if ( !strcmp(command, "altp2m_write") )
    {
        default_access = XENMEM_access_rx;
        altp2m = 1;
        memaccess = 1;
    }
    else if ( !strcmp(command, "altp2m_exec") )
    {
        default_access = XENMEM_access_rw;
        altp2m = 1;
        memaccess = 1;
    }
    else if ( !strcmp(command, "altp2m_write_no_gpt") )
    {
        default_access = XENMEM_access_rw;
        altp2m_write_no_gpt = 1;
        memaccess = 1;
        altp2m = 1;
    }
    else if ( !strcmp(command, "debug") )
    {
        debug = 1;
    }
    else if ( !strcmp(command, "cpuid") )
    {
        cpuid = 1;
    }
    else if ( !strcmp(command, "desc_access") )
    {
        desc_access = 1;
    }
    else if ( !strcmp(command, "write_ctrlreg_cr4") )
    {
        write_ctrlreg_cr4 = 1;
    }
#elif defined(__arm__) || defined(__aarch64__)
    else if ( !strcmp(command, "privcall") )
    {
        privcall = 1;
    }
#endif
    else
    {
        usage(command);
        return -1;
    }

    vm_event = vm_event_init(domain_id,
                             (new_interface) ? &channel_ops : &ring_ops);
    if ( vm_event == NULL )
    {
        ERROR("Error initialising vm_event");
        return 1;
    }

    DPRINTF("starting %s %u\n", command, domain_id);

    /* ensure that if we get a signal, we'll do cleanup, then exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    /* Set whether the access listener is required */
    rc = xc_domain_set_access_required(vm_event->xch, domain_id, required);
    if ( rc < 0 )
    {
        ERROR("Error %d setting mem_access listener required\n", rc);
        goto exit;
    }

    /* With altp2m we just create a new, restricted view of the memory */
    if ( memaccess && altp2m )
    {
        xen_pfn_t gfn = 0;
        unsigned long perm_set = 0;

        if( altp2m_write_no_gpt )
        {
            rc = xc_monitor_inguest_pagefault(vm_event->xch, domain_id, 1);
            if ( rc < 0 )
            {
                ERROR("Error %d setting inguest pagefault\n", rc);
                goto exit;
            }
            rc = xc_monitor_emul_unimplemented(vm_event->xch, domain_id, 1);
            if ( rc < 0 )
            {
                ERROR("Error %d failed to enable emul unimplemented\n", rc);
                goto exit;
            }
        }

        rc = xc_altp2m_set_domain_state( vm_event->xch, domain_id, 1 );
        if ( rc < 0 )
        {
            ERROR("Error %d enabling altp2m on domain!\n", rc);
            goto exit;
        }

        rc = xc_altp2m_create_view( vm_event->xch, domain_id, default_access,
                                    &altp2m_view_id );
        if ( rc < 0 )
        {
            ERROR("Error %d creating altp2m view!\n", rc);
            goto exit;
        }

        DPRINTF("altp2m view created with id %u\n", altp2m_view_id);
        DPRINTF("Setting altp2m mem_access permissions.. ");

        for( ; gfn < vm_event->max_gpfn; ++gfn )
        {
            rc = xc_altp2m_set_mem_access( vm_event->xch, domain_id,
                                           altp2m_view_id, gfn, default_access);
            if ( !rc )
                perm_set++;
        }

        DPRINTF("done! Permissions set on %lu pages.\n", perm_set);

        rc = xc_altp2m_switch_to_view( vm_event->xch, domain_id, altp2m_view_id );
        if ( rc < 0 )
        {
            ERROR("Error %d switching to altp2m view!\n", rc);
            goto exit;
        }

        rc = xc_monitor_singlestep( vm_event->xch, domain_id, 1 );
        if ( rc < 0 )
        {
            ERROR("Error %d failed to enable singlestep monitoring!\n", rc);
            goto exit;
        }
    }

    if ( memaccess && !altp2m )
    {
        /* Set the default access type and convert all pages to it */
        rc = xc_set_mem_access(vm_event->xch, domain_id, default_access, ~0ull, 0);
        if ( rc < 0 )
        {
            ERROR("Error %d setting default mem access type\n", rc);
            goto exit;
        }

        rc = xc_set_mem_access(vm_event->xch, domain_id, default_access, START_PFN,
                               (vm_event->max_gpfn - START_PFN) );

        if ( rc < 0 )
        {
            ERROR("Error %d setting all memory to access type %d\n", rc,
                  default_access);
            goto exit;
        }
    }

    if ( breakpoint )
    {
        rc = xc_monitor_software_breakpoint(vm_event->xch, domain_id, 1);
        if ( rc < 0 )
        {
            ERROR("Error %d setting breakpoint trapping with vm_event\n", rc);
            goto exit;
        }
    }

    if ( debug )
    {
        rc = xc_monitor_debug_exceptions(vm_event->xch, domain_id, 1, 1);
        if ( rc < 0 )
        {
            ERROR("Error %d setting debug exception listener with vm_event\n", rc);
            goto exit;
        }
    }

    if ( cpuid )
    {
        rc = xc_monitor_cpuid(vm_event->xch, domain_id, 1);
        if ( rc < 0 )
        {
            ERROR("Error %d setting cpuid listener with vm_event\n", rc);
            goto exit;
        }
    }

    if ( desc_access )
    {
        rc = xc_monitor_descriptor_access(vm_event->xch, domain_id, 1);
        if ( rc < 0 )
        {
            ERROR("Error %d setting descriptor access listener with vm_event\n", rc);
            goto exit;
        }
    }

    if ( privcall )
    {
        rc = xc_monitor_privileged_call(vm_event->xch, domain_id, 1);
        if ( rc < 0 )
        {
            ERROR("Error %d setting privileged call trapping with vm_event\n", rc);
            goto exit;
        }
    }

    if ( write_ctrlreg_cr4 )
    {
        /* Mask the CR4.PGE bit so no events will be generated for global TLB flushes. */
        rc = xc_monitor_write_ctrlreg(vm_event->xch, domain_id, VM_EVENT_X86_CR4, 1, 1,
                                      X86_CR4_PGE, 1);
        if ( rc < 0 )
        {
            ERROR("Error %d setting write control register trapping with vm_event\n", rc);
            goto exit;
        }
    }

    /* Wait for access */
    for ( ; ; )
    {
        int port = 0;

        if ( interrupted )
        {
            /* Unregister for every event */
            DPRINTF("xenaccess shutting down on signal %d\n", interrupted);

            if ( breakpoint )
                rc = xc_monitor_software_breakpoint(vm_event->xch, domain_id, 0);
            if ( debug )
                rc = xc_monitor_debug_exceptions(vm_event->xch, domain_id, 0, 0);
            if ( cpuid )
                rc = xc_monitor_cpuid(vm_event->xch, domain_id, 0);
            if ( desc_access )
                rc = xc_monitor_descriptor_access(vm_event->xch, domain_id, 0);
            if ( write_ctrlreg_cr4 )
                rc = xc_monitor_write_ctrlreg(vm_event->xch, domain_id, VM_EVENT_X86_CR4, 0, 0, 0, 0);

            if ( privcall )
                rc = xc_monitor_privileged_call(vm_event->xch, domain_id, 0);

            if ( altp2m )
            {
                rc = xc_altp2m_switch_to_view( vm_event->xch, domain_id, 0 );
                rc = xc_altp2m_destroy_view(vm_event->xch, domain_id, altp2m_view_id);
                rc = xc_altp2m_set_domain_state(vm_event->xch, domain_id, 0);
                rc = xc_monitor_singlestep(vm_event->xch, domain_id, 0);
            } else {
                rc = xc_set_mem_access(vm_event->xch, domain_id, XENMEM_access_rwx, ~0ull, 0);
                rc = xc_set_mem_access(vm_event->xch, domain_id, XENMEM_access_rwx, START_PFN,
                                       (vm_event->max_gpfn - START_PFN) );
            }

            shutting_down = 1;
        }

        rc = xc_wait_for_event_or_timeout(vm_event->xch, vm_event->xce, 100);
        if ( rc < -1 )
        {
            ERROR("Error getting event");
            interrupted = -1;
            continue;
        }
        else if ( rc != -1 )
        {
            DPRINTF("Got event from Xen\n");
        }

        port = rc;

        while ( vm_event->ops->get_request(vm_event, &req, &port) )
        {
            if ( req.version != VM_EVENT_INTERFACE_VERSION )
            {
                ERROR("Error: vm_event interface version mismatch!\n");
                interrupted = -1;
                continue;
            }

            memset( &rsp, 0, sizeof (rsp) );
            rsp.version = VM_EVENT_INTERFACE_VERSION;
            rsp.vcpu_id = req.vcpu_id;
            rsp.flags = (req.flags & VM_EVENT_FLAG_VCPU_PAUSED);
            rsp.reason = req.reason;

            switch ( req.reason )
            {
            case VM_EVENT_REASON_MEM_ACCESS:
                if ( !shutting_down )
                {
                    /*
                     * This serves no other purpose here then demonstrating the use of the API.
                     * At shutdown we have already reset all the permissions so really no use getting it again.
                     */
                    xenmem_access_t access;
                    rc = xc_get_mem_access(vm_event->xch, domain_id, req.u.mem_access.gfn, &access);
                    if (rc < 0)
                    {
                        ERROR("Error %d getting mem_access event\n", rc);
                        interrupted = -1;
                        continue;
                    }
                }

                printf("PAGE ACCESS: %c%c%c for GFN %"PRIx64" (offset %06"
                       PRIx64") gla %016"PRIx64" (valid: %c; fault in gpt: %c; fault with gla: %c) (vcpu %u [%c], altp2m view %u)\n",
                       (req.u.mem_access.flags & MEM_ACCESS_R) ? 'r' : '-',
                       (req.u.mem_access.flags & MEM_ACCESS_W) ? 'w' : '-',
                       (req.u.mem_access.flags & MEM_ACCESS_X) ? 'x' : '-',
                       req.u.mem_access.gfn,
                       req.u.mem_access.offset,
                       req.u.mem_access.gla,
                       (req.u.mem_access.flags & MEM_ACCESS_GLA_VALID) ? 'y' : 'n',
                       (req.u.mem_access.flags & MEM_ACCESS_FAULT_IN_GPT) ? 'y' : 'n',
                       (req.u.mem_access.flags & MEM_ACCESS_FAULT_WITH_GLA) ? 'y': 'n',
                       req.vcpu_id,
                       (req.flags & VM_EVENT_FLAG_VCPU_PAUSED) ? 'p' : 'r',
                       req.altp2m_idx);

                if ( altp2m && req.flags & VM_EVENT_FLAG_ALTERNATE_P2M)
                {
                    DPRINTF("\tSwitching back to default view!\n");

                    rsp.flags |= (VM_EVENT_FLAG_ALTERNATE_P2M | VM_EVENT_FLAG_TOGGLE_SINGLESTEP);
                    rsp.altp2m_idx = 0;
                }
                else if ( default_access != after_first_access )
                {
                    rc = xc_set_mem_access(vm_event->xch, domain_id, after_first_access,
                                           req.u.mem_access.gfn, 1);
                    if (rc < 0)
                    {
                        ERROR("Error %d setting gfn to access_type %d\n", rc,
                              after_first_access);
                        interrupted = -1;
                        continue;
                    }
                }

                rsp.u.mem_access = req.u.mem_access;
                break;

            case VM_EVENT_REASON_SOFTWARE_BREAKPOINT:
                printf("Breakpoint: rip=%016"PRIx64", gfn=%"PRIx64" (vcpu %d)\n",
                       req.data.regs.x86.rip,
                       req.u.software_breakpoint.gfn,
                       req.vcpu_id);

                /* Reinject */
                rc = xc_hvm_inject_trap(vm_event->xch, domain_id, req.vcpu_id,
                                        X86_TRAP_INT3,
                                        req.u.software_breakpoint.type, -1,
                                        req.u.software_breakpoint.insn_length, 0);
                if (rc < 0)
                {
                    ERROR("Error %d injecting breakpoint\n", rc);
                    interrupted = -1;
                    continue;
                }
                break;

            case VM_EVENT_REASON_PRIVILEGED_CALL:
                printf("Privileged call: pc=%"PRIx64" (vcpu %d)\n",
                       req.data.regs.arm.pc,
                       req.vcpu_id);

                rsp.data.regs.arm = req.data.regs.arm;
                rsp.data.regs.arm.pc += 4;
                rsp.flags |= VM_EVENT_FLAG_SET_REGISTERS;
                break;

            case VM_EVENT_REASON_SINGLESTEP:
                printf("Singlestep: rip=%016"PRIx64", vcpu %d, altp2m %u\n",
                       req.data.regs.x86.rip,
                       req.vcpu_id,
                       req.altp2m_idx);

                if ( altp2m )
                {
                    printf("\tSwitching altp2m to view %u!\n", altp2m_view_id);

                    rsp.flags |= VM_EVENT_FLAG_ALTERNATE_P2M;
                    rsp.altp2m_idx = altp2m_view_id;
                }

                rsp.flags |= VM_EVENT_FLAG_TOGGLE_SINGLESTEP;

                break;

            case VM_EVENT_REASON_DEBUG_EXCEPTION:
                printf("Debug exception: rip=%016"PRIx64", vcpu %d. Type: %u. Length: %u\n",
                       req.data.regs.x86.rip,
                       req.vcpu_id,
                       req.u.debug_exception.type,
                       req.u.debug_exception.insn_length);

                /* Reinject */
                rc = xc_hvm_inject_trap(vm_event->xch, domain_id, req.vcpu_id,
                                        X86_TRAP_DEBUG,
                                        req.u.debug_exception.type, -1,
                                        req.u.debug_exception.insn_length,
                                        req.data.regs.x86.cr2);
                if (rc < 0)
                {
                    ERROR("Error %d injecting breakpoint\n", rc);
                    interrupted = -1;
                    continue;
                }

                break;

            case VM_EVENT_REASON_CPUID:
                printf("CPUID executed: rip=%016"PRIx64", vcpu %d. Insn length: %"PRIu32" " \
                       "0x%"PRIx32" 0x%"PRIx32": EAX=0x%"PRIx64" EBX=0x%"PRIx64" ECX=0x%"PRIx64" EDX=0x%"PRIx64"\n",
                       req.data.regs.x86.rip,
                       req.vcpu_id,
                       req.u.cpuid.insn_length,
                       req.u.cpuid.leaf,
                       req.u.cpuid.subleaf,
                       req.data.regs.x86.rax,
                       req.data.regs.x86.rbx,
                       req.data.regs.x86.rcx,
                       req.data.regs.x86.rdx);
                rsp.flags |= VM_EVENT_FLAG_SET_REGISTERS;
                rsp.data = req.data;
                rsp.data.regs.x86.rip += req.u.cpuid.insn_length;
                break;

            case VM_EVENT_REASON_DESCRIPTOR_ACCESS:
                printf("Descriptor access: rip=%016"PRIx64", vcpu %d: "\
                       "VMExit info=0x%"PRIx32", descriptor=%d, is write=%d\n",
                       req.data.regs.x86.rip,
                       req.vcpu_id,
                       req.u.desc_access.arch.vmx.instr_info,
                       req.u.desc_access.descriptor,
                       req.u.desc_access.is_write);
                rsp.flags |= VM_EVENT_FLAG_EMULATE;
                break;

            case VM_EVENT_REASON_WRITE_CTRLREG:
                printf("Control register written: rip=%016"PRIx64", vcpu %d: "
                       "reg=%s, old_value=%016"PRIx64", new_value=%016"PRIx64"\n",
                       req.data.regs.x86.rip,
                       req.vcpu_id,
                       get_x86_ctrl_reg_name(req.u.write_ctrlreg.index),
                       req.u.write_ctrlreg.old_value,
                       req.u.write_ctrlreg.new_value);
                break;

            case VM_EVENT_REASON_EMUL_UNIMPLEMENTED:
                if ( altp2m_write_no_gpt && req.flags & VM_EVENT_FLAG_ALTERNATE_P2M )
                {
                    DPRINTF("\tSwitching back to default view!\n");

                    rsp.flags |= (VM_EVENT_FLAG_ALTERNATE_P2M |
                                  VM_EVENT_FLAG_TOGGLE_SINGLESTEP);
                    rsp.altp2m_idx = 0;
                }
                break;

            default:
                fprintf(stderr, "UNKNOWN REASON CODE %d\n", req.reason);
            }

            /* Put the response on the ring */
            put_response(vm_event, &rsp, port);

            /* Tell Xen page is ready */
            rc = notify_port(vm_event, port);
            if ( rc != 0 )
            {
                ERROR("Error resuming page");
                interrupted = -1;
            }
        }

        if ( shutting_down )
            break;
    }
    DPRINTF("xenaccess shut down on signal %d\n", interrupted);

exit:
    if ( altp2m )
    {
        uint32_t vcpu_id;
        for ( vcpu_id = 0; vcpu_id<XEN_LEGACY_MAX_VCPUS; vcpu_id++)
            rc = control_singlestep(vm_event->xch, domain_id, vcpu_id, 0);
    }

    /* Tear down domain */
    rc1 = vm_event_teardown(vm_event);
    if ( rc1 != 0 )
        ERROR("Error tearing down vm_event");

    if ( rc == 0 )
        rc = rc1;

    DPRINTF("xenaccess exit code %d\n", rc);

    return rc;
}


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
