/******************************************************************************
 * tools/proctrace.c
 *
 * Demonstrative tool for collecting Intel Processor Trace data from Xen.
 *  Could be used to externally monitor a given vCPU in given DomU.
 *
 * Copyright (C) 2020 by CERT Polska - NASK PIB
 *
 * Authors: Michał Leszczyński, michal.leszczynski@cert.pl
 * Date:    June, 2020
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; under version 2 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <signal.h>
#include <errno.h>

#include <xenctrl.h>
#include <xen/xen.h>
#include <xenforeignmemory.h>

volatile int interrupted = 0;
volatile int domain_down = 0;

void term_handler(int signum) {
    interrupted = 1;
}

int main(int argc, char* argv[]) {
    xc_interface *xc;
    uint32_t domid;
    uint32_t vcpu_id;
    uint64_t size;

    int rc = -1;
    uint8_t *buf = NULL;
    uint64_t last_offset = 0;

    xenforeignmemory_handle *fmem;
    xenforeignmemory_resource_handle *fres;

    if (signal(SIGINT, term_handler) == SIG_ERR)
    {
        fprintf(stderr, "Failed to register signal handler\n");
        return 1;
    }

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <domid> <vcpu_id>\n", argv[0]);
        fprintf(stderr, "It's recommended to redirect this"
                        "program's output to file\n");
        fprintf(stderr, "or to pipe it's output to xxd or other program.\n");
        return 1;
    }

    domid = atoi(argv[1]);
    vcpu_id = atoi(argv[2]);

    xc = xc_interface_open(0, 0, 0);

    fmem = xenforeignmemory_open(0, 0);

    if (!xc) {
        fprintf(stderr, "Failed to open xc interface\n");
        return 1;
    }

    rc = xc_vmtrace_pt_enable(xc, domid, vcpu_id);

    if (rc) {
        fprintf(stderr, "Failed to call xc_vmtrace_pt_enable\n");
        return 1;
    }
    
    rc = xc_vmtrace_pt_get_offset(xc, domid, vcpu_id, NULL, &size);

    if (rc) {
        fprintf(stderr, "Failed to get trace buffer size\n");
        return 1;
    }

    fres = xenforeignmemory_map_resource(
        fmem, domid, XENMEM_resource_vmtrace_buf,
        /* vcpu: */ vcpu_id,
        /* frame: */ 0,
        /* num_frames: */ size >> XC_PAGE_SHIFT,
        (void **)&buf,
        PROT_READ, 0);

    if (!buf) {
        fprintf(stderr, "Failed to map trace buffer\n");
        return 1;
    }

    while (!interrupted) {
        uint64_t offset;
        rc = xc_vmtrace_pt_get_offset(xc, domid, vcpu_id, &offset, NULL);

        if (rc == ENODATA) {
            interrupted = 1;
            domain_down = 1;
	} else if (rc) {
            fprintf(stderr, "Failed to call xc_vmtrace_pt_get_offset\n");
            return 1;
        }

        if (offset > last_offset)
        {
            fwrite(buf + last_offset, offset - last_offset, 1, stdout);
        }
        else if (offset < last_offset)
        {
            // buffer wrapped
            fwrite(buf + last_offset, size - last_offset, 1, stdout);
            fwrite(buf, offset, 1, stdout);
        }

        last_offset = offset;
        usleep(1000 * 100);
    }

    rc = xenforeignmemory_unmap_resource(fmem, fres);

    if (rc) {
        fprintf(stderr, "Failed to unmap resource\n");
        return 1;
    }

    rc = xenforeignmemory_close(fmem);

    if (rc) {
        fprintf(stderr, "Failed to close fmem\n");
        return 1;
    }

    /*
     * Don't try to disable PT if the domain is already dying.
     */
    if (!domain_down) {
        rc = xc_vmtrace_pt_disable(xc, domid, vcpu_id);

        if (rc) {
            fprintf(stderr, "Failed to call xc_vmtrace_pt_disable\n");
            return 1;
        }
    }

    rc = xc_interface_close(xc);

    if (rc) {
        fprintf(stderr, "Failed to close xc interface\n");
        return 1;
    }

    return 0;
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
