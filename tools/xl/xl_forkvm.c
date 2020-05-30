/*
 * Copyright 2020 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */

#include <fcntl.h>
#include <inttypes.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <libxl.h>
#include <libxl_utils.h>
#include <libxlutil.h>

#include "xl.h"
#include "xl_utils.h"
#include "xl_parse.h"

int main_fork_vm(int argc, char **argv)
{
    int rc, debug = 0;
    uint32_t domid_in = INVALID_DOMID, domid_out = INVALID_DOMID;
    int launch_dm = 1;
    bool pause = 0;
    const char *config_file = NULL;
    const char *dm_restore_file = NULL;

    int opt;
    static struct option opts[] = {
        {"launch-dm", 1, 0, 'l'},
        COMMON_LONG_OPTS
    };

    SWITCH_FOREACH_OPT(opt, "phdC:Q:l:", opts, "fork-vm", 1) {
    case 'd':
        debug = 1;
        break;
    case 'p':
        pause = 1;
        break;
    case 'C':
        config_file = optarg;
        break;
    case 'Q':
        dm_restore_file = optarg;
        break;
    case 'l':
        if ( !strcmp(optarg, "no") )
            launch_dm = 0;
        if ( !strcmp(optarg, "yes") )
            launch_dm = 1;
        if ( !strcmp(optarg, "late") )
            launch_dm = 2;
        break;
    default:
        fprintf(stderr, "Unimplemented option(s)\n");
        return EXIT_FAILURE;
    }

    if (argc-optind == 1) {
        domid_in = atoi(argv[optind]);
    } else {
        help("fork-vm");
        return EXIT_FAILURE;
    }

    if (launch_dm && (!config_file || !dm_restore_file)) {
        fprintf(stderr, "Currently you must provide both -C and -Q options\n");
        return EXIT_FAILURE;
    }

    if (launch_dm == 2) {
        domid_out = domid_in;
        rc = EXIT_SUCCESS;
    } else {
        rc = libxl_domain_fork_vm(ctx, domid_in, &domid_out);
    }

    if (rc == EXIT_SUCCESS) {
        if ( launch_dm ) {
            struct domain_create dom_info;
            memset(&dom_info, 0, sizeof(dom_info));
            dom_info.dm_restore_domid = domid_out;
            dom_info.dm_restore_file = dm_restore_file;
            dom_info.debug = debug;
            dom_info.paused = pause;
            dom_info.config_file = config_file;
            dom_info.migrate_fd = -1;
            dom_info.send_back_fd = -1;
            rc = create_domain(&dom_info) < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
        } else if ( !pause )
            rc = libxl_domain_unpause(ctx, domid_out, NULL);
    }

    if (rc == EXIT_SUCCESS)
        fprintf(stderr, "fork-vm command successfully returned domid: %u\n", domid_out);
    else if ( domid_out != INVALID_DOMID )
        libxl_domain_destroy(ctx, domid_out, 0);

    return rc;
}

/*
 * Local variables:
 * mode: C
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
