/*
 * ipt.c: Support for Intel Processor Trace Virtualization.
 *
 * Copyright (c) 2018, Intel Corporation.
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
 *
 * Author: Luwei Kang <luwei.kang@intel.com>
 */
#include <xen/errno.h>
#include <xen/init.h>
#include <xen/lib.h>
#include <xen/string.h>
#include <asm/ipt.h>

/* ipt: Flag to enable Intel Processor Trace (default off). */
unsigned int __read_mostly ipt_mode = IPT_MODE_OFF;
static int parse_ipt_params(const char *str);
custom_param("ipt", parse_ipt_params);

static int __init parse_ipt_params(const char *str)
{
    if ( !strcmp("guest", str) )
        ipt_mode = IPT_MODE_GUEST;
    else if ( str )
    {
        printk("Unknown Intel Processor Trace mode specified: '%s'\n", str);
        return -EINVAL;
    }

    return 0;
}
