/******************************************************************************
 * xc_vmtrace.c
 *
 * API for manipulating hardware tracing features
 *
 * Copyright (c) 2020, Michal Leszczynski
 *
 * Copyright 2020 CERT Polska. All rights reserved.
 * Use is subject to license terms.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; If not, see <http://www.gnu.org/licenses/>.
 */

#include "xc_private.h"
#include <xen/trace.h>

int xc_vmtrace_pt_enable(
        xc_interface *xch, uint32_t domid, uint32_t vcpu)
{
    DECLARE_DOMCTL;
    int rc;

    domctl.cmd = XEN_DOMCTL_vmtrace_op;
    domctl.domain = domid;
    domctl.u.vmtrace_op.cmd = XEN_DOMCTL_vmtrace_pt_enable;
    domctl.u.vmtrace_op.vcpu = vcpu;
    domctl.u.vmtrace_op.pad1 = 0;
    domctl.u.vmtrace_op.pad2 = 0;

    rc = do_domctl(xch, &domctl);
    return rc;
}

int xc_vmtrace_pt_get_offset(
        xc_interface *xch, uint32_t domid, uint32_t vcpu,
        uint64_t *offset, uint64_t *size)
{
    DECLARE_DOMCTL;
    int rc;

    domctl.cmd = XEN_DOMCTL_vmtrace_op;
    domctl.domain = domid;
    domctl.u.vmtrace_op.cmd = XEN_DOMCTL_vmtrace_pt_get_offset;
    domctl.u.vmtrace_op.vcpu = vcpu;
    domctl.u.vmtrace_op.pad1 = 0;
    domctl.u.vmtrace_op.pad2 = 0;

    rc = do_domctl(xch, &domctl);
    if ( !rc )
    {
        if (offset)
            *offset = domctl.u.vmtrace_op.offset;

        if (size)
            *size = domctl.u.vmtrace_op.size;
    }

    return rc;
}

int xc_vmtrace_pt_disable(xc_interface *xch, uint32_t domid, uint32_t vcpu)
{
    DECLARE_DOMCTL;
    int rc;

    domctl.cmd = XEN_DOMCTL_vmtrace_op;
    domctl.domain = domid;
    domctl.u.vmtrace_op.cmd = XEN_DOMCTL_vmtrace_pt_disable;
    domctl.u.vmtrace_op.vcpu = vcpu;
    domctl.u.vmtrace_op.pad1 = 0;
    domctl.u.vmtrace_op.pad2 = 0;

    rc = do_domctl(xch, &domctl);
    return rc;
}

