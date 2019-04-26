/*
 * vm-event-ng.c
 *
 * Copyright (c) 2019 Bitdefender S.R.L.
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
#include <string.h>
#include <sys/mman.h>
#include <xenforeignmemory.h>
#include "xen-access.h"

#ifndef PFN_UP
#define PFN_UP(x)     (((x) + XC_PAGE_SIZE-1) >> XC_PAGE_SHIFT)
#endif /* PFN_UP */

typedef struct vm_event_channels
{
    vm_event_t vme;
    int num_channels;
    xenforeignmemory_resource_handle *fres;
    struct vm_event_slot *slots;
    int *ports;
} vm_event_channels_t;

#define to_channels(_vme) container_of((_vme), vm_event_channels_t, vme)

static int vm_event_channels_init(xc_interface *xch, xenevtchn_handle *xce,
                                  domid_t domain_id, vm_event_ops_t *ops,
                                  vm_event_t **vm_event)
{
    vm_event_channels_t *impl = NULL;
    int rc, i;

    impl = (vm_event_channels_t *)calloc(1, sizeof(vm_event_channels_t));
    if ( impl == NULL )
        return -ENOMEM;

    rc = xc_monitor_ng_enable(xch, domain_id, &impl->fres, &impl->num_channels, (void**)&impl->slots);
    if ( rc )
    {
        ERROR("Failed to enable monitor");
        return rc;
    }

    impl->ports = calloc(impl->num_channels, sizeof(int));
    if ( impl->ports == NULL )
    {
        rc = -ENOMEM;
        goto err;
    }

    for ( i = 0; i < impl->num_channels; i++)
    {
        rc = xenevtchn_bind_interdomain(xce, domain_id, impl->slots[i].port);
        if (  rc < 0 )
        {
            ERROR("Failed to bind vm_event_slot port for vcpu %d", i);
            rc = -errno;
            goto err;
        }

        impl->ports[i] = rc;
    }

    *vm_event = (vm_event_t*) impl;
    return 0;

err:
    while ( --i >= 0 )
        xenevtchn_unbind(xce, impl->ports[i]);
    free(impl->ports);
    xc_monitor_ng_disable(xch, domain_id, &impl->fres);
    free(impl);
    return rc;
}

static int vcpu_id_by_port(vm_event_channels_t *impl, int port, int *vcpu_id)
{
    int i;

    for ( i = 0; i < impl->num_channels; i++ )
    {
        if ( port == impl->ports[i] )
        {
            *vcpu_id = i;
            return 0;
        }
    }

    return -EINVAL;
}

static int vm_event_channels_teardown(vm_event_t *vm_event)
{
    vm_event_channels_t *impl = to_channels(vm_event);
    int rc, i;

    if ( impl == NULL || impl->ports == NULL )
        return -EINVAL;

    for ( i = 0; i < impl->num_channels; i++ )
    {
        rc = xenevtchn_unbind(vm_event->xce, impl->ports[i]);
        if ( rc != 0 )
        {
            ERROR("Error unbinding event port");
            return rc;
        }
    }

    return xc_monitor_ng_disable(impl->vme.xch, impl->vme.domain_id, &impl->fres);
}

static bool vm_event_channels_get_request(vm_event_t *vm_event, vm_event_request_t *req, int *port)
{
    int vcpu_id;
    vm_event_channels_t *impl = to_channels(vm_event);

    if ( vcpu_id_by_port(impl, *port, &vcpu_id) != 0 )
        return false;

    if ( impl->slots[vcpu_id].state != STATE_VM_EVENT_SLOT_SUBMIT )
        return false;

    memcpy(req, &impl->slots[vcpu_id].u.req, sizeof(*req));

    return true;
}

static void vm_event_channels_put_response(vm_event_t *vm_event, vm_event_response_t *rsp, int port)
{
    int vcpu_id;
    vm_event_channels_t *impl = to_channels(vm_event);

    if ( vcpu_id_by_port(impl, port, &vcpu_id) != 0 )
        return;

    memcpy(&impl->slots[vcpu_id].u.rsp, rsp, sizeof(*rsp));
    impl->slots[vcpu_id].state = STATE_VM_EVENT_SLOT_FINISH;
}

static int vm_event_channels_notify_port(vm_event_t *vm_event, int port)
{
    return xenevtchn_notify(vm_event->xce, port);
}

vm_event_ops_t channel_ops = {
    .get_request = vm_event_channels_get_request,
    .put_response = vm_event_channels_put_response,
    .notify_port = vm_event_channels_notify_port,
    .init = vm_event_channels_init,
    .teardown = vm_event_channels_teardown,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
