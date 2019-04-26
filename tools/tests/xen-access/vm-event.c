/*
 * vm-event.c
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
#include "xen-access.h"

typedef struct vm_event_ring {
    vm_event_t vme;
    int port;
    vm_event_back_ring_t back_ring;
    uint32_t evtchn_port;
    void *ring_page;
} vm_event_ring_t;

#define to_ring(_vme) container_of((_vme), vm_event_ring_t, vme)

static int vm_event_ring_init(xc_interface *xch, xenevtchn_handle *xce,
                              domid_t domain_id, vm_event_ops_t *ops,
                              vm_event_t **vm_event)
{
    vm_event_ring_t *impl;
    int rc;

    impl = (vm_event_ring_t*) calloc (1, sizeof(vm_event_ring_t));
    if ( impl == NULL )
        return -ENOMEM;

    /* Enable mem_access */
    impl->ring_page = xc_monitor_enable(xch, domain_id, &impl->evtchn_port);
    if ( impl->ring_page == NULL )
    {
        switch ( errno )
        {
        case EBUSY:
            ERROR("xenaccess is (or was) active on this domain");
            break;
        case ENODEV:
            ERROR("EPT not supported for this guest");
            break;
        default:
            perror("Error enabling mem_access");
            break;
        }
        rc = -errno;
        goto err;
    }

    /* Bind event notification */
    rc = xenevtchn_bind_interdomain(xce, domain_id, impl->evtchn_port);
    if ( rc < 0 )
    {
        ERROR("Failed to bind event channel");
        munmap(impl->ring_page, XC_PAGE_SIZE);
        xc_monitor_disable(xch, domain_id);
        goto err;
    }

    impl->port = rc;

    /* Initialise ring */
    SHARED_RING_INIT((vm_event_sring_t *)impl->ring_page);
    BACK_RING_INIT(&impl->back_ring, (vm_event_sring_t *)impl->ring_page,
                   XC_PAGE_SIZE);

    *vm_event = (vm_event_t*) impl;
    return 0;

err:
    free(impl);
    return rc;
}

static int vm_event_ring_teardown(vm_event_t *vm_event)
{
    vm_event_ring_t *impl = to_ring(vm_event);
    int rc;

    if ( impl->ring_page != NULL )
        munmap(impl->ring_page, XC_PAGE_SIZE);

    /* Tear down domain xenaccess in Xen */
    rc = xc_monitor_disable(vm_event->xch, vm_event->domain_id);
    if ( rc != 0 )
    {
        ERROR("Error tearing down domain xenaccess in xen");
        return rc;
    }

    /* Unbind VIRQ */
    rc = xenevtchn_unbind(vm_event->xce, impl->port);
    if ( rc != 0 )
    {
        ERROR("Error unbinding event port");
        return rc;
    }

    return 0;
}

/*
 * Note that this function is not thread safe.
 */
static bool vm_event_ring_get_request(vm_event_t *vm_event, vm_event_request_t *req, int *port)
{
    vm_event_back_ring_t *back_ring;
    RING_IDX req_cons;
    vm_event_ring_t *impl = to_ring(vm_event);

    if ( !RING_HAS_UNCONSUMED_REQUESTS(&impl->back_ring) )
        return false;

    back_ring = &impl->back_ring;
    req_cons = back_ring->req_cons;

    /* Copy request */
    memcpy(req, RING_GET_REQUEST(back_ring, req_cons), sizeof(*req));
    req_cons++;

    /* Update ring */
    back_ring->req_cons = req_cons;
    back_ring->sring->req_event = req_cons + 1;

    *port = impl->port;

    return true;
}

/*
 * Note that this function is not thread safe.
 */
static void vm_event_ring_put_response(vm_event_t *vm_event, vm_event_response_t *rsp, int port)
{
    vm_event_back_ring_t *back_ring;
    RING_IDX rsp_prod;
    vm_event_ring_t *impl = to_ring(vm_event);

    back_ring = &impl->back_ring;
    rsp_prod = back_ring->rsp_prod_pvt;

    /* Copy response */
    memcpy(RING_GET_RESPONSE(back_ring, rsp_prod), rsp, sizeof(*rsp));
    rsp_prod++;

    /* Update ring */
    back_ring->rsp_prod_pvt = rsp_prod;
    RING_PUSH_RESPONSES(back_ring);
}

static int vm_event_ring_notify_port(vm_event_t *vm_event, int port)
{
    return xenevtchn_notify(vm_event->xce, port);
}

vm_event_ops_t ring_ops = {
    .get_request = vm_event_ring_get_request,
    .put_response = vm_event_ring_put_response,
    .notify_port = vm_event_ring_notify_port,
    .init = vm_event_ring_init,
    .teardown = vm_event_ring_teardown,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
