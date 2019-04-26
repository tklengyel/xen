/*
 * xen-access.h
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

#ifndef XEN_ACCESS_H
#define XEN_ACCESS_H

#include <xenctrl.h>
#include <xenevtchn.h>
#include <xen/vm_event.h>

#ifndef container_of
#define container_of(ptr, type, member) ({ \
                const typeof( ((type *)0)->member ) *__mptr = (ptr); \
                (type *)( (char *)__mptr - offsetof(type,member) );})
#endif /* container_of */

#define DPRINTF(a, b...) fprintf(stderr, a, ## b)
#define ERROR(a, b...) fprintf(stderr, a "\n", ## b)
#define PERROR(a, b...) fprintf(stderr, a ": %s\n", ## b, strerror(errno))

struct vm_event_ops;

typedef struct vm_event {
    xc_interface *xch;
    domid_t domain_id;
    xenevtchn_handle *xce;
    xen_pfn_t max_gpfn;
    struct vm_event_ops *ops;
} vm_event_t;

typedef struct vm_event_ops {
    int (*init)(xc_interface *, xenevtchn_handle *, domid_t,
                struct vm_event_ops *, vm_event_t **);
    int (*teardown)(vm_event_t *);
    bool (*get_request)(vm_event_t *, vm_event_request_t *, int *);
    void (*put_response)(vm_event_t *, vm_event_response_t *, int);
    int (*notify_port)(vm_event_t *, int port);
} vm_event_ops_t;

static inline bool get_request(vm_event_t *vm_event, vm_event_request_t *req,
                               int *port)
{
    return ( vm_event ) ? vm_event->ops->get_request(vm_event, req, port) :
                          false;
}

static inline void put_response(vm_event_t *vm_event, vm_event_response_t *rsp, int port)
{
    if (  vm_event )
        vm_event->ops->put_response(vm_event, rsp, port);
}

static inline int notify_port(vm_event_t *vm_event, int port)
{
    if ( !vm_event )
        return -EINVAL;

    return vm_event->ops->notify_port(vm_event, port);
}

#endif /* XEN_ACCESS_H */

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
