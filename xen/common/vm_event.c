/******************************************************************************
 * vm_event.c
 *
 * VM event support.
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Patrick Colp)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */


#include <xen/sched.h>
#include <xen/event.h>
#include <xen/wait.h>
#include <xen/vm_event.h>
#include <xen/mem_access.h>
#include <xen/vmap.h>
#include <asm/p2m.h>
#include <asm/monitor.h>
#include <asm/vm_event.h>
#include <xsm/xsm.h>

/* for public/io/ring.h macros */
#define xen_mb()   smp_mb()
#define xen_rmb()  smp_rmb()
#define xen_wmb()  smp_wmb()

static int vm_event_ring_pfn_param(uint32_t type)
{
    switch( type )
    {
#ifdef CONFIG_HAS_MEM_PAGING
    case XEN_VM_EVENT_TYPE_PAGING:
        return HVM_PARAM_PAGING_RING_PFN;
#endif
    case XEN_VM_EVENT_TYPE_MONITOR:
        return HVM_PARAM_MONITOR_RING_PFN;
#ifdef CONFIG_HAS_MEM_SHARING
    case XEN_VM_EVENT_TYPE_SHARING:
        return HVM_PARAM_SHARING_RING_PFN;
#endif
    };

    ASSERT_UNREACHABLE();
    return -1;
}

static int vm_event_pause_flag(uint32_t type)
{
    switch( type )
    {
#ifdef CONFIG_HAS_MEM_PAGING
    case XEN_VM_EVENT_TYPE_PAGING:
        return _VPF_mem_paging;
#endif
    case XEN_VM_EVENT_TYPE_MONITOR:
        return _VPF_mem_access;
#ifdef CONFIG_HAS_MEM_SHARING
    case XEN_VM_EVENT_TYPE_SHARING:
        return _VPF_mem_sharing;
#endif
    };

    ASSERT_UNREACHABLE();
    return -1;
}

#ifdef CONFIG_HAS_MEM_PAGING
static void mem_paging_notification(struct vcpu *v, unsigned int port);
#endif
static void monitor_notification(struct vcpu *v, unsigned int port);
#ifdef CONFIG_HAS_MEM_SHARING
static void mem_sharing_notification(struct vcpu *v, unsigned int port);
#endif

static xen_event_channel_notification_t vm_event_notification_fn(uint32_t type)
{
    switch( type )
    {
#ifdef CONFIG_HAS_MEM_PAGING
    case XEN_VM_EVENT_TYPE_PAGING:
        return mem_paging_notification;
#endif
    case XEN_VM_EVENT_TYPE_MONITOR:
        return monitor_notification;
#ifdef CONFIG_HAS_MEM_SHARING
    case XEN_VM_EVENT_TYPE_SHARING:
        return mem_sharing_notification;
#endif
    };

    ASSERT_UNREACHABLE();
    return NULL;
}

/*
 * VM event ring implementation;
 */

#define to_ring(_ved) container_of((_ved), struct vm_event_ring_domain, ved)

/* VM event ring implementation */
struct vm_event_ring_domain
{
    /* VM event domain */
    struct vm_event_domain ved;
    /* The ring has 64 entries */
    unsigned char foreign_producers;
    unsigned char target_producers;
    /* shared ring page */
    void *ring_page;
    struct page_info *ring_pg_struct;
    /* front-end ring */
    vm_event_front_ring_t front_ring;
    /* event channel port (vcpu0 only) */
    int xen_port;
    /* vm_event bit for vcpu->pause_flags */
    int pause_flag;
    /* list of vcpus waiting for room in the ring */
    struct waitqueue_head wq;
    /* the number of vCPUs blocked */
    unsigned int blocked;
    /* The last vcpu woken up */
    unsigned int last_vcpu_wake_up;
};

static const struct vm_event_ops vm_event_ring_ops;

static int vm_event_ring_enable(
    struct domain *d,
    struct xen_domctl_vm_event_op *vec,
    struct vm_event_domain **p_ved)
{
    int rc;
    int param = vm_event_ring_pfn_param(vec->type);
    int pause_flag = vm_event_pause_flag(vec->type);
    xen_event_channel_notification_t fn = vm_event_notification_fn(vec->type);
    unsigned long ring_gfn = d->arch.hvm.params[param];
    struct vm_event_ring_domain *impl;

    /*
     * Only one connected agent at a time.  If the helper crashed, the ring is
     * in an undefined state, and the guest is most likely unrecoverable.
     */
    if ( *p_ved != NULL )
        return -EBUSY;

    /* No chosen ring GFN?  Nothing we can do. */
    if ( ring_gfn == 0 )
        return -EOPNOTSUPP;

    impl = xzalloc(struct vm_event_ring_domain);
    if ( !impl )
        return -ENOMEM;

    /* Trivial setup. */
    spin_lock_init(&impl->ved.lock);
    init_waitqueue_head(&impl->wq);
    impl->ved.d = d;
    impl->ved.ops = &vm_event_ring_ops;
    impl->pause_flag = pause_flag;

    rc = vm_event_init_domain(d);
    if ( rc < 0 )
        goto err;

    rc = prepare_ring_for_helper(d, ring_gfn, &impl->ring_pg_struct,
                                 &impl->ring_page);
    if ( rc < 0 )
        goto err;

    FRONT_RING_INIT(&impl->front_ring,
                    (vm_event_sring_t *)impl->ring_page,
                    PAGE_SIZE);

    rc = alloc_unbound_xen_event_channel(d, 0, current->domain->domain_id, fn);
    if ( rc < 0 )
        goto err;

    impl->xen_port = vec->u.enable.port = rc;

    /* Success.  Fill in the domain's appropriate ved. */
    *p_ved = &impl->ved;

    return 0;

 err:
    destroy_ring_for_helper(&impl->ring_page, impl->ring_pg_struct);
    xfree(impl);

    return rc;
}

static unsigned int vm_event_ring_available(struct vm_event_ring_domain *impl)
{
    int avail_req = RING_FREE_REQUESTS(&impl->front_ring);

    avail_req -= impl->target_producers;
    avail_req -= impl->foreign_producers;

    BUG_ON(avail_req < 0);

    return avail_req;
}

/*
 * vm_event_ring_wake_blocked() will wakeup vcpus waiting for room in the
 * ring. These vCPUs were paused on their way out after placing an event,
 * but need to be resumed where the ring is capable of processing at least
 * one event from them.
 */
static void vm_event_ring_wake_blocked(struct vm_event_ring_domain *impl)
{
    struct vcpu *v;
    unsigned int i, j, k, avail_req = vm_event_ring_available(impl);
    struct domain *d = impl->ved.d;

    if ( avail_req == 0 || impl->blocked == 0 )
        return;

    /* We remember which vcpu last woke up to avoid scanning always linearly
     * from zero and starving higher-numbered vcpus under high load */
    for ( i = impl->last_vcpu_wake_up + 1, j = 0; j < d->max_vcpus; i++, j++ )
    {
        k = i % d->max_vcpus;
        v = d->vcpu[k];
        if ( !v )
            continue;

        if ( !impl->blocked || avail_req == 0 )
            break;

        if ( test_and_clear_bit(impl->pause_flag, &v->pause_flags) )
        {
            vcpu_unpause(v);
            avail_req--;
            impl->blocked--;
            impl->last_vcpu_wake_up = k;
        }
    }
}

/*
 * In the event that a vCPU attempted to place an event in the ring and
 * was unable to do so, it is queued on a wait queue.  These are woken as
 * needed, and take precedence over the blocked vCPUs.
 */
static void vm_event_ring_wake_queued(struct vm_event_ring_domain *impl)
{
    unsigned int avail_req = vm_event_ring_available(impl);

    if ( avail_req > 0 )
        wake_up_nr(&impl->wq, avail_req);
}

/*
 * vm_event_ring_wake() will wakeup all vcpus waiting for the ring to
 * become available.  If we have queued vCPUs, they get top priority. We
 * are guaranteed that they will go through code paths that will eventually
 * call vm_event_ring_wake() again, ensuring that any blocked vCPUs will get
 * unpaused once all the queued vCPUs have made it through.
 */
static void vm_event_ring_wake(struct vm_event_ring_domain *impl)
{
    if ( !list_empty(&impl->wq.list) )
        vm_event_ring_wake_queued(impl);
    else
        vm_event_ring_wake_blocked(impl);
}

static int vm_event_ring_disable(struct vm_event_domain **p_ved)
{
    struct vcpu *v;
    struct domain *d = (*p_ved)->d;
    struct vm_event_ring_domain *impl = to_ring(*p_ved);

    spin_lock(&impl->ved.lock);

    if ( !list_empty(&impl->wq.list) )
    {
        spin_unlock(&impl->ved.lock);
        return -EBUSY;
    }

    /* Free domU's event channel and leave the other one unbound */
    free_xen_event_channel(d, impl->xen_port);

    /* Unblock all vCPUs */
    for_each_vcpu ( d, v )
    {
        if ( test_and_clear_bit(impl->pause_flag, &v->pause_flags) )
        {
            vcpu_unpause(v);
            impl->blocked--;
        }
    }

    destroy_ring_for_helper(&impl->ring_page, impl->ring_pg_struct);

    vm_event_cleanup_domain(d);

    spin_unlock(&impl->ved.lock);

    xfree(impl);
    *p_ved = NULL;

    return 0;
}

static void vm_event_ring_release_slot(struct vm_event_ring_domain *impl)
{
    /* Update the accounting */
    if ( current->domain == impl->ved.d )
        impl->target_producers--;
    else
        impl->foreign_producers--;

    /* Kick any waiters */
    vm_event_ring_wake(impl);
}

/*
 * vm_event_ring_mark_and_pause() tags vcpu and put it to sleep.
 * The vcpu will resume execution in vm_event_ring_wake_blocked().
 */
static void vm_event_ring_mark_and_pause(struct vcpu *v,
                                         struct vm_event_ring_domain *impl)
{
    if ( !test_and_set_bit(impl->pause_flag, &v->pause_flags) )
    {
        vcpu_pause_nosync(v);
        impl->blocked++;
    }
}

/*
 * This must be preceded by a call to claim_slot(), and is guaranteed to
 * succeed.  As a side-effect however, the vCPU may be paused if the ring is
 * overly full and its continued execution would cause stalling and excessive
 * waiting.  The vCPU will be automatically unpaused when the ring clears.
 */
static void vm_event_ring_put_request(struct vm_event_domain *ved,
                                      vm_event_request_t *req)
{
    vm_event_front_ring_t *front_ring;
    int free_req;
    unsigned int avail_req;
    RING_IDX req_prod;
    struct vcpu *curr = current;
    struct vm_event_ring_domain *impl = to_ring(ved);

    if ( curr->domain != ved->d )
    {
        req->flags |= VM_EVENT_FLAG_FOREIGN;

        if ( !(req->flags & VM_EVENT_FLAG_VCPU_PAUSED) )
            gdprintk(XENLOG_WARNING, "d%dv%d was not paused.\n",
                     ved->d->domain_id, req->vcpu_id);
    }

    req->version = VM_EVENT_INTERFACE_VERSION;

    spin_lock(&impl->ved.lock);

    /* Due to the reservations, this step must succeed. */
    front_ring = &impl->front_ring;
    free_req = RING_FREE_REQUESTS(front_ring);
    ASSERT(free_req > 0);

    /* Copy request */
    req_prod = front_ring->req_prod_pvt;
    memcpy(RING_GET_REQUEST(front_ring, req_prod), req, sizeof(*req));
    req_prod++;

    /* Update ring */
    front_ring->req_prod_pvt = req_prod;
    RING_PUSH_REQUESTS(front_ring);

    /* We've actually *used* our reservation, so release the slot. */
    vm_event_ring_release_slot(impl);

    /* Give this vCPU a black eye if necessary, on the way out.
     * See the comments above wake_blocked() for more information
     * on how this mechanism works to avoid waiting. */
    avail_req = vm_event_ring_available(impl);
    if( curr->domain == ved->d && avail_req < ved->d->max_vcpus &&
        !atomic_read(&curr->vm_event_pause_count) )
        vm_event_ring_mark_and_pause(curr, impl);

    spin_unlock(&impl->ved.lock);

    notify_via_xen_event_channel(ved->d, impl->xen_port);
}

static int vm_event_ring_get_response(struct vm_event_ring_domain *impl,
                                      vm_event_response_t *rsp)
{
    vm_event_front_ring_t *front_ring;
    RING_IDX rsp_cons;
    int rc = 0;

    spin_lock(&impl->ved.lock);

    front_ring = &impl->front_ring;
    rsp_cons = front_ring->rsp_cons;

    if ( !RING_HAS_UNCONSUMED_RESPONSES(front_ring) )
        goto out;

    /* Copy response */
    memcpy(rsp, RING_GET_RESPONSE(front_ring, rsp_cons), sizeof(*rsp));
    rsp_cons++;

    /* Update ring */
    front_ring->rsp_cons = rsp_cons;
    front_ring->sring->rsp_event = rsp_cons + 1;

    /* Kick any waiters -- since we've just consumed an event,
     * there may be additional space available in the ring. */
    vm_event_ring_wake(impl);

    rc = 1;

 out:
    spin_unlock(&impl->ved.lock);

    return rc;
}

static void vm_event_handle_response(struct domain *d, struct vcpu *v,
                                     vm_event_response_t *rsp)
{
    /* Check flags which apply only when the vCPU is paused */
    if ( atomic_read(&v->vm_event_pause_count) )
    {
#ifdef CONFIG_HAS_MEM_PAGING
        if ( rsp->reason == VM_EVENT_REASON_MEM_PAGING )
            p2m_mem_paging_resume(d, rsp);
#endif

        /*
         * Check emulation flags in the arch-specific handler only, as it
         * has to set arch-specific flags when supported, and to avoid
         * bitmask overhead when it isn't supported.
         */
        vm_event_emulate_check(v, rsp);

        /*
         * Check in arch-specific handler to avoid bitmask overhead when
         * not supported.
         */
        vm_event_register_write_resume(v, rsp);

        /*
         * Check in arch-specific handler to avoid bitmask overhead when
         * not supported.
         */
        vm_event_toggle_singlestep(d, v, rsp);

        /* Check for altp2m switch */
        if ( rsp->flags & VM_EVENT_FLAG_ALTERNATE_P2M )
            p2m_altp2m_check(v, rsp->altp2m_idx);

        if ( rsp->flags & VM_EVENT_FLAG_SET_REGISTERS )
            vm_event_set_registers(v, rsp);

        if ( rsp->flags & VM_EVENT_FLAG_GET_NEXT_INTERRUPT )
            vm_event_monitor_next_interrupt(v);

        if ( rsp->flags & VM_EVENT_FLAG_VCPU_PAUSED )
            vm_event_vcpu_unpause(v);
    }
}

/*
 * Pull all responses from the given ring and unpause the corresponding vCPU
 * if required. Based on the response type, here we can also call custom
 * handlers.
 *
 * Note: responses are handled the same way regardless of which ring they
 * arrive on.
 */
static int vm_event_ring_resume(struct vm_event_domain *ved, struct vcpu *v)
{
    vm_event_response_t rsp;
    struct vm_event_ring_domain *impl = to_ring(ved);

    /*
     * vm_event_ring_resume() runs in either XEN_VM_EVENT_* domctls, or
     * EVTCHN_send context from the introspection consumer. Both contexts
     * are guaranteed not to be the subject of vm_event responses.
     * While we could ASSERT(v != current) for each VCPU in d in the loop
     * below, this covers the case where we would need to iterate over all
     * of them more succintly.
     */
    ASSERT(ved->d != current->domain);

    /* Pull all responses off the ring. */
    while ( vm_event_ring_get_response(impl, &rsp) )
    {
        struct vcpu *v;

        if ( rsp.version != VM_EVENT_INTERFACE_VERSION )
        {
            printk(XENLOG_G_WARNING "vm_event interface version mismatch\n");
            continue;
        }

        /* Validate the vcpu_id in the response. */
        v = domain_vcpu(ved->d, rsp.vcpu_id);
        if ( !v )
            continue;

        /*
         * In some cases the response type needs extra handling, so here
         * we call the appropriate handlers.
         */
        vm_event_handle_response(ved->d, v, &rsp);
    }

    return 0;
}

static void vm_event_ring_cancel_slot(struct vm_event_domain *ved)
{
    spin_lock(&ved->lock);
    vm_event_ring_release_slot(to_ring(ved));
    spin_unlock(&ved->lock);
}

static int vm_event_ring_grab_slot(struct vm_event_ring_domain *impl, int foreign)
{
    unsigned int avail_req;
    int rc;

    if ( !impl->ring_page )
        return -EOPNOTSUPP;

    spin_lock(&impl->ved.lock);

    avail_req = vm_event_ring_available(impl);

    rc = -EBUSY;
    if ( avail_req == 0 )
        goto out;

    if ( !foreign )
        impl->target_producers++;
    else
        impl->foreign_producers++;

    rc = 0;

 out:
    spin_unlock(&impl->ved.lock);

    return rc;
}

/* Simple try_grab wrapper for use in the wait_event() macro. */
static int vm_event_ring_wait_try_grab(struct vm_event_ring_domain *impl, int *rc)
{
    *rc = vm_event_ring_grab_slot(impl, 0);

    return *rc;
}

/* Call vm_event_ring_grab_slot() until the ring doesn't exist, or is available. */
static int vm_event_ring_wait_slot(struct vm_event_ring_domain *impl)
{
    int rc = -EBUSY;

    wait_event(impl->wq, vm_event_ring_wait_try_grab(impl, &rc) != -EBUSY);

    return rc;
}

static bool vm_event_ring_check(struct vm_event_domain *ved)
{
    return to_ring(ved)->ring_page != NULL;
}

/*
 * Determines whether or not the current vCPU belongs to the target domain,
 * and calls the appropriate wait function.  If it is a guest vCPU, then we
 * use vm_event_ring_wait_slot() to reserve a slot.  As long as there is a ring,
 * this function will always return 0 for a guest.  For a non-guest, we check
 * for space and return -EBUSY if the ring is not available.
 *
 * Return codes: -EOPNOTSUPP: the ring is not yet configured
 *               -EBUSY: the ring is busy
 *               0: a spot has been reserved
 *
 */
static int vm_event_ring_claim_slot(struct vm_event_domain *ved, bool allow_sleep)
{
    if ( (current->domain == ved->d) && allow_sleep )
        return vm_event_ring_wait_slot(to_ring(ved));
    else
        return vm_event_ring_grab_slot(to_ring(ved), current->domain != ved->d);
}

static void vm_event_ring_cleanup(struct vm_event_domain *ved)
{
    struct vm_event_ring_domain *impl = to_ring(ved);
    /* Destroying the wait queue head means waking up all
     * queued vcpus. This will drain the list, allowing
     * the disable routine to complete. It will also drop
     * all domain refs the wait-queued vcpus are holding.
     * Finally, because this code path involves previously
     * pausing the domain (domain_kill), unpausing the
     * vcpus causes no harm. */
    destroy_waitqueue_head(&impl->wq);
}

/*
 * VM event NG (new generation)
 */
#define to_channels(_ved) container_of((_ved), \
                                        struct vm_event_channels_domain, ved)

struct vm_event_channels_domain
{
    /* VM event domain */
    struct vm_event_domain ved;
    /* shared channels buffer */
    struct vm_event_slot *slots;
    /* the buffer size (number of frames) */
    unsigned int nr_frames;
    /* buffer's mnf list */
    mfn_t mfn[0];
};

static const struct vm_event_ops vm_event_channels_ops;

static void vm_event_channels_free_buffer(struct vm_event_channels_domain *impl)
{
    int i;

    vunmap(impl->slots);
    impl->slots = NULL;

    for ( i = 0; i < impl->nr_frames; i++ )
        free_domheap_page(mfn_to_page(impl->mfn[i]));
}

static int vm_event_channels_alloc_buffer(struct vm_event_channels_domain *impl)
{
    int i = 0;

    impl->slots = vzalloc(impl->nr_frames * PAGE_SIZE);
    if ( !impl->slots )
        return -ENOMEM;

    for ( i = 0; i < impl->nr_frames; i++ )
        impl->mfn[i] = vmap_to_mfn(impl->slots + i * PAGE_SIZE);

    for ( i = 0; i < impl->nr_frames; i++ )
        share_xen_page_with_guest(mfn_to_page(impl->mfn[i]), current->domain,
                                  SHARE_rw);

    return 0;
}

static int vm_event_channels_enable(
    struct domain *d,
    struct xen_domctl_vm_event_op *vec,
    struct vm_event_domain **p_ved)
{
    int rc, i = 0;
    xen_event_channel_notification_t fn = vm_event_notification_fn(vec->type);
    unsigned int nr_frames = PFN_UP(d->max_vcpus * sizeof(struct vm_event_slot));
    struct vm_event_channels_domain *impl;

    if ( *p_ved )
        return -EBUSY;

    impl = _xzalloc(sizeof(struct vm_event_channels_domain) +
                           nr_frames * sizeof(mfn_t),
                    __alignof__(struct vm_event_channels_domain));
    if ( unlikely(!impl) )
        return -ENOMEM;

    spin_lock_init(&impl->ved.lock);

    impl->nr_frames = nr_frames;
    impl->ved.d = d;
    impl->ved.ops = &vm_event_channels_ops;

    rc = vm_event_init_domain(d);
    if ( rc < 0 )
        goto err;

    rc = vm_event_channels_alloc_buffer(impl);
    if ( rc )
        goto err;

    for ( i = 0; i < d->max_vcpus; i++ )
    {
        rc = alloc_unbound_xen_event_channel(d, i, current->domain->domain_id, fn);
        if ( rc < 0 )
            goto err;

        impl->slots[i].port = rc;
        impl->slots[i].state = STATE_VM_EVENT_SLOT_IDLE;
    }

    *p_ved = &impl->ved;

    return 0;

err:
    while ( --i >= 0 )
        evtchn_close(d, impl->slots[i].port, 0);
    xfree(impl);

    return rc;
}

static int vm_event_channels_disable(struct vm_event_domain **p_ved)
{
    struct vcpu *v;
    struct domain *d = (*p_ved)->d;
    struct vm_event_channels_domain *impl = to_channels(*p_ved);
    int i;

    spin_lock(&impl->ved.lock);

    for_each_vcpu( impl->ved.d, v )
    {
        if ( atomic_read(&v->vm_event_pause_count) )
            vm_event_vcpu_unpause(v);
    }

    for ( i = 0; i < impl->ved.d->max_vcpus; i++ )
        evtchn_close(impl->ved.d, impl->slots[i].port, 0);

    vm_event_channels_free_buffer(impl);

    vm_event_cleanup_domain(d);

    spin_unlock(&impl->ved.lock);

    xfree(impl);
    *p_ved = NULL;

    return 0;
}

static bool vm_event_channels_check(struct vm_event_domain *ved)
{
    return to_channels(ved)->slots != NULL;
}

static void vm_event_channels_cleanup(struct vm_event_domain *ved)
{
}

static int vm_event_channels_claim_slot(struct vm_event_domain *ved,
                                        bool allow_sleep)
{
    return 0;
}

static void vm_event_channels_cancel_slot(struct vm_event_domain *ved)
{
}

static void vm_event_channels_put_request(struct vm_event_domain *ved,
                                          vm_event_request_t *req)
{
    struct vm_event_channels_domain *impl = to_channels(ved);
    struct vm_event_slot *slot;

    ASSERT( req->vcpu_id >= 0 && req->vcpu_id < ved->d->max_vcpus );

    slot = &impl->slots[req->vcpu_id];

    if ( current->domain != ved->d )
    {
        req->flags |= VM_EVENT_FLAG_FOREIGN;
#ifndef NDEBUG
        if ( !(req->flags & VM_EVENT_FLAG_VCPU_PAUSED) )
            gdprintk(XENLOG_G_WARNING, "d%dv%d was not paused.\n",
                     ved->d->domain_id, req->vcpu_id);
#endif
    }

    req->version = VM_EVENT_INTERFACE_VERSION;

    spin_lock(&impl->ved.lock);
    if ( slot->state != STATE_VM_EVENT_SLOT_IDLE )
    {
        gdprintk(XENLOG_G_WARNING, "The VM event slot for d%dv%d is not IDLE.\n",
                 impl->ved.d->domain_id, req->vcpu_id);
        spin_unlock(&impl->ved.lock);
        return;
    }

    slot->u.req = *req;
    slot->state = STATE_VM_EVENT_SLOT_SUBMIT;
    spin_unlock(&impl->ved.lock);
    notify_via_xen_event_channel(impl->ved.d, slot->port);
}

static int vm_event_channels_get_response(struct vm_event_channels_domain *impl,
                                          struct vcpu *v, vm_event_response_t *rsp)
{
    struct vm_event_slot *slot = &impl->slots[v->vcpu_id];
    int rc = 0;

    ASSERT( slot != NULL );
    spin_lock(&impl->ved.lock);

    if ( slot->state != STATE_VM_EVENT_SLOT_FINISH )
    {
        gdprintk(XENLOG_G_WARNING, "The VM event slot state for d%dv%d is invalid.\n",
                 impl->ved.d->domain_id, v->vcpu_id);
        rc = -1;
        goto out;
    }

    *rsp = slot->u.rsp;
    slot->state = STATE_VM_EVENT_SLOT_IDLE;

out:
    spin_unlock(&impl->ved.lock);

    return rc;
}

static int vm_event_channels_resume(struct vm_event_domain *ved, struct vcpu *v)
{
    vm_event_response_t rsp;
    struct vm_event_channels_domain *impl = to_channels(ved);

    ASSERT(ved->d != current->domain);

    if ( vm_event_channels_get_response(impl, v, &rsp) ||
         rsp.version != VM_EVENT_INTERFACE_VERSION ||
         rsp.vcpu_id != v->vcpu_id )
        return -1;

    vm_event_handle_response(ved->d, v, &rsp);

    return 0;
}

int vm_event_ng_get_frames(struct domain *d, unsigned int id,
                           unsigned long frame, unsigned int nr_frames,
                           xen_pfn_t mfn_list[])
{
    struct vm_event_domain *ved;
    int i;

    switch (id )
    {
    case XEN_VM_EVENT_TYPE_MONITOR:
        ved = d->vm_event_monitor;
        break;

    default:
        return -ENOSYS;
    }

    if ( !vm_event_check(ved) )
        return -EINVAL;

    if ( frame != 0 || nr_frames != to_channels(ved)->nr_frames )
        return -EINVAL;

    spin_lock(&ved->lock);

    for ( i = 0; i < to_channels(ved)->nr_frames; i++ )
        mfn_list[i] = mfn_x(to_channels(ved)->mfn[i]);

    spin_unlock(&ved->lock);

    return 0;
}

/*
 * vm_event implementation agnostic functions
 */

/* Clean up on domain destruction */
void vm_event_cleanup(struct domain *d)
{
#ifdef CONFIG_HAS_MEM_PAGING
    if ( vm_event_check(d->vm_event_paging) )
    {
        d->vm_event_paging->ops->cleanup(d->vm_event_paging);
        d->vm_event_paging->ops->disable(&d->vm_event_paging);
    }
#endif

    if ( vm_event_check(d->vm_event_monitor) )
    {
        d->vm_event_monitor->ops->cleanup(d->vm_event_monitor);
        d->vm_event_monitor->ops->disable(&d->vm_event_monitor);
    }

#ifdef CONFIG_HAS_MEM_SHARING
    if ( vm_event_check(d->vm_event_share) )
    {
        d->vm_event_share->ops->cleanup(d->vm_event_share);
        d->vm_event_share->ops->disable(&d->vm_event_share);
    }
#endif
}

static int vm_event_enable(struct domain *d,
                           struct xen_domctl_vm_event_op *vec,
                           struct vm_event_domain **p_ved)
{
    return ( vec->flags & XEN_VM_EVENT_FLAGS_NG_OP ) ?
        vm_event_channels_enable(d, vec, p_ved) :
        vm_event_ring_enable(d, vec, p_ved);
}

static int vm_event_resume(struct vm_event_domain *ved, struct vcpu *v)
{
    if ( !vm_event_check(ved) )
         return -ENODEV;

    if ( !v )
        return -EINVAL;

    return ved->ops->resume(ved, v);
}

#ifdef CONFIG_HAS_MEM_PAGING
/* Registered with Xen-bound event channel for incoming notifications. */
static void mem_paging_notification(struct vcpu *v, unsigned int port)
{
    vm_event_resume(v->domain->vm_event_paging, v);
}
#endif

/* Registered with Xen-bound event channel for incoming notifications. */
static void monitor_notification(struct vcpu *v, unsigned int port)
{
    vm_event_resume(v->domain->vm_event_monitor, v);
}

#ifdef CONFIG_HAS_MEM_SHARING
/* Registered with Xen-bound event channel for incoming notifications. */
static void mem_sharing_notification(struct vcpu *v, unsigned int port)
{
    vm_event_resume(v->domain->vm_event_share, v);
}
#endif

/*
 * vm_event domctl interface
 */

int vm_event_domctl(struct domain *d, struct xen_domctl_vm_event_op *vec)
{
    int rc;

    if ( vec->op == XEN_VM_EVENT_GET_VERSION )
    {
        vec->u.version = VM_EVENT_INTERFACE_VERSION;
        return 0;
    }

    rc = xsm_vm_event_control(XSM_PRIV, d, vec->type, vec->op);
    if ( rc )
        return rc;

    if ( unlikely(d == current->domain) ) /* no domain_pause() */
    {
        gdprintk(XENLOG_INFO, "Tried to do a memory event op on itself.\n");
        return -EINVAL;
    }

    if ( unlikely(d->is_dying) )
    {
        gdprintk(XENLOG_INFO, "Ignoring memory event op on dying domain %u\n",
                 d->domain_id);
        return 0;
    }

    if ( unlikely(d->vcpu == NULL) || unlikely(d->vcpu[0] == NULL) )
    {
        gdprintk(XENLOG_INFO,
                 "Memory event op on a domain (%u) with no vcpus\n",
                 d->domain_id);
        return -EINVAL;
    }

    rc = -ENOSYS;

    switch ( vec->type )
    {
#ifdef CONFIG_HAS_MEM_PAGING
    case XEN_VM_EVENT_TYPE_PAGING:
    {
        rc = -EINVAL;

        /*
         * The NG interface is only supported by XEN_VM_EVENT_TYPE_MONITOR
         * for now.
         */
        if ( vec->flags & XEN_VM_EVENT_FLAGS_NG_OP )
            break;

        switch( vec->op )
        {
        case XEN_VM_EVENT_ENABLE:
        {
            rc = -EOPNOTSUPP;
            /* hvm fixme: p2m_is_foreign types need addressing */
            if ( is_hvm_domain(hardware_domain) )
                break;

            rc = -ENODEV;
            /* Only HAP is supported */
            if ( !hap_enabled(d) )
                break;

            /* No paging if iommu is used */
            rc = -EMLINK;
            if ( unlikely(has_iommu_pt(d)) )
                break;

            rc = -EXDEV;
            /* Disallow paging in a PoD guest */
            if ( p2m_pod_entry_count(p2m_get_hostp2m(d)) )
                break;

            /* domain_pause() not required here, see XSA-99 */
            rc = vm_event_enable(d, vec, &d->vm_event_paging);
        }
        break;

        case XEN_VM_EVENT_DISABLE:
            if ( !vm_event_check(d->vm_event_paging) )
                break;
            domain_pause(d);
            rc = d->vm_event_paging->ops->disable(&d->vm_event_paging);
            domain_unpause(d);
            break;

        case XEN_VM_EVENT_RESUME:
            rc = vm_event_resume(d->vm_event_paging,
                                 domain_vcpu(d, vec->u.resume.vcpu_id));
            break;

        default:
            rc = -ENOSYS;
            break;
        }
    }
    break;
#endif

    case XEN_VM_EVENT_TYPE_MONITOR:
    {
        rc = -EINVAL;

        switch( vec->op )
        {
        case XEN_VM_EVENT_ENABLE:
            /* domain_pause() not required here, see XSA-99 */
            rc = arch_monitor_init_domain(d);
            if ( rc )
                break;

            rc = vm_event_enable(d, vec, &d->vm_event_monitor);

            break;

        case XEN_VM_EVENT_DISABLE:
            if ( !vm_event_check(d->vm_event_monitor) )
                break;
            domain_pause(d);
            rc = d->vm_event_monitor->ops->disable(&d->vm_event_monitor);
            arch_monitor_cleanup_domain(d);
            domain_unpause(d);
            break;

        case XEN_VM_EVENT_RESUME:
            rc = vm_event_resume(d->vm_event_monitor,
                                 domain_vcpu(d, vec->u.resume.vcpu_id));
            break;

        default:
            rc = -ENOSYS;
            break;
        }
    }
    break;

#ifdef CONFIG_HAS_MEM_SHARING
    case XEN_VM_EVENT_TYPE_SHARING:
    {
        rc = -EINVAL;

        /*
         * The NG interface is only supported by XEN_VM_EVENT_TYPE_MONITOR
         * for now.
         */
        if ( vec->flags & XEN_VM_EVENT_FLAGS_NG_OP )
            break;

        switch( vec->op )
        {
        case XEN_VM_EVENT_ENABLE:
            rc = -EOPNOTSUPP;
            /* hvm fixme: p2m_is_foreign types need addressing */
            if ( is_hvm_domain(hardware_domain) )
                break;

            rc = -ENODEV;
            /* Only HAP is supported */
            if ( !hap_enabled(d) )
                break;

            /* domain_pause() not required here, see XSA-99 */
            rc = vm_event_enable(d, vec, &d->vm_event_share);
            break;

        case XEN_VM_EVENT_DISABLE:
            if ( !vm_event_check(d->vm_event_share) )
                break;
            domain_pause(d);
            rc = d->vm_event_share->ops->disable(&d->vm_event_share);
            domain_unpause(d);
            break;

        case XEN_VM_EVENT_RESUME:
            rc = vm_event_resume(d->vm_event_share,
                                 domain_vcpu(d, vec->u.resume.vcpu_id));
            break;

        default:
            rc = -ENOSYS;
            break;
        }
    }
    break;
#endif

    default:
        rc = -ENOSYS;
    }

    return rc;
}

void vm_event_vcpu_pause(struct vcpu *v)
{
    ASSERT(v == current);

    atomic_inc(&v->vm_event_pause_count);
    vcpu_pause_nosync(v);
}

void vm_event_vcpu_unpause(struct vcpu *v)
{
    int old, new, prev = v->vm_event_pause_count.counter;

    /*
     * All unpause requests as a result of toolstack responses.
     * Prevent underflow of the vcpu pause count.
     */
    do
    {
        old = prev;
        new = old - 1;

        if ( new < 0 )
        {
            printk(XENLOG_G_WARNING
                   "%pv vm_event: Too many unpause attempts\n", v);
            return;
        }

        prev = cmpxchg(&v->vm_event_pause_count.counter, old, new);
    } while ( prev != old );

    vcpu_unpause(v);
}

static const struct vm_event_ops vm_event_ring_ops = {
    .check = vm_event_ring_check,
    .cleanup = vm_event_ring_cleanup,
    .claim_slot = vm_event_ring_claim_slot,
    .cancel_slot = vm_event_ring_cancel_slot,
    .disable = vm_event_ring_disable,
    .put_request = vm_event_ring_put_request,
    .resume = vm_event_ring_resume,
};

static const struct vm_event_ops vm_event_channels_ops = {
    .check = vm_event_channels_check,
    .cleanup = vm_event_channels_cleanup,
    .claim_slot = vm_event_channels_claim_slot,
    .cancel_slot = vm_event_channels_cancel_slot,
    .disable = vm_event_channels_disable,
    .put_request = vm_event_channels_put_request,
    .resume = vm_event_channels_resume,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
