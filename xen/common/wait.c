/******************************************************************************
 * wait.c
 * 
 * Sleep in hypervisor context for some event to occur.
 * 
 * Copyright (c) 2010, Keir Fraser <keir@xen.org>
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
#include <xen/softirq.h>
#include <xen/wait.h>
#include <xen/errno.h>

struct waitqueue_vcpu {
    struct list_head list;
    struct vcpu *vcpu;
#ifdef CONFIG_X86
    /*
     * Xen/x86 does not have per-vcpu hypervisor stacks. So we must save the
     * hypervisor context before sleeping (descheduling), setjmp/longjmp-style.
     */
    void *esp;
    char *stack;
#endif
};

int init_waitqueue_vcpu(struct vcpu *v)
{
    struct waitqueue_vcpu *wqv;

    wqv = xzalloc(struct waitqueue_vcpu);
    if ( wqv == NULL )
        return -ENOMEM;

#ifdef CONFIG_X86
    wqv->stack = alloc_xenheap_page();
    if ( wqv->stack == NULL )
    {
        xfree(wqv);
        return -ENOMEM;
    }
#endif

    INIT_LIST_HEAD(&wqv->list);
    wqv->vcpu = v;

    v->waitqueue_vcpu = wqv;

    return 0;
}

void destroy_waitqueue_vcpu(struct vcpu *v)
{
    struct waitqueue_vcpu *wqv;

    wqv = v->waitqueue_vcpu;
    if ( wqv == NULL )
        return;

    BUG_ON(!list_empty(&wqv->list));
#ifdef CONFIG_X86
    free_xenheap_page(wqv->stack);
#endif
    xfree(wqv);

    v->waitqueue_vcpu = NULL;
}

void init_waitqueue_head(struct waitqueue_head *wq)
{
    spin_lock_init(&wq->lock);
    INIT_LIST_HEAD(&wq->list);
}

void destroy_waitqueue_head(struct waitqueue_head *wq)
{
    wake_up_all(wq);
}

void wake_up_nr(struct waitqueue_head *wq, unsigned int nr)
{
    struct waitqueue_vcpu *wqv;

    spin_lock(&wq->lock);

    while ( !list_empty(&wq->list) && nr-- )
    {
        wqv = list_entry(wq->list.next, struct waitqueue_vcpu, list);
        list_del_init(&wqv->list);
        vcpu_unpause(wqv->vcpu);
        put_domain(wqv->vcpu->domain);
    }

    spin_unlock(&wq->lock);
}

void wake_up_one(struct waitqueue_head *wq)
{
    wake_up_nr(wq, 1);
}

void wake_up_all(struct waitqueue_head *wq)
{
    wake_up_nr(wq, UINT_MAX);
}

#ifdef CONFIG_X86

static void __prepare_to_wait(struct waitqueue_vcpu *wqv)
{
    struct cpu_info *cpu_info = get_cpu_info();
    struct vcpu *curr = current;
    unsigned long dummy;

    ASSERT(wqv->esp == NULL);

    /* Save current VCPU affinity; force wakeup on *this* CPU only. */
    if ( vcpu_temporary_affinity(curr, smp_processor_id(), VCPU_AFFINITY_WAIT) )
    {
        gdprintk(XENLOG_ERR, "Unable to set vcpu affinity\n");
        domain_crash(curr->domain);

        for ( ; ; )
            do_softirq();
    }

    /*
     * Hand-rolled setjmp().
     *
     * __prepare_to_wait() is the leaf of a deep calltree.  Preserve the GPRs,
     * bounds check what we want to stash in wqv->stack, copy the active stack
     * (up to cpu_info) into wqv->stack, then return normally.  Our caller
     * will shortly schedule() and discard the current context.
     *
     * The copy out is performed with a rep movsb.  When
     * check_wakeup_from_wait() longjmp()'s back into us, %rsp is pre-adjusted
     * to be suitable and %rsi/%rdi are swapped, so the rep movsb instead
     * copies in from wqv->stack over the active stack.
     */
    asm volatile (
        "push %%rbx; push %%rbp; push %%r12;"
        "push %%r13; push %%r14; push %%r15;"

        "sub %%esp,%%ecx;"
        "cmp %[sz], %%ecx;"
        "ja .L_skip;"       /* Bail if >4k */
        "mov %%rsp,%%rsi;"

        /* check_wakeup_from_wait() longjmp()'s to this point. */
        ".L_wq_resume: rep movsb;"
        "mov %%rsp,%%rsi;"

        ".L_skip:"
        "pop %%r15; pop %%r14; pop %%r13;"
        "pop %%r12; pop %%rbp; pop %%rbx"
        : "=&S" (wqv->esp), "=&c" (dummy), "=&D" (dummy)
        : "0" (0), "1" (cpu_info), "2" (wqv->stack),
          [sz] "i" (PAGE_SIZE)
        : "memory", "rax", "rdx", "r8", "r9", "r10", "r11" );

    if ( likely(wqv->esp) )
        return;

        gdprintk(XENLOG_ERR, "Stack too large in %s\n", __func__);
        domain_crash(curr->domain);

        for ( ; ; )
            do_softirq();
}

static void __finish_wait(struct waitqueue_vcpu *wqv)
{
    wqv->esp = NULL;
    vcpu_temporary_affinity(current, NR_CPUS, VCPU_AFFINITY_WAIT);
}

void check_wakeup_from_wait(void)
{
    struct vcpu *curr = current;
    struct waitqueue_vcpu *wqv = curr->waitqueue_vcpu;

    ASSERT(list_empty(&wqv->list));

    if ( likely(wqv->esp == NULL) )
        return;

    /* Check if we are still pinned. */
    if ( unlikely(!(curr->affinity_broken & VCPU_AFFINITY_WAIT)) )
    {
        gdprintk(XENLOG_ERR, "vcpu affinity lost\n");
        domain_crash(curr->domain);

        /* Re-initiate scheduler and don't longjmp(). */
        raise_softirq(SCHEDULE_SOFTIRQ);
        for ( ; ; )
            do_softirq();
    }

    /*
     * We are about to jump into a deeper call tree.  In principle, this risks
     * executing more RET than CALL instructions, and underflowing the RSB.
     *
     * However, we are pinned to the same CPU as previously.  Therefore,
     * either:
     *
     *   1) We've scheduled another vCPU in the meantime, and the context
     *      switch path has (by default) issued IBPB which flushes the RSB, or
     *
     *   2) We're still in the same context.  Returning back to the deeper
     *      call tree is resuming the execution path we left, and remains
     *      balanced as far as that logic is concerned.
     *
     *      In fact, the path through the scheduler will execute more CALL
     *      than RET instructions, making the RSB unbalanced in the safe
     *      direction.
     *
     * Therefore, no actions are necessary here to maintain RSB safety.
     */

    /*
     * Hand-rolled longjmp().
     *
     * check_wakeup_from_wait() is always called with a shallow stack,
     * immediately after the vCPU has been rescheduled.
     *
     * Adjust %rsp to be the correct depth for the (deeper) stack we want to
     * restore, then prepare %rsi, %rdi and %rcx such that when we rejoin the
     * rep movs in __prepare_to_wait(), it copies from wqv->stack over the
     * active stack.
     *
     * All other GPRs are available for use; They're restored from the stack,
     * or explicitly clobbered.
     */
    asm volatile ( "mov %%rdi, %%rsp;"
                   "jmp .L_wq_resume"
                   :
                   : "S" (wqv->stack), "D" (wqv->esp),
                     "c" ((char *)get_cpu_info() - (char *)wqv->esp)
                   : "memory" );
    unreachable();
}

#else /* !CONFIG_X86 */

#define __prepare_to_wait(wqv) ((void)0)
#define __finish_wait(wqv) ((void)0)

#endif

void prepare_to_wait(struct waitqueue_head *wq)
{
    struct vcpu *curr = current;
    struct waitqueue_vcpu *wqv = curr->waitqueue_vcpu;

    ASSERT_NOT_IN_ATOMIC();
    __prepare_to_wait(wqv);

    ASSERT(list_empty(&wqv->list));
    spin_lock(&wq->lock);
    list_add_tail(&wqv->list, &wq->list);
    vcpu_pause_nosync(curr);
    get_knownalive_domain(curr->domain);
    spin_unlock(&wq->lock);
}

void finish_wait(struct waitqueue_head *wq)
{
    struct vcpu *curr = current;
    struct waitqueue_vcpu *wqv = curr->waitqueue_vcpu;

    __finish_wait(wqv);

    if ( list_empty(&wqv->list) )
        return;

    spin_lock(&wq->lock);
    if ( !list_empty(&wqv->list) )
    {
        list_del_init(&wqv->list);
        vcpu_unpause(curr);
        put_domain(curr->domain);
    }
    spin_unlock(&wq->lock);
}
