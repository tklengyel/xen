/*
 * arch/arm/hvm.c
 *
 * Arch-specific hardware virtual machine abstractions.
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
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/guest_access.h>
#include <xen/sched.h>
#include <xen/monitor.h>

#include <xsm/xsm.h>

#include <public/xen.h>
#include <public/hvm/params.h>
#include <public/hvm/hvm_op.h>

#include <asm/hypercall.h>

#include <asm/altp2m.h>

static int do_altp2m_op(XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct xen_hvm_altp2m_op a;
    struct domain *d = NULL;
    uint64_t mode;
    int rc = 0;

    if ( copy_from_guest(&a, arg, 1) )
        return -EFAULT;

    if ( a.pad1 || a.pad2 ||
         (a.version != HVMOP_ALTP2M_INTERFACE_VERSION) ||
         (a.cmd < HVMOP_altp2m_get_domain_state) ||
         (a.cmd > HVMOP_altp2m_change_gfn) )
        return -EINVAL;

    d = (a.cmd != HVMOP_altp2m_vcpu_enable_notify) ?
        rcu_lock_domain_by_any_id(a.domain) : rcu_lock_current_domain();

    if ( d == NULL )
        return -ESRCH;

    /*
     * TODO: We prohibit concurrent access of the altp2m interface by locking
     * the entire domain. Determine which HVMOPs can be executed concurrently.
     */

    /* Prevent concurrent execution of the following HVMOPs. */
    domain_lock(d);

    if ( (a.cmd != HVMOP_altp2m_get_domain_state) &&
         (a.cmd != HVMOP_altp2m_set_domain_state) &&
         !altp2m_active(d) )
    {
        rc = -EOPNOTSUPP;
        goto out;
    }

    mode = d->arch.hvm_domain.params[HVM_PARAM_ALTP2M];

    if ( XEN_ALTP2M_disabled == mode )
    {
        rc = -EINVAL;
        goto out;
    }

    if ( (rc = xsm_hvm_altp2mhvm_op(XSM_OTHER, d, mode, a.cmd)) )
        goto out;

    switch ( a.cmd )
    {
    case HVMOP_altp2m_get_domain_state:
        rc = -EOPNOTSUPP;
        break;

    case HVMOP_altp2m_set_domain_state:
        rc = -EOPNOTSUPP;
        break;

    case HVMOP_altp2m_vcpu_enable_notify:
        rc = -EOPNOTSUPP;
        break;

    case HVMOP_altp2m_create_p2m:
        rc = -EOPNOTSUPP;
        break;

    case HVMOP_altp2m_destroy_p2m:
        rc = -EOPNOTSUPP;
        break;

    case HVMOP_altp2m_switch_p2m:
        rc = -EOPNOTSUPP;
        break;

    case HVMOP_altp2m_set_mem_access:
        rc = -EOPNOTSUPP;
        break;

    case HVMOP_altp2m_change_gfn:
        rc = -EOPNOTSUPP;
        break;
    }

out:
    domain_unlock(d);
    rcu_unlock_domain(d);

    return rc;
}

static int hvm_allow_set_param(struct domain *d, const struct xen_hvm_param *a)
{
    uint64_t value = d->arch.hvm_domain.params[a->index];
    int rc;

    rc = xsm_hvm_param(XSM_TARGET, d, HVMOP_set_param);
    if ( rc )
        return rc;

    switch ( a->index )
    {
    /* The following parameters should only be changed once. */
    case HVM_PARAM_ALTP2M:
        if ( value != 0 && a->value != value )
            rc = -EEXIST;
        break;
    default:
        break;
    }

    return rc;
}

static int hvm_allow_get_param(struct domain *d, const struct xen_hvm_param *a)
{
    int rc;

    rc = xsm_hvm_param(XSM_TARGET, d, HVMOP_get_param);
    if ( rc )
        return rc;

    switch ( a->index )
    {
        /* This switch statement can be used to control/limit guest access to
         * certain HVM params. */
    default:
        break;
    }

    return rc;
}

long do_hvm_op(unsigned long op, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    long rc = 0;

    switch ( op )
    {
    case HVMOP_set_param:
    case HVMOP_get_param:
    {
        struct xen_hvm_param a;
        struct domain *d;

        if ( copy_from_guest(&a, arg, 1) )
            return -EFAULT;

        if ( a.index >= HVM_NR_PARAMS )
            return -EINVAL;

        d = rcu_lock_domain_by_any_id(a.domid);
        if ( d == NULL )
            return -ESRCH;

        switch ( op )
        {
        case HVMOP_set_param:
            rc = hvm_allow_set_param(d, &a);
            if ( rc )
                break;

            d->arch.hvm_domain.params[a.index] = a.value;
            break;

        case HVMOP_get_param:
            rc = hvm_allow_get_param(d, &a);
            if ( rc )
                break;

            a.value = d->arch.hvm_domain.params[a.index];
            rc = copy_to_guest(arg, &a, 1) ? -EFAULT : 0;
            break;
        }

        rcu_unlock_domain(d);
        break;
    }

    case HVMOP_guest_request_vm_event:
        if ( guest_handle_is_null(arg) )
            monitor_guest_request();
        else
            rc = -EINVAL;
        break;

    case HVMOP_altp2m:
        rc = do_altp2m_op(arg);
        break;

    default:
    {
        gdprintk(XENLOG_DEBUG, "HVMOP op=%lu: not implemented\n", op);
        rc = -ENOSYS;
        break;
    }
    }

    return rc;
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
