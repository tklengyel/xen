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

#include <xen/config.h>
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
#include <asm/hvm/hvm.h>

/* Xen command-line option enabling altp2m */
static bool_t __initdata opt_altp2m_enabled = 0;
boolean_param("altp2m", opt_altp2m_enabled);

struct hvm_function_table hvm_funcs __read_mostly = {
    .name = "ARM_HVM",
};

/* Initcall enabling hvm functionality. */
static int __init hvm_enable(void)
{
    if ( opt_altp2m_enabled )
        hvm_funcs.altp2m_supported = 1;
    else
        hvm_funcs.altp2m_supported = 0;

    return 0;
}
presmp_initcall(hvm_enable);

static int do_altp2m_op(XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct xen_hvm_altp2m_op a;
    struct domain *d = NULL;
    int rc = 0;

    if ( !hvm_altp2m_supported() )
        return -EOPNOTSUPP;

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

    if ( (a.cmd != HVMOP_altp2m_get_domain_state) &&
         (a.cmd != HVMOP_altp2m_set_domain_state) &&
         !d->arch.altp2m_active )
    {
        rc = -EOPNOTSUPP;
        goto out;
    }

    if ( (rc = xsm_hvm_altp2mhvm_op(XSM_TARGET, d)) )
        goto out;

    switch ( a.cmd )
    {
    case HVMOP_altp2m_get_domain_state:
        if ( !d->arch.hvm_domain.params[HVM_PARAM_ALTP2M] )
        {
            rc = -EINVAL;
            break;
        }

        a.u.domain_state.state = altp2m_active(d);
        rc = __copy_to_guest(arg, &a, 1) ? -EFAULT : 0;
        break;

    case HVMOP_altp2m_set_domain_state:
    {
        struct vcpu *v;
        bool_t ostate;

        if ( !d->arch.hvm_domain.params[HVM_PARAM_ALTP2M] )
        {
            rc = -EINVAL;
            break;
        }

        ostate = d->arch.altp2m_active;
        d->arch.altp2m_active = !!a.u.domain_state.state;

        /* If the alternate p2m state has changed, handle appropriately */
        if ( d->arch.altp2m_active != ostate &&
             (ostate || !(rc = p2m_init_altp2m_by_id(d, 0))) )
        {
            for_each_vcpu( d, v )
            {
                if ( !ostate )
                    altp2m_vcpu_initialise(v);
                else
                    altp2m_vcpu_destroy(v);
            }

            if ( ostate )
                p2m_flush_altp2m(d);
        }

        break;
    }

    case HVMOP_altp2m_vcpu_enable_notify:
        rc = -EOPNOTSUPP;
        break;

    case HVMOP_altp2m_create_p2m:
        if ( !(rc = p2m_init_next_altp2m(d, &a.u.view.view)) )
            rc = __copy_to_guest(arg, &a, 1) ? -EFAULT : 0;
        break;

    case HVMOP_altp2m_destroy_p2m:
        rc = p2m_destroy_altp2m_by_id(d, a.u.view.view);
        break;

    case HVMOP_altp2m_switch_p2m:
        rc = p2m_switch_domain_altp2m_by_id(d, a.u.view.view);
        break;

    case HVMOP_altp2m_set_mem_access:
        if ( a.u.set_mem_access.pad )
            rc = -EINVAL;
        else
            rc = p2m_set_mem_access(d, _gfn(a.u.set_mem_access.gfn), 1, 0, 0,
                                    a.u.set_mem_access.hvmmem_access,
                                    a.u.set_mem_access.view);
        break;

    case HVMOP_altp2m_change_gfn:
        if ( a.u.change_gfn.pad1 || a.u.change_gfn.pad2 )
            rc = -EINVAL;
        else
            rc = p2m_change_altp2m_gfn(d, a.u.change_gfn.view,
                                       _gfn(a.u.change_gfn.old_gfn),
                                       _gfn(a.u.change_gfn.new_gfn));
        break;
    }

 out:
    rcu_unlock_domain(d);

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

        rc = xsm_hvm_param(XSM_TARGET, d, op);
        if ( rc )
            goto param_fail;

        if ( op == HVMOP_set_param )
        {
            d->arch.hvm_domain.params[a.index] = a.value;
        }
        else
        {
            a.value = d->arch.hvm_domain.params[a.index];
            rc = copy_to_guest(arg, &a, 1) ? -EFAULT : 0;
        }

    param_fail:
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
