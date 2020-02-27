#include "xc_private.h"


static int do_clone_op(xc_interface *xch, int cmd, void *op, size_t len)
{
    int ret = -1;
    DECLARE_HYPERCALL_BOUNCE(op, len, XC_HYPERCALL_BUFFER_BOUNCE_BOTH);

    if ( !xch )
    {
        errno = -EINVAL;
        goto out;
    }

    if ( xc_hypercall_bounce_pre(xch, op) )
    {
        PERROR("Could not bounce buffer for clone_op hypercall");
        goto out;
    }

    ret = xencall2(xch->xcall, __HYPERVISOR_clone_op,
                   cmd, HYPERCALL_BUFFER_AS_ARG(op));
    if ( ret < 0 )
    {
        if ( errno == EACCES )
            DPRINTF("clone operation failed -- need to"
                    " rebuild the user-space tool set?\n");
    }

    xc_hypercall_bounce_post(xch, op);
out:
    return ret;
}

int xc_cloning_enable(xc_interface *xch, void *notification_ring, int pages_num,
        unsigned long flags)
{
    clone_enable_info_t enable_info;

    enable_info.ring_vaddr = (unsigned long) notification_ring;
    enable_info.pages_num = pages_num;

    enable_info.flags = 0;
    if (flags & XC_CLONING_FLAG_USE_PAGE_SHARING_INFO_POOL)
        enable_info.flags |= CLONEOP_FLAG_USE_PAGE_SHARING_INFO_POOL;

    return do_clone_op(xch, CLONEOP_enable, &enable_info, sizeof(enable_info));
}

int xc_cloning_disable(xc_interface *xch)
{
    return do_clone_op(xch, CLONEOP_disable, NULL, 0);
}

int xc_cloning_clone_batch(xc_interface *xch, uint32_t domid,
        uint32_t children_num, uint32_t *children_domids)
{
    clone_op_t op;
    domid_t child_list[children_num];
    DECLARE_HYPERCALL_BOUNCE(child_list, sizeof(child_list), XC_HYPERCALL_BUFFER_BOUNCE_OUT);
    unsigned long start_info_mfn;
    int rc;

    rc = xc_hvm_param_get(xch, domid, PV_PARAM_START_INFO_PFN, &start_info_mfn);
    if ( rc )
    {
        PERROR("Error getting start info mfn!");
        goto out;
    }

    if ( xc_hypercall_bounce_pre(xch, child_list) )
        return -1;

    op.parent_id = domid;
    op.start_info_mfn = start_info_mfn;
    op.nr_children = children_num;
    set_xen_guest_handle(op.child_list, child_list);

    rc = do_clone_op(xch, CLONEOP_clone, &op, sizeof(op));
    if ( rc )
        PERROR("Error calling do_clone_op()");

    xc_hypercall_bounce_post(xch, child_list);

    if ( children_domids )
    {
        for (int i = 0; i < children_num; i++)
            children_domids[i] = child_list[i];
    }
out:
    return rc;

}

int xc_cloning_clone_single(xc_interface *xch, uint32_t domid,
        uint32_t *child_domid)
{
    return xc_cloning_clone_batch(xch, domid, 1, child_domid);
}

int xc_cloning_completion(xc_interface *xch, uint32_t id)
{
    clone_completion_t op;

    op.id = id;

    return do_clone_op(xch, CLONEOP_clone_completion, &op, sizeof(op));
}

int xc_cloning_cow(xc_interface *xch, uint32_t domid, void *addr, unsigned long *mfn)
{
    clone_cow_t op;
    int rc;

    op.domid = domid;
    op.vaddr = (unsigned long) addr;

    rc = do_clone_op(xch, CLONEOP_clone_cow, &op, sizeof(op));
    if (rc == 0 && mfn)
        *mfn = op.mfn;

    return rc;
}

int xc_cloning_reset(xc_interface *xch, uint32_t domid)
{
    clone_reset_t op;
    int rc;

    op.domid = domid;

    rc = do_clone_op(xch, CLONEOP_clone_reset, &op, sizeof(op));

    return rc;
}

int xc_domain_cloning_enable(xc_interface *xch,
        uint32_t domid, uint32_t max_clones)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_cloning_op;
    domctl.domain = domid;
    domctl.u.cloning_op.op = XEN_DOMCTL_CLONING_ENABLE;
    domctl.u.cloning_op.u.max_clones = max_clones;

    if ( do_domctl(xch, &domctl) )
        return -1;

    return 0;
}

int xc_domain_cloning_disable(xc_interface *xch,
        uint32_t domid)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_cloning_op;
    domctl.domain = domid;
    domctl.u.cloning_op.op = XEN_DOMCTL_CLONING_DISABLE;

    if ( do_domctl(xch, &domctl) )
        return -1;

    return 0;
}

int xc_domain_fuzzing_enable(xc_interface *xch,
        uint32_t domid)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_cloning_op;
    domctl.domain = domid;
    domctl.u.cloning_op.op = XEN_DOMCTL_FUZZING_ENABLE;

    if ( do_domctl(xch, &domctl) )
        return -1;

    return 0;
}

int xc_domain_fuzzing_disable(xc_interface *xch,
        uint32_t domid)
{
    DECLARE_DOMCTL;

    domctl.cmd = XEN_DOMCTL_cloning_op;
    domctl.domain = domid;
    domctl.u.cloning_op.op = XEN_DOMCTL_FUZZING_DISABLE;

    if ( do_domctl(xch, &domctl) )
        return -1;

    return 0;
}
