/*
 * fork.c
 *
 *  Created on: Dec 7, 2018
 *      Author: wolf
 */

//TODO revisit inclusions

#include <xen/types.h>
#include <xen/err.h>
#include <xen/sched.h>
#include <xen/mm.h>
#include <xen/event.h>
#include <xen/guest_access.h>
#include <xen/trace.h>
#include <xen/grant_table.h>
#include <public/xen.h>
#include <public/clone.h>
#include <asm/current.h>
#include <asm/page.h>//TODO
#include <asm/paging.h>//TODO
#include <asm/p2m.h>//TODO
#define GUEST_PAGING_LEVELS 4
#include <asm/guest_pt.h>
#include <asm/mem_sharing.h>
#include <asm/pv/p2m.h>
#include <xsm/xsm.h>


static int  dch_meminit(struct domain_clone_helper *dch);
static void dch_memfini(struct domain_clone_helper *dch);

extern void gnttab_cloning_sm_init(struct gnttab_cloning_sm *sm);


static int dch_init(struct domain_clone_helper *dch,
        struct domain *parent,
        unsigned long parent_start_info_mfn)
{
    int rc;

    memset(dch, 0, sizeof(*dch));
    dch->parent.domain = parent;
    dch->parent.start_info_mfn = parent_start_info_mfn;

    rc = dch_meminit(dch);
    if ( rc )
    {
        gprintk(XENLOG_ERR, "Error dch_alloc_mfns() rc=%d\n", rc);
        goto out;
    }

out:
    return rc;
}

static void dch_fini(struct domain_clone_helper *dch)
{
    dch_memfini(dch);
}

extern int arch_pt_pages_num(struct domain *d);
extern int grant_table_entries_num_for_cloning(struct domain *d);
/* This should be declared in xen/mm.h */
extern unsigned int max_order(const struct domain *d);

/* Returns the number of physical memory pages which are particular to clone */
static int physmem_pages_num(struct domain *d)
{
    int n;

    n  = p2m_fll_get_lists_num(d);
    n += arch_pt_pages_num(d);

    n += 1; /* start info; TODO we might not need this */
    n += 1; /* xenstore */
    n += 1; /* console */

    /* skip Xenstore and console grant entries (TODO HVM) */
    n += grant_table_entries_num_for_cloning(d) - 2;

    n += d->arch.cloning.state.stack_pages;

    if ( d->arch.cloning.fuzzing )
    {
        n += 1; /* monitor ring */
        n += PV_NR_PARAMS - 1; /* -1 because without start_info */
    }

    return n;
}

static int pfns_bm_init(struct pfns_bm *pbm, unsigned long size)
{
    int rc = 0;

    pbm->size = size;
    pbm->bm = xmalloc_array(unsigned long, BITS_TO_LONGS(size));
    if ( !pbm->bm )
    {
        rc = -ENOMEM;
        goto out;
    }
out:
    return rc;
}

static void pfns_bm_fini(struct pfns_bm *pbm)
{
    if ( pbm->bm )
    {
        xfree(pbm->bm);
        pbm->bm = NULL;
        pbm->size = 0;
    }
}

static int dch_meminit(struct domain_clone_helper *dch)
{
    unsigned long pfns_num;
    int order_hi;
    int rc;

    pfns_num = domain_get_maximum_gpfn(dch->parent.domain) + 1;

    rc = pfns_bm_init(&dch->pfns_physmem, pfns_num);
    if ( rc )
        goto out;
    rc = pfns_bm_init(&dch->pfns_shared, pfns_num);
    if ( rc )
        goto out;

    dch->mfns.num = physmem_pages_num(dch->parent.domain);
    ASSERT(dch->mfns.num >= 0);
    dch->mfns.first_free = dch->mfns.num; /* Nothing free for now */

    dch->mfns.array = xmalloc_array(xen_pfn_t, dch->mfns.num);
    if ( !dch->mfns.array )
    {
        rc = -ENOMEM;
        goto out;
    }

    order_hi = max_order(dch->parent.domain);
    dch->mfns_batch.order = get_order_from_pages(dch->mfns.num);
    dch->mfns_batch.order = MIN(dch->mfns_batch.order, order_hi); //TODO an order lower?
    dch->mfns_batch.size = (1 << dch->mfns_batch.order);
    dch->mfns_batch.num = (dch->mfns.num >> dch->mfns_batch.order);

out:
    if ( rc ) {
        pfns_bm_fini(&dch->pfns_shared);
        pfns_bm_fini(&dch->pfns_physmem);
        dch_memfini(dch);
    }
    return rc;
}

static void dch_memfini(struct domain_clone_helper *dch)
{
    if ( dch->mfns.array )
    {
        xfree(dch->mfns.array);
        dch->mfns.array = NULL;
    }
    pfns_bm_fini(&dch->pfns_shared);
    pfns_bm_fini(&dch->pfns_physmem);
}

/*
 * inspired from populate_physmap() in common/memory.c
 */
static int alloc_extent(struct domain *d,
    unsigned int extent_order, unsigned int memflags, xen_pfn_t *extent)
{
    struct page_info *page;
    unsigned long mfn, mfn_num;
    int rc = 0;

    page = alloc_domheap_pages(d, extent_order, 0);
    if ( unlikely(!page) )
    {
        rc = -ENOMEM;
        goto out;
    }

    mfn = mfn_x(page_to_mfn(page));
    mfn_num = (1 << extent_order);

    for ( unsigned long i = 0; i < mfn_num; i++ )
        extent[i] = mfn + i;

out:
    return rc;
}

static int dch_set_child(struct domain_clone_helper *dch,
        struct domain *child)
{
    int rc = 0, i;

    TRACE_1D(TRC_CLONE_ALLOC_PHYSMAP, 1);

    dch->child.domain = child;

    bitmap_zero(dch->pfns_physmem.bm, dch->pfns_physmem.size);
    bitmap_zero(dch->pfns_shared.bm, dch->pfns_shared.size);

    ASSERT(dch->mfns.first_free == dch->mfns.num);
    dch->mfns.first_free = 0;

    for ( i = 0; i < dch->mfns_batch.num; i++ )
    {
        rc = alloc_extent(dch->child.domain, dch->mfns_batch.order, 0,
                &dch->mfns.array[i * dch->mfns_batch.size]);
        if ( rc )
        {
            gdprintk(XENLOG_ERR,
                "Error calling alloc_extent() rc=%d batch_size=%d i=%d\n",
                rc, dch->mfns_batch.size, i);
            goto out;
        }
    }

    /* TODO this may fragment the memory too much */
    for ( i = i * dch->mfns_batch.size; i < dch->mfns.num; i++ )
    {
        rc = alloc_extent(dch->child.domain, 0, 0, &dch->mfns.array[i]);
        if ( rc )
        {
            gdprintk(XENLOG_ERR,
                "Error calling alloc_extent() rc=%d i=%d\n", rc, i);
            goto out;
        }
    }

    gnttab_cloning_sm_init(&dch->sm);

out:
    /* TODO what do we do with extents? */
    TRACE_1D(TRC_CLONE_ALLOC_PHYSMAP, 0);
    return rc;
}

/* This may be public one day */
static int dch_alloc_mfns(struct domain_clone_helper *dch,
        int count, xen_pfn_t *mfns)
{
    int i;

    if ( dch->mfns.first_free + count > dch->mfns.num )
        return -ENOMEM;

    for ( i = 0; i < count; i++ )
        mfns[i] = dch->mfns.array[dch->mfns.first_free++];

    return 0;
}

unsigned long dch_alloc_mfn(struct domain_clone_helper *dch)
{
    unsigned long mfn;
    int rc;

    rc = dch_alloc_mfns(dch, 1, &mfn);
    if ( rc )
    {
        gdprintk(XENLOG_ERR, "no new mfn available!\n");
        mfn = INVALID_PFN;
    }

    return mfn;
}

void dch_set_child_physmem_mfn(struct domain_clone_helper *dch,
        unsigned long gpfn, unsigned long dmfn)
{
    int rc;

    ASSERT(dch);
    /* TODO validate gpfn */
    ASSERT(mfn_valid(_mfn(dmfn)));
    rc = p2m_fll_set_entry(dch->child.domain, gpfn, dmfn);
    if ( rc != 0 )
        gdprintk(XENLOG_ERR, "Error calling p2m_fll_set_entry(dch=%p, gpfn=%lx, dmfn=%lx)=%d\n",
                dch, gpfn, dmfn, rc);
    ASSERT(rc == 0);
    set_bit(gpfn, dch->pfns_physmem.bm);
}

void dch_replace_child_mfn(struct domain_clone_helper *dch,
        unsigned long smfn, unsigned long *pdmfn)
{
    unsigned long gpfn, dmfn;

    gpfn = get_gpfn_from_mfn(smfn);
    dmfn = dch_alloc_mfn(dch);
    ASSERT(mfn_valid(_mfn(dmfn)));
    dch_set_child_physmem_mfn(dch, gpfn, dmfn);

    if ( pdmfn )
        *pdmfn = dmfn;
}

static int shared_info_clone(struct domain *parent, struct domain *child,
        struct domain_clone_helper *dch)
{
    int rc;

    /*
     * We copy everything now, even pfn_to_mfn_frame_list_list which
     * will be updated next.
     */
    memcpy(child->shared_info, parent->shared_info,
        sizeof(*parent->shared_info));

    rc = p2m_fll_clone(child, parent, dch);
    if ( rc )
    {
        gprintk(XENLOG_ERR, "Error p2m_fll_clone() rc=%d\n", rc);
        goto out;
    }

out:
    return rc;
}



static
int domain_vcpu_context_clone(struct domain *parent, struct domain *child,
        struct domain_clone_helper *dch)
{
    vcpu_guest_context_u ctxt;
    unsigned long i;
    int rc = 0;

    TRACE_1D(TRC_CLONE_PAGETABLE, 1);

    /* TODO we currently support only 1 address space */
    ASSERT(parent->max_vcpus == 1);

    ctxt.nat = alloc_vcpu_guest_context();
    if ( !ctxt.nat )
    {
        gprintk(XENLOG_ERR, "Error allocating vcpu guest context\n");
        rc = -ENOMEM;
        goto out;
    }

    for ( i = 0; i < parent->max_vcpus; i++ )
    {
        unsigned long smfn, dmfn;

        arch_get_info_guest(parent->vcpu[i], ctxt);

        smfn = paddr_to_pfn(ctxt.nat->ctrlreg[3]);
        if ( !pagetable_get_pfn(p2m_get_pagetable(parent->arch.p2m)) )
            parent->arch.p2m->phys_table = pagetable_from_mfn(_mfn(smfn));//TODO reset

        dch_replace_child_mfn(dch, smfn, &dmfn);

        page_table_clone(dmfn, smfn, dch);
        ctxt.nat->ctrlreg[3] = pfn_to_paddr(dmfn);

        rc = arch_set_info_guest(child->vcpu[i], ctxt);
        ASSERT(rc == 0);
    }

    free_vcpu_guest_context(ctxt.nat);

out:
    TRACE_1D(TRC_CLONE_PAGETABLE, 0);
    return rc;
}

static
int domain_vcpu_context_reset(struct domain *parent, struct domain *child,
        struct domain_clone_helper *dch)
{
    vcpu_guest_context_u ctxt;
    unsigned long i;
    int rc = 0;

    /* TODO we currently support only 1 address space */
    ASSERT(parent->max_vcpus == 1);

    ctxt.nat = alloc_vcpu_guest_context();
    if ( !ctxt.nat )
    {
        gprintk(XENLOG_ERR, "Error allocating vcpu guest context\n");
        rc = -ENOMEM;
        goto out;
    }

    for ( i = 0; i < parent->max_vcpus; i++ )
    {
        unsigned long smfn, dmfn;

        arch_get_info_guest(child->vcpu[i], ctxt);
        dmfn = paddr_to_pfn(ctxt.nat->ctrlreg[3]);

        arch_get_info_guest(parent->vcpu[i], ctxt);
        smfn = paddr_to_pfn(ctxt.nat->ctrlreg[3]);

        page_table_reset(dmfn, smfn, dch);
    }

    free_vcpu_guest_context(ctxt.nat);

out:
    return rc;
}

static void do_setmaxmem(struct domain *d, struct domain *s)
{
    spin_lock(&d->page_alloc_lock);//TODO lock s?
    d->max_pages = s->max_pages;
    spin_unlock(&d->page_alloc_lock);
}


extern int domain_vcpus_clone(struct domain *parent, struct domain *child);

extern
struct domain *domain_copy(struct domain *s, domid_t domid);

extern
int grant_table_clone(struct domain *d, struct domain *s, struct domain_clone_helper *dch);

/******************************************************************************
 * Notification ring
 */

static clone_notification_ring_t *cnring;
static spinlock_t cnring_lock;
static unsigned long cnring_pages_num;

static
int notification_ring_init(unsigned long ring_vaddr, unsigned long pages_num)
{
    int rc, clz;

    rc = map_cloning_notification_ring(ring_vaddr, pages_num,
            (void **) &cnring);
    if ( rc )
        goto out;

    /* entries_num is a power of two */
    cnring->hdr.entries_num =
        (PAGE_SIZE * pages_num - sizeof(clone_notification_ring_header_t)) /
        sizeof(clone_notification_t);
    clz = __builtin_clzl(cnring->hdr.entries_num) + 1;
    cnring->hdr.entries_num = 1 << (64 - clz);
    cnring->hdr.prod_idx = 0;
    cnring->hdr.cons_idx = 0;

    cnring_pages_num = pages_num;

    spin_lock_init(&cnring_lock);

    printk("notification_ring=%p entries=%lu\n",
            cnring, cnring->hdr.entries_num); /* TODO revisit */
out:
    return rc;
}

static int notification_ring_fini(void)
{
    int rc;

    rc = unmap_cloning_notification_ring(cnring);
    if (rc == 0)
        printk("notification_ring unmapped\n");

    return rc;
}

#define CLONING_RING_IS_FULL(p) \
    ((p)->hdr.prod_idx + 1 - (p)->hdr.cons_idx > (p)->hdr.entries_num)

static bool notification_ring_is_full(void)
{
    bool ret;

    spin_lock_recursive(&cnring_lock);
    ret = CLONING_RING_IS_FULL(cnring);
    spin_unlock_recursive(&cnring_lock);

    return ret;
}

static void notification_ring_add(struct domain_clone_helper *dch,
        struct clone_child_info *child_info)
{
    clone_notification_t *cne;
#if 0
    int rc;
#endif

    spin_lock_recursive(&cnring_lock);

    /* this should have been already called */
    ASSERT(!notification_ring_is_full());

#if 0
    rc = modify_xen_mappings(
            (unsigned long) cnring,
            (unsigned long) cnring + cnring_pages_num * PAGE_SIZE,
            PAGE_HYPERVISOR_RW);
    if (rc) {
        gprintk(XENLOG_ERR, "Error modify_xen_mappings()=%d\n", rc);
        return;
    }
#endif

    cne = &cnring->entries[CLONE_RING_PROD_IDX(cnring)];
    cne->id = cnring->hdr.prod_idx;
    cne->parent_id = dch->parent.domain->domain_id;
    cne->child_id = child_info->domid;
    cne->parent_start_info_mfn = dch->parent.start_info_mfn;
    cne->child_start_info_mfn = child_info->start_info_mfn;
    cnring->hdr.prod_idx++;

#if 0
    rc = modify_xen_mappings(
            (unsigned long) cnring,
            (unsigned long) cnring + cnring_pages_num * PAGE_SIZE,
            PAGE_HYPERVISOR_RO);//TODO also at init
    if (rc) {
        gprintk(XENLOG_ERR, "Error modify_xen_mappings()=%d\n", rc);
        return;
    }
#endif

    spin_unlock_recursive(&cnring_lock);

    child_info->ring_id = cne->id;
}

/******************************************************************************
 * Completion ring
 */

enum cce_state {
    CCE_STATE_NONE,
    CCE_STATE_CREATED,
    CCE_STATE_COMPLETED,
};

struct clone_completion_entry {
    spinlock_t lock;
    enum cce_state state;
    struct waitqueue_head wq;
    struct clone_op_state *cos;
};

static
void cce_set_state(struct clone_completion_entry *cce, enum cce_state state)
{
    spin_lock(&cce->lock);
    cce->state = state;
    spin_unlock(&cce->lock);
}

static
enum cce_state cce_get_state(struct clone_completion_entry *cce)
{
    enum cce_state state;

    spin_lock(&cce->lock);
    state = cce->state;
    spin_unlock(&cce->lock);
    return state;
}

struct clone_completion_ring {
    struct {
        unsigned long entries_num;
        unsigned long prod_idx;
        unsigned long cons_idx;
        spinlock_t lock;
    } hdr;
    struct clone_completion_entry *entries;
} ccring;

static int completion_ring_init(void)
{
    struct clone_completion_entry *cce;
    int rc = 0;

    spin_lock_recursive(&cnring_lock);
    ASSERT(cnring->hdr.entries_num > 0);
    spin_unlock_recursive(&cnring_lock);

    ccring.entries = xmalloc_array(struct clone_completion_entry,
            cnring->hdr.entries_num);
    if ( !ccring.entries )
    {
        rc = -ENOMEM;
        unmap_cloning_notification_ring(cnring);
        goto out;
    }
    ccring.hdr.entries_num = cnring->hdr.entries_num;
    ccring.hdr.prod_idx = 0;
    ccring.hdr.cons_idx = 0;
    spin_lock_init(&ccring.hdr.lock);

    for ( unsigned long i = 0; i < ccring.hdr.entries_num; i++ )
    {
        cce = &ccring.entries[CLONE_RING_IDX(&ccring, i)];
        spin_lock_init(&cce->lock);
        init_waitqueue_head(&cce->wq);
        cce->state = CCE_STATE_NONE;
        cce->cos = NULL;
    }

out:
    return rc;
}

static void completion_ring_fini(void)
{
    if ( ccring.entries )
    {
        xfree(ccring.entries);
        ccring.entries = NULL;
    }
}

static bool completion_ring_is_full(void)
{
    return CLONING_RING_IS_FULL(&ccring);
}

static void completion_ring_add(uint32_t id, struct clone_op_state *cos)
{
    struct clone_completion_entry *cce;

    spin_lock(&ccring.hdr.lock);
    ASSERT(!completion_ring_is_full());
    if (!(id == ccring.hdr.prod_idx))
        printk("id=%u vs ccring.hdr.prod_idx=%lu\n", id, ccring.hdr.prod_idx);
    ASSERT(id == ccring.hdr.prod_idx);

    cce = &ccring.entries[CLONE_RING_IDX(&ccring, id)];
    cce_set_state(cce, CCE_STATE_CREATED);
    cce->cos = cos;
    ccring.hdr.prod_idx++;

    spin_unlock(&ccring.hdr.lock);
}

static void completion_ring_purge_completed(void)
{
    struct clone_completion_entry *cce;
    struct clone_op_state *cos;

    spin_lock(&ccring.hdr.lock);

    while ( ccring.hdr.cons_idx < ccring.hdr.prod_idx )
    {
        cce = &ccring.entries[CLONE_RING_IDX(&ccring, ccring.hdr.cons_idx)];

        if ( cce_get_state(cce) != CCE_STATE_COMPLETED )
            break;
        cce_set_state(cce, CCE_STATE_NONE);

        cos = cce->cos;
        ASSERT(cos != NULL);
        cos->nr_done++;
        cce->cos = NULL;

        ccring.hdr.cons_idx++;
    }

    spin_unlock(&ccring.hdr.lock);
}

static void completion_ring_wait(uint32_t entry_id)
{
    struct clone_completion_entry *cce;

    spin_lock(&ccring.hdr.lock);
    ASSERT(ccring.hdr.cons_idx <= entry_id && entry_id < ccring.hdr.prod_idx);
    cce = &ccring.entries[CLONE_RING_IDX(&ccring, entry_id)];
    ASSERT(cce_get_state(cce) != CCE_STATE_NONE);
    spin_unlock(&ccring.hdr.lock);

    wait_event(cce->wq, cce_get_state(cce) == CCE_STATE_COMPLETED);

    completion_ring_purge_completed();
}

static int completion_ring_done(uint32_t entry_id)
{
    struct clone_completion_entry *cce;
    int rc = 0;

    spin_lock(&ccring.hdr.lock);
    if ( ccring.hdr.cons_idx > entry_id || entry_id >= ccring.hdr.prod_idx )
    {
        printk("entry_id=%u cons=%lu prod=%lu\n", entry_id, ccring.hdr.cons_idx, ccring.hdr.prod_idx);
        rc = -EINVAL;
        spin_unlock(&ccring.hdr.lock);
        goto out;
    }
    cce = &ccring.entries[CLONE_RING_IDX(&ccring, entry_id)];
    ASSERT(cce_get_state(cce) == CCE_STATE_CREATED);
    spin_unlock(&ccring.hdr.lock);

    cce_set_state(cce, CCE_STATE_COMPLETED);
    wake_up_one(&cce->wq);
out:
    return rc;
}

/******************************************************************************
 * Single VM cloning
 */

static void start_info_clone(struct domain_clone_helper *dch)
{
    start_info_t *prntsi, *chldsi;

    prntsi = map_domain_page(_mfn(dch->parent.start_info_mfn));
    dch_replace_child_mfn(dch, dch->parent.start_info_mfn,
        &dch->child.start_info_mfn);
    chldsi = map_domain_page(_mfn(dch->child.start_info_mfn));

    /* fill child start info */
    memcpy(chldsi->magic, prntsi->magic, sizeof(prntsi->magic));
    chldsi->nr_pages = prntsi->nr_pages;
    chldsi->shared_info = virt_to_maddr(&dch->child.domain->shared_info);
    chldsi->flags = prntsi->flags;

    dch_replace_child_mfn(dch, prntsi->store_mfn, &chldsi->store_mfn);
    chldsi->store_evtchn = prntsi->store_evtchn;
    /* Save Xenstore mfns for grant table cloning */
    dch->parent.xenstore_mfn = prntsi->store_mfn;
    dch->child.xenstore_mfn = chldsi->store_mfn;

    dch_replace_child_mfn(dch, prntsi->console.domU.mfn,
        &chldsi->console.domU.mfn);
    chldsi->console.domU.evtchn = prntsi->console.domU.evtchn;
    /* Save console mfns for grant table cloning */
    dch->parent.console_mfn = prntsi->console.domU.mfn;
    dch->child.console_mfn = chldsi->console.domU.mfn;

    chldsi->pt_base = prntsi->pt_base;
    chldsi->nr_pt_frames = prntsi->nr_pt_frames;
    chldsi->mfn_list = prntsi->mfn_list;
    chldsi->mod_start = prntsi->mod_start;
    chldsi->mod_len = prntsi->mod_len;
    memcpy(chldsi->cmd_line, prntsi->cmd_line, sizeof(prntsi->cmd_line));
    chldsi->first_p2m_pfn = prntsi->first_p2m_pfn;
    chldsi->nr_p2m_frames = prntsi->nr_p2m_frames;

    unmap_domain_page(chldsi);
    unmap_domain_page(prntsi);
}

extern long domain_generate_domid(domid_t *pdom);
extern unsigned long system_pages_number(void);
extern void save_segments(struct vcpu *v);

static long do_clone_vm(struct domain *parent,
        struct domain_clone_helper *dch,
        struct cpu_user_regs *stack_regs,
        domid_t child_domid,
        bool self_cloning)
{
    struct domain *child;
    struct cpu_user_regs *user_regs;
    unsigned long before_pg, after_pg, total_pg;
    int rc = 0;

    TRACE_1D(TRC_CLONE_OP, 1);

    before_pg = system_pages_number();

    child = domain_copy(parent, child_domid);
    if ( IS_ERR(child) )
    {
        rc = PTR_ERR(child);
        gprintk(XENLOG_ERR, "Error domain_copy() rc=%d\n", rc);
        goto out;
    }

    child->parent = parent;
    child->arch.cloning.triggered = true;//TODO set to false when no shared remaining
    child->arch.p2m->max_mapped_pfn = parent->arch.p2m->max_mapped_pfn;

    rc = domain_vcpus_clone(parent, child);
    if ( rc )
    {
        gprintk(XENLOG_ERR, "Error domain_vcpus_clone() rc=%d\n", rc);
        goto out_domain_kill;
    }

    do_setmaxmem(child, parent);

    rc = dch_set_child(dch, child);
    if ( rc )
    {
        gprintk(XENLOG_ERR, "Error dch_set_child() rc=%d\n", rc);
        goto out_domain_kill;
    }

    /* Setup shared info (and P2M FLL) */
    rc = shared_info_clone(parent, child, dch);
    if ( rc )
    {
        gprintk(XENLOG_ERR, "Error shared_info_clone() rc=%d\n", rc);
        goto out_memory;
    }

    start_info_clone(dch);

    rc = evtchn_clone(parent, child);
    if ( rc )
    {
        gprintk(XENLOG_ERR, "Error evtchn_clone() rc=%d\n", rc);
        goto out_memory;
    }

    rc = grant_table_clone(child, parent, dch);
    if ( rc )
    {
        gprintk(XENLOG_ERR, "Error grant_table_clone() rc=%d\n", rc);
        goto out_evtchn;
    }

    if ( !self_cloning )
    {
        unsigned long pvalue, cvalue;

        /* set params if fuzzing */
        if ( parent->arch.cloning.fuzzing )
        {
            /* set start info mfn */
            domain_set_param(child, PV_PARAM_START_INFO_PFN,
                    dch->child.start_info_mfn);

            for ( int i = PV_PARAM_START_INFO_PFN + 1; i < PV_NR_PARAMS; i++ )
            {
                pvalue = domain_get_param(parent, i);
                dch_replace_child_mfn(dch, pvalue, &cvalue);
                domain_set_param(child, i, cvalue);
            }
        }

        rc = cloning_copy_special_pages(dch, stack_regs->rsp, parent->arch.cloning.state.stack_pages);//TODO always
        if ( rc )
        {
            gprintk(XENLOG_ERR, "Error %s:cloning_copy_special_pages() rc=%d\n",
                    __FUNCTION__, rc);
            goto out_gnttab;
        }
    }

    if ( page_sharing_info_pool_enabled )
    {
        rc = mem_sharing_pools_init(child);
        if ( rc )
        {
            gprintk(XENLOG_ERR, "Error mem_sharing_pools_init() rc=%d\n", rc);
            goto out_domain_kill;
        }
    }

    rc = domain_vcpu_context_clone(parent, child, dch);
    if ( rc )
    {
        gprintk(XENLOG_ERR, "Error domain_vcpu_context_clone() rc=%d\n", rc);
        goto out_gnttab;
    }

    //TODO maybe more?
    user_regs = &child->vcpu[0]->arch.user_regs;
    memcpy(user_regs, stack_regs, CTXT_SWITCH_STACK_BYTES);

    if ( !self_cloning )
    {
        struct clone_op_state *cos;

        cos = &parent->arch.cloning.state;
        vcpu_info(child->vcpu[0], evtchn_upcall_mask) =
                cos->saved_evtchn_upcall_mask;
    }
    else
        save_segments(child->vcpu[0]);

#if 0
    if (list_empty(&parent->children))
        parent->family_id = family_id++;
    child->family_id = parent->family_id;
    INIT_LIST_HEAD(&child->children_list);
    INIT_LIST_HEAD(&child->children);
    list_add_tail(&parent->children, &child->children_list);
#endif

    after_pg = system_pages_number();
    total_pg = before_pg - after_pg;

    printk("cloned %d -> %d total_pg=%lu physmem_pg=%d meta_pg=%lu\n",
        parent->domain_id, child->domain_id,
        total_pg, dch->mfns.num, total_pg - dch->mfns.num);

    if ( rc )
    {
        int rc2;

        /* TODO argo_destroy(child);*/
out_gnttab:
        gnttab_release_mappings(child);
out_evtchn:
        evtchn_destroy(child);
        /* TODO vnuma_destroy(child->vnuma);*/
out_memory:
        domain_set_outstanding_pages(child, 0);
out_domain_kill:
        child->is_dying = DOMDYING_dying;
        do
        {
            rc2 = domain_kill(child);
        } while ( rc2 == -ERESTART );
    }
out:
    TRACE_1D(TRC_CLONE_OP, 0);
    return rc;
}

static long do_reset_vm(struct domain *child)
{
    struct domain *parent = child->parent;
    struct clone_op_state *cos = &parent->arch.cloning.state;
    struct domain_clone_helper *dch = &cos->dch;
    struct cpu_user_regs *parent_regs = &cos->saved_regs, *child_regs;
    int rc = 0;
#if CONFIG_MEMSHR_STATS
    unsigned long start = rdtsc(), stop;
#endif

    /* TODO check if the right child is set */

    /* Handle shared info corruption */
    if ( !child->arch.cloning.fuzzing_backup.shared_info )
    {
        child->arch.cloning.fuzzing_backup.shared_info =
                alloc_xenheap_pages(0, MEMF_bits(32));
        if ( child->arch.cloning.fuzzing_backup.shared_info == NULL )
        {
            rc = -ENOMEM;
            goto out;
        }
        memcpy(child->arch.cloning.fuzzing_backup.shared_info, child->shared_info, sizeof(*child->shared_info));

        rc = p2m_fll_backup_save(child);
    }
    else
    {
        if ( !domain_get_maximum_gpfn(child) )
        {
            printk("Restoring shared info domid=%d\n", child->domain_id);
            memcpy(child->shared_info, child->arch.cloning.fuzzing_backup.shared_info, sizeof(*child->shared_info));
        }
    }

    child_regs = &child->vcpu[0]->arch.user_regs;
    memcpy(child_regs, parent_regs, CTXT_SWITCH_STACK_BYTES);

    /* TODO start_info, evtchn, grant_table: what can change there? */

    /* TODO support self cloning? */
    rc = cloning_copy_special_pages(dch, parent_regs->rsp, cos->stack_pages);
    if ( rc )
    {
        /* Handle P2M FLL corruption */
        if ( rc == -EINVAL )
        {
            printk("Restoring shared info and P2M FLL domid=%d\n",
                    child->domain_id);
            memcpy(child->shared_info, child->arch.cloning.fuzzing_backup.shared_info, sizeof(*child->shared_info));

            rc = p2m_fll_backup_restore(child);
            if ( rc )
            {
                gprintk(XENLOG_ERR, "Error %s:p2m_fll_restore() rc=%d\n",
                        __FUNCTION__, rc);
                goto out;
            }

            rc = cloning_copy_special_pages(dch, parent_regs->rsp, cos->stack_pages);
        }
        if ( rc )
        {
            gprintk(XENLOG_ERR, "Error %s:cloning_copy_special_pages() rc=%d\n",
                    __FUNCTION__, rc);
            goto out;
        }
    }

    rc = domain_vcpu_context_reset(parent, child, dch);
    if ( rc )
    {
        gprintk(XENLOG_ERR, "Error domain_vcpu_context_clone() rc=%d\n", rc);
        goto out;
    }

    /* TODO support self cloning? */
    vcpu_info(child->vcpu[0], evtchn_upcall_mask) =
            cos->saved_evtchn_upcall_mask;

    atomic_set(&child->cow_pages, 0);

#if CONFIG_MEMSHR_STATS
    stop = rdtsc();
    child->memshr_stats.fuzz.sum_duration_usec += (stop - start) / 1000;
    child->memshr_stats.fuzz.iteration_num++;
    if ( child->memshr_stats.fuzz.iteration_num == 100 )
    {
        printk("RESET_STATS PV duration=%lu usec pages=%lu\n",
            child->memshr_stats.fuzz.sum_duration_usec / child->memshr_stats.fuzz.iteration_num,
            child->memshr_stats.fuzz.sum_reset_pages / child->memshr_stats.fuzz.iteration_num);
        child->memshr_stats.fuzz.sum_reset_pages = 0;
        child->memshr_stats.fuzz.sum_duration_usec = 0;
        child->memshr_stats.fuzz.iteration_num = 0;
    }
#endif

out:
    return rc;
}

/******************************************************************************
 * Clone operation state
 */

static void clone_op_state_fini(struct clone_op_state *cos)
{
    dch_fini(&cos->dch);

    if ( cos->child_info )
    {
        xfree(cos->child_info);
        cos->child_info = NULL;
    }
    cos->nr_requested = 0;
    cos->nr_created = 0;
    cos->nr_queued_to_notification = 0;
    cos->nr_queued_to_completion = 0;
    cos->nr_done = 0;
    cos->in_progress = false;
}

static int clone_op_state_init(struct clone_op_state *cos,
        struct domain *parent, clone_op_t *op, bool self_cloning)
{
    unsigned long sp;
    int rc;

    ASSERT(!cos->in_progress);

    printk("%s children=%d\n", __FUNCTION__, op->nr_children);

    if ( self_cloning )
    {
        memcpy(&cos->saved_regs, guest_cpu_user_regs(), CTXT_SWITCH_STACK_BYTES);
        cos->saved_regs.rax = 1; /* for discriminating between parent and child */
    }
    else
    {
        struct vcpu *p = parent->vcpu[0];

        memcpy(&cos->saved_regs, &p->arch.user_regs, CTXT_SWITCH_STACK_BYTES);

        sp = cos->saved_regs.rsp;
        cos->stack_pages =
                (sp - sizeof(struct cpu_user_regs) < (sp & PAGE_MASK)) ? 2 : 1;
        /* TODO stack can have more pages */
    }

    rc = dch_init(&cos->dch, parent, op->start_info_mfn);
    if ( rc )
    {
        gprintk(XENLOG_ERR, "Error dch_init() rc=%d\n", rc);
        rc = -ENOMEM;
        goto out;
    }

    /* TODO we should create only for number of children limited to one of the rings' sizes */
    cos->child_info = xmalloc_array(struct clone_child_info, op->nr_children);
    if ( !cos->child_info )
    {
        gprintk(XENLOG_ERR, "Error allocating child info array\n");
        rc = -ENOMEM;
        goto out;
    }

    /*
     * We set the child domid's now because we are going to set as read-only
     * all the writable pages of the calling domain.
     * Looks kind of hackish indeed.
     *
     * TODO CoW the page with this vaddr for parent+children.
     */
    for ( uint32_t i = 0; i < op->nr_children; i++ )
    {
        rc = domain_generate_domid(&cos->child_info[i].domid);
        if ( rc )
        {
            gprintk(XENLOG_ERR, "Error domain_generate_domid() rc=%d\n", rc);
            goto out;
        }

        if ( __copy_to_guest_offset(op->child_list, i, &cos->child_info[i].domid, 1) )
        {
            gprintk(XENLOG_ERR, "Error copying dom ids\n");
            /*TODO find some error handling op.status = GNTST_bad_virt_addr;*/
            rc = -EINVAL;
            goto out;
        }
    }

    cos->nr_requested = op->nr_children;
    cos->nr_created = 0;
    cos->nr_done = 0;
    cos->in_progress = true;

out:
    if ( rc )
        clone_op_state_fini(cos);
    return rc;
}

static long do_clone_vms(struct domain *parent, bool self_cloning)
{
    struct clone_op_state *cos = &parent->arch.cloning.state;
    bool stop_queueing_to_notification, stop_queueing_to_completion;
    uint32_t i;
    int rc = 0;

    TRACE_1D(TRC_CLONE_OP_ALL, 1);

    completion_ring_purge_completed();

    stop_queueing_to_notification = (cos->nr_queued_to_notification < cos->nr_created);
    stop_queueing_to_completion = (cos->nr_queued_to_completion < cos->nr_queued_to_notification);

    /* Create clones */
    for ( i = cos->nr_created; i < cos->nr_requested; i++ )
    {
        rc = do_clone_vm(parent, &cos->dch, &cos->saved_regs,
                cos->child_info[i].domid, self_cloning);
        if ( rc )
        {
            gprintk(XENLOG_ERR, "Error calling do_clone_vm() rc=%d\n", rc);
            rc = -1;
            goto out_clone_op_state_fini;
        }
        cos->child_info[i].start_info_mfn = cos->dch.child.start_info_mfn;
        cos->nr_created++;

        /*
         * Try to send a notification right away.
         * If rings are full, we wait until we have some room there.
         */
        if ( !stop_queueing_to_notification )
        {
            if ( !notification_ring_is_full() )
            {
                notification_ring_add(&cos->dch, &cos->child_info[i]);
                cos->nr_queued_to_notification++;

                if ( !stop_queueing_to_completion )
                {
                    if ( !completion_ring_is_full() )
                    {
                        completion_ring_add(cos->child_info[i].ring_id, cos);
                        cos->nr_queued_to_completion++;
                    }
                    else
                        stop_queueing_to_completion = true;
                }

                send_global_virq(VIRQ_CLONED);
            }
            else
                stop_queueing_to_notification = true;
        }

        if ( hypercall_preempt_check() )
        {
            rc = -ERESTART;
            goto out;
        }
    }

    /* Send notifications for all created clones */
    for ( i = cos->nr_queued_to_notification; i < cos->nr_created; i++ )
    {
        if ( notification_ring_is_full() )
            break;

        notification_ring_add(&cos->dch, &cos->child_info[i]);
        cos->nr_queued_to_notification++;

        if ( !stop_queueing_to_completion )
        {
            if ( !completion_ring_is_full() )
            {
                completion_ring_add(cos->child_info[i].ring_id, cos);
                cos->nr_queued_to_completion++;
            }
            else
                stop_queueing_to_completion = true;
        }

        send_global_virq(VIRQ_CLONED);//TODO maybe at the end of the loop

        if ( hypercall_preempt_check() )//TODO remove?
        {
            rc = -ERESTART;
            goto out;
        }
    }

    /* Prepare to wait for completion of all clones that we send notifications for */
    for ( i = cos->nr_queued_to_completion; i < cos->nr_queued_to_notification; i++ )
    {
        if ( completion_ring_is_full() )
            break;
        completion_ring_add(cos->child_info[i].ring_id, cos);
        cos->nr_queued_to_completion++;

        if ( hypercall_preempt_check() )
        {
            rc = -ERESTART;
            goto out;
        }
    }

    /* Wait completion of all clones */
    /* TODO wait on completion ring when fuzzing */
    for ( i = cos->nr_done; !in_atomic() && i < cos->nr_queued_to_completion; i++ )
    {
        completion_ring_wait(cos->child_info[i].ring_id);

        if ( hypercall_preempt_check() && i < cos->nr_queued_to_completion - 1 )
        {
            rc = -ERESTART;
            goto out;
        }
    }

out_clone_op_state_fini:
    /* TODO take care of cleaning up cos for fuzzing */
    if ( !parent->arch.cloning.fuzzing )
        clone_op_state_fini(cos);
out:
    TRACE_1D(TRC_CLONE_OP_ALL, 0);
    return rc;
}

int clone_fini(struct domain *d)
{
    int rc = 0;

    if ( d->arch.cloning.fuzzing )
    {
        p2m_fll_backup_delete(d);

        if ( d->arch.cloning.fuzzing_backup.shared_info )
        {
            free_xenheap_pages(d->arch.cloning.fuzzing_backup.shared_info, 0);
            d->arch.cloning.fuzzing_backup.shared_info = NULL;
        }

        d->arch.cloning.fuzzing = false;
    }

    return rc;
}

/* TODO move */
static bool cloning_enabled = false;

long do_clone_op(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    long ret = 0;

    switch ( cmd )
    {
    case CLONEOP_enable:
    {
        clone_enable_info_t clone_enable;

        ret = -EBUSY;
        if ( cloning_enabled )
            break;

        ret = -EFAULT;
        if ( copy_from_guest(&clone_enable, arg, 1) )
            break;

        if ( clone_enable.flags & CLONEOP_FLAG_USE_PAGE_SHARING_INFO_POOL )
        {
            /* we use a page_sharing_info pool for 60% of the available pages */
            ret = page_sharing_info_allocator_init(avail_domheap_pages() * 60 / 100);
            if ( ret )
            {
                printk("Error init page_sharing_info allocator\n");
                break;
            }
        }

        ret = notification_ring_init(clone_enable.ring_vaddr,
                clone_enable.pages_num);
        if ( ret )
            break;
        ret = completion_ring_init();
        if ( ret )
        {
            notification_ring_fini();
            break;
        }
        cloning_enabled = true;
        break;
    }

    case CLONEOP_disable:
    {
        ret = -EINVAL;
        if ( !cloning_enabled )
            break;

        ret = notification_ring_fini();
        if ( ret )
            break;
        completion_ring_fini();
        cloning_enabled = false;
        break;
    }

    case CLONEOP_clone:
    {
        struct vcpu *v = current;
        struct domain *d = v->domain, *parent;
        struct clone_op_state *cos;
        static clone_op_t op;
        bool self_cloning;

        ret = -EPERM;
        if ( !cloning_enabled )
            break;

        /* TODO lock domain */

        if ( d->domain_id == 0 )
        {
            /* when Dom0 triggers the cloning arg is copied every time */
            ret = -EFAULT;
            if ( copy_from_guest(&op, arg, 1) )
                break;

            ret = rcu_lock_live_remote_domain_by_id(op.parent_id, &parent);
            if ( ret )
                break;

            self_cloning = false;
        }
        else
        {
            parent = d;
            self_cloning = true;
        }

        if ( !parent->arch.cloning.enabled )
            break;

        cos = &parent->arch.cloning.state;
        if ( !cos->in_progress )
        {
            /* just started cloning */
            if ( self_cloning )
            {
                /* when current domain is cloning arg is copied only once */
                ret = -EFAULT;
                if ( copy_from_guest(&op, arg, 1) )
                    break;
            }
            else
            {
                domain_pause(parent);
                /* save interrupt status */
                cos->saved_evtchn_upcall_mask =
                        vcpu_info(parent->vcpu[0], evtchn_upcall_mask);
                vcpu_info(parent->vcpu[0], evtchn_upcall_mask) = 1;
            }

            if ( !guest_handle_okay(op.child_list, op.nr_children) )
                return -EFAULT;

            ret = clone_op_state_init(cos, parent, &op, self_cloning);
            if ( ret )
            {
                gprintk(XENLOG_ERR, "Error calling clone_op_state_init() rc=%ld\n",
                        ret);
                break;
            }

            if ( page_sharing_info_pool_enabled )
            {
                if ( !d->arch.cloning.gfn_info_pool )
                {
                    ret = mem_sharing_pools_init(d);
                    if ( ret )
                        break;
                }
            }

            parent->arch.p2m->max_mapped_pfn = domain_get_maximum_gpfn(parent);//TODO
            parent->arch.cloning.triggered = true; /* TODO set on false when creating the parent domain */
        }

        ret = do_clone_vms(parent, self_cloning);
        if ( ret == -ERESTART )
        {
            ret = hypercall_create_continuation(
                    __HYPERVISOR_clone_op, "ih", cmd, arg);

            if ( !self_cloning )
                rcu_unlock_domain(parent);
        }
        else
        {
            if ( !self_cloning )
            {
                /* restore interrupt status */
                vcpu_info(parent->vcpu[0], evtchn_upcall_mask) =
                        cos->saved_evtchn_upcall_mask;
                domain_unpause(parent);
                rcu_unlock_domain(parent);
            }
        }
        break;
    }

    case CLONEOP_clone_completion:
    {
        clone_completion_t op;

        ret = -EPERM;
        if ( !cloning_enabled )
            break;

        ret = -EFAULT;
        if ( copy_from_guest(&op, arg, 1) )
            break;

        ret = completion_ring_done(op.id);
        break;
    }

    case CLONEOP_clone_cow:
    {
        clone_cow_t op;
        struct domain *d;

        ret = -EPERM;
        if ( !cloning_enabled )
            break;

        ret = -EFAULT;
        if ( copy_from_guest(&op, arg, 1) )
            break;

        ret = rcu_lock_live_remote_domain_by_id(op.domid, &d);
        if ( ret )
            break;

        ret = -EPERM;
        if ( !d->arch.cloning.fuzzing )
        {
            rcu_unlock_domain(d);
            break;
        }

        domain_pause(d);

        ret = do_domain_cow(d, op.vaddr, &op.mfn);
        if (ret == -1)
        {
            int x;
            x = 1;
        }

        domain_unpause(d);
        rcu_unlock_domain(d);
        break;
    }

    case CLONEOP_clone_reset:
    {
        clone_reset_t op;
        struct domain *d;

        ret = -EPERM;
        if ( !cloning_enabled )
            break;

        ret = -EFAULT;
        if ( copy_from_guest(&op, arg, 1) )
            break;

        ret = rcu_lock_live_remote_domain_by_id(op.domid, &d);
        if ( ret )
            break;

        ret = -EPERM;
        if ( !d->arch.cloning.fuzzing )
        {
            rcu_unlock_domain(d);
            break;
        }

        domain_pause(d);

        ret = do_reset_vm(d);

        domain_unpause(d);
        rcu_unlock_domain(d);
        break;
    }

    default:
        ret = -ENOSYS;
    }

    return ret;
}

int cloning_domctl(struct domain *d, struct xen_domctl_cloning_op *cloneop)
{
    int rc = 0;

    switch ( cloneop->op )
    {
    case XEN_DOMCTL_CLONING_ENABLE:
        d->arch.cloning.enabled = true;
        break;

    case XEN_DOMCTL_CLONING_DISABLE:
        d->arch.cloning.enabled = false;
        break;

    case XEN_DOMCTL_FUZZING_ENABLE:
        d->arch.cloning.fuzzing = true;
        d->arch.cloning.enabled = cloning_enabled;
        break;

    case XEN_DOMCTL_FUZZING_DISABLE:
        d->arch.cloning.fuzzing = false;
        if (d->arch.cloning.enabled)
            d->arch.cloning.enabled = false;
        break;

    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}
