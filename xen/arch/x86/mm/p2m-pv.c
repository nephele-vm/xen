/******************************************************************************
 * arch/x86/mm/p2m-pv.c
 *
 * physical-to-machine mappings for PV domains.
 *
 * Copyright (c) 2020 University Politehnica of Bucharest (Costin Lupu)
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

#include <xen/types.h>
#include <xen/domain_page.h>
#include <xen/mm.h>
#include <xen/sched.h>
#include <xen/trace.h>
#include <asm/shared.h>
#include <asm/p2m.h>
#include <asm/pv/p2m.h>
#include <asm/mem_sharing.h>

#include "mm-locks.h"


/* for P2M */
#ifdef __x86_64__
#define P2M_SHIFT       9
#else
#define P2M_SHIFT       10
#endif
#define P2M_ENTRIES     (1UL << P2M_SHIFT)
#define P2M_MASK        (P2M_ENTRIES - 1)
#define L1_P2M_SHIFT    P2M_SHIFT
#define L2_P2M_SHIFT    (2 * P2M_SHIFT)
#define L3_P2M_SHIFT    (3 * P2M_SHIFT)
#define L1_P2M_IDX(pfn) ((pfn) & P2M_MASK)
#define L2_P2M_IDX(pfn) (((pfn) >> L1_P2M_SHIFT) & P2M_MASK)
#define L3_P2M_IDX(pfn) (((pfn) >> L2_P2M_SHIFT) & P2M_MASK)
#define INVALID_P2M_ENTRY (~0UL)

#define L2_ENTRIES(n)          DIV_ROUND_UP(n, P2M_ENTRIES)
#define L3_ENTRIES(n)          DIV_ROUND_UP(n, (P2M_ENTRIES * P2M_ENTRIES))
#define L3_PAGES(n)            DIV_ROUND_UP(L3_ENTRIES(n), P2M_ENTRIES)


int p2m_fll_set_entry(struct domain *d, unsigned long gfn, unsigned long mfn)
{
    unsigned long max_pfn;
    unsigned long l3_list_mfn, *l3_list, l3_idx;
    unsigned long l2_list_mfn, *l2_list, l2_idx;
    unsigned long l1_list_mfn, *l1_list, l1_idx;
    int rc = 0;

    max_pfn = domain_get_maximum_gpfn(d);
    if ( gfn > max_pfn )
    {
        rc = -EINVAL;
        goto out;
    }

    l3_list_mfn = arch_get_pfn_to_mfn_frame_list_list(d);
    /* this function should be called only when cloning */
    ASSERT(mfn_valid(_mfn(l3_list_mfn)));

    l3_list = map_domain_page(_mfn(l3_list_mfn));
    l3_idx = L3_P2M_IDX(gfn);
    l2_list_mfn = l3_list[l3_idx];
    ASSERT(mfn_valid(_mfn(l2_list_mfn)));

    l2_list = map_domain_page(_mfn(l2_list_mfn));
    l2_idx = L2_P2M_IDX(gfn);
    l1_list_mfn = l2_list[l2_idx];
    ASSERT(mfn_valid(_mfn(l1_list_mfn)));

    l1_list = map_domain_page(_mfn(l1_list_mfn));
    l1_idx = L1_P2M_IDX(gfn);
    l1_list[l1_idx] = mfn;

    unmap_domain_page(l1_list);
    unmap_domain_page(l2_list);
    unmap_domain_page(l3_list);

    set_gpfn_from_mfn(mfn, gfn);

out:
    return rc;
}

int p2m_fll_get_entry(struct domain *d, unsigned long gfn, unsigned long *mfn)
{
    unsigned long max_pfn;
    unsigned long l3_list_mfn, *l3_list, l3_idx;
    unsigned long l2_list_mfn, *l2_list, l2_idx;
    unsigned long l1_list_mfn, *l1_list, l1_idx;
    int rc = 0;

    max_pfn = domain_get_maximum_gpfn(d);
    if ( gfn > max_pfn )
    {
        gdprintk(XENLOG_ERR, "Invalid max_pfn=%lx\n", max_pfn);
        rc = -EINVAL;
        goto out;
    }

    l3_list_mfn = arch_get_pfn_to_mfn_frame_list_list(d);
    if ( !mfn_valid(_mfn(l3_list_mfn)) )
    {
        gdprintk(XENLOG_ERR, "Invalid l3_list_mfn=%lx\n", l3_list_mfn);
        rc = -EINVAL;
        goto out;
    }

    l3_list = map_domain_page(_mfn(l3_list_mfn));
    l3_idx = L3_P2M_IDX(gfn);
    l2_list_mfn = l3_list[l3_idx];
    if ( !mfn_valid(_mfn(l2_list_mfn)) )
    {
        gdprintk(XENLOG_ERR, "Invalid l2_list_mfn=%lx\n", l2_list_mfn);
        rc = -EINVAL;
        goto out;
    }

    l2_list = map_domain_page(_mfn(l2_list_mfn));
    l2_idx = L2_P2M_IDX(gfn);
    l1_list_mfn = l2_list[l2_idx];
    if ( !mfn_valid(_mfn(l1_list_mfn)) )
    {
        gdprintk(XENLOG_ERR, "Invalid l1_list_mfn=%lx\n", l1_list_mfn);
        rc = -EINVAL;
        goto out;
    }

    l1_list = map_domain_page(_mfn(l1_list_mfn));
    l1_idx = L1_P2M_IDX(gfn);
    *mfn = l1_list[l1_idx];

    unmap_domain_page(l1_list);
    unmap_domain_page(l2_list);
    unmap_domain_page(l3_list);

out:
    return rc;
}

int p2m_fll_get_lists_num(struct domain *d)
{
    int n;
    unsigned long max_pfn, pfn_num;

    max_pfn = domain_get_maximum_gpfn(d);
    pfn_num = max_pfn + 1;

    n  = L2_ENTRIES(pfn_num);
    n += L3_ENTRIES(pfn_num);
    n += L3_PAGES(pfn_num); /* TODO do we support more than one L3 page? */

    return n;
}

int p2m_fll_clone(struct domain *d, struct domain *s,
        struct domain_clone_helper *dch)
{
    unsigned long sl3_list_mfn, *sl3_list;
    unsigned long dl3_list_mfn, *dl3_list;
    struct p2me {
        unsigned long pfn;
        unsigned long mfn;
    } *new_mfns;
    unsigned long new_mfns_num = 0, new_mfns_max;
    int rc = 0;

    TRACE_1D(TRC_CLONE_P2M, 1);

    new_mfns_max = p2m_fll_get_lists_num(s);

    new_mfns = xmalloc_array(struct p2me, new_mfns_max);
    if ( !new_mfns )
    {
        rc = -ENOMEM;
        goto out;
    }

    sl3_list_mfn = arch_get_pfn_to_mfn_frame_list_list(s);
    if ( !mfn_valid(_mfn(sl3_list_mfn)) )
    {
        rc = -EINVAL;
        goto out_free_new_mfns;
    }

    /* TODO support multiple l3 pages */
    dl3_list_mfn = dch_alloc_mfn(dch);
    ASSERT(mfn_valid(_mfn(dl3_list_mfn)));
    new_mfns[new_mfns_num].pfn = get_gpfn_from_mfn(sl3_list_mfn);
    new_mfns[new_mfns_num].mfn = dl3_list_mfn;
    new_mfns_num++;
    arch_set_pfn_to_mfn_frame_list_list(d, dl3_list_mfn);

    sl3_list = map_domain_page(_mfn(sl3_list_mfn));
    dl3_list = map_domain_page(_mfn(dl3_list_mfn));

    //TODO preemptible
    for ( int l3_idx = 0; l3_idx < L3_ENTRIES(dch->pfns_physmem.size); l3_idx++ )
    {
        unsigned long sl2_list_mfn, *sl2_list;
        unsigned long dl2_list_mfn, *dl2_list;
        unsigned long l2_list_max;

        sl2_list_mfn = sl3_list[l3_idx];
        if ( !mfn_valid(_mfn(sl2_list_mfn)) )
        {
            rc = -EINVAL;
            goto out_free_new_mfns;
        }

        dl2_list_mfn = dch_alloc_mfn(dch);
        ASSERT(mfn_valid(_mfn(dl2_list_mfn)));
        new_mfns[new_mfns_num].pfn = get_gpfn_from_mfn(sl2_list_mfn);
        new_mfns[new_mfns_num].mfn = dl2_list_mfn;
        new_mfns_num++;
        dl3_list[l3_idx] = dl2_list_mfn;

        sl2_list = map_domain_page(_mfn(sl2_list_mfn));
        dl2_list = map_domain_page(_mfn(dl2_list_mfn));

        l2_list_max = MIN(L2_ENTRIES(dch->pfns_physmem.size) - l3_idx * P2M_ENTRIES, P2M_ENTRIES);
        for ( int l2_idx = 0; l2_idx < l2_list_max; l2_idx++ )
        {
            unsigned long sl1_list_mfn, *sl1_list;
            unsigned long dl1_list_mfn, *dl1_list;
            unsigned long l1_list_max;

            sl1_list_mfn = sl2_list[l2_idx];
            if ( !mfn_valid(_mfn(sl1_list_mfn)) )
            {
                rc = -EINVAL;
                break;
            }

            dl1_list_mfn = dch_alloc_mfn(dch);
            ASSERT(mfn_valid(_mfn(dl1_list_mfn)));
            new_mfns[new_mfns_num].pfn = get_gpfn_from_mfn(sl1_list_mfn);
            new_mfns[new_mfns_num].mfn = dl1_list_mfn;
            new_mfns_num++;
            dl2_list[l2_idx] = dl1_list_mfn;

            sl1_list = map_domain_page(_mfn(sl1_list_mfn));
            dl1_list = map_domain_page(_mfn(dl1_list_mfn));

            l1_list_max = MIN(dch->pfns_physmem.size - l3_idx * P2M_ENTRIES * P2M_ENTRIES - l2_idx * P2M_ENTRIES, P2M_ENTRIES); //TODO
            memcpy(dl1_list, sl1_list, l1_list_max * sizeof(unsigned long));

            unmap_domain_page(sl1_list);
            unmap_domain_page(dl1_list);
        }

        unmap_domain_page(sl2_list);
        unmap_domain_page(dl2_list);

        if ( rc )
            break;
    }

    unmap_domain_page(sl3_list);
    unmap_domain_page(dl3_list);

    if ( rc )
        goto out_free_new_mfns;

    ASSERT(new_mfns_num == new_mfns_max);
    for ( unsigned long i = 0; i < new_mfns_num; i++ )
        dch_set_child_physmem_mfn(dch, new_mfns[i].pfn, new_mfns[i].mfn);

out_free_new_mfns:
    xfree(new_mfns);
out:
    TRACE_1D(TRC_CLONE_P2M, 0);
    return rc;
}

int p2m_fll_backup_save(struct domain *d)
{
    void **p2m_fll_linear;
    unsigned long count = 0, p2m_fll_pages_num, pfns_num;
    unsigned long sl3_list_mfn, *sl3_list;
    unsigned long *dl3_list;
    int rc = 0;

    p2m_fll_pages_num = p2m_fll_get_lists_num(d);

    p2m_fll_linear = xzalloc_array(void *, p2m_fll_pages_num);
    if ( !p2m_fll_linear )
    {
        rc = -ENOMEM;
        goto out;
    }

    sl3_list_mfn = arch_get_pfn_to_mfn_frame_list_list(d);
    if ( !mfn_valid(_mfn(sl3_list_mfn)) )
    {
        rc = -EINVAL;
        goto out_free_backup;
    }

    dl3_list = alloc_xenheap_pages(0, 0);
    if ( !dl3_list )
    {
        rc = -ENOMEM;
        goto out_free_backup;
    }
    p2m_fll_linear[0] = dl3_list;
    count++;

    sl3_list = map_domain_page(_mfn(sl3_list_mfn));
    pfns_num = domain_get_maximum_gpfn(d) + 1;

    for ( int l3_idx = 0; l3_idx < L3_ENTRIES(pfns_num); l3_idx++ )
    {
        unsigned long sl2_list_mfn, *sl2_list;
        unsigned long *dl2_list;
        unsigned long l2_list_max;

        sl2_list_mfn = sl3_list[l3_idx];
        if ( !mfn_valid(_mfn(sl2_list_mfn)) )
        {
            rc = -EINVAL;
            break;
        }

        dl3_list[l3_idx] = sl2_list_mfn;

        dl2_list = alloc_xenheap_pages(0, 0);
        if ( !dl2_list )
        {
            rc = -ENOMEM;
            break;
        }
        p2m_fll_linear[L3_PAGES(pfns_num) + l3_idx] = dl2_list;
        count++;

        sl2_list = map_domain_page(_mfn(sl2_list_mfn));

        l2_list_max = MIN(L2_ENTRIES(pfns_num) - l3_idx * P2M_ENTRIES, P2M_ENTRIES);
        for ( int l2_idx = 0; l2_idx < l2_list_max; l2_idx++ )
        {
            unsigned long sl1_list_mfn, *sl1_list;
            unsigned long *dl1_list;
            unsigned long l1_list_max;

            sl1_list_mfn = sl2_list[l2_idx];
            if ( !mfn_valid(_mfn(sl1_list_mfn)) )
            {
                rc = -EINVAL;
                break;
            }

            dl2_list[l2_idx] = sl1_list_mfn;

            dl1_list = alloc_xenheap_pages(0, 0);
            if ( !dl1_list )
            {
                rc = -ENOMEM;
                break;
            }
            p2m_fll_linear[L3_PAGES(pfns_num) + L3_ENTRIES(pfns_num) + l3_idx * P2M_ENTRIES + l2_idx] = dl1_list;
            count++;

            sl1_list = map_domain_page(_mfn(sl1_list_mfn));

            l1_list_max = MIN(pfns_num - l3_idx * P2M_ENTRIES * P2M_ENTRIES - l2_idx * P2M_ENTRIES, P2M_ENTRIES);
            memcpy(dl1_list, sl1_list, l1_list_max * sizeof(unsigned long));

            unmap_domain_page(sl1_list);
        }

        unmap_domain_page(sl2_list);

        if ( rc )
            break;
    }

    unmap_domain_page(sl3_list);

    if ( rc )
        goto out_free_backup;

    ASSERT(count == p2m_fll_pages_num);
    d->arch.cloning.fuzzing_backup.p2m_fll_linear = p2m_fll_linear;

out_free_backup:
    if ( rc )
    {
        if ( p2m_fll_linear )
        {
            for ( int i = 0; i < p2m_fll_pages_num; i++ )
            {
                if ( p2m_fll_linear[i] )
                    free_xenheap_pages(p2m_fll_linear[i], 0);
            }
            xfree(p2m_fll_linear);
        }
    }
out:
    return rc;
}

int p2m_fll_backup_restore(struct domain *d)
{
    void **p2m_fll_linear;
    unsigned long p2m_fll_pages_num, pfns_num;
    unsigned long sl3_list_mfn, *sl3_list;
    unsigned long *dl3_list;
    int rc = 0;

    if ( !d->arch.cloning.fuzzing_backup.p2m_fll_linear )
    {
        rc = -EINVAL;
        goto out;
    }

    p2m_fll_linear = d->arch.cloning.fuzzing_backup.p2m_fll_linear;
    p2m_fll_pages_num = p2m_fll_get_lists_num(d);

    sl3_list_mfn = arch_get_pfn_to_mfn_frame_list_list(d);
    ASSERT(mfn_valid(_mfn(sl3_list_mfn)));

    dl3_list = p2m_fll_linear[0];
    sl3_list = map_domain_page(_mfn(sl3_list_mfn));
    pfns_num = domain_get_maximum_gpfn(d) + 1;

    for ( int l3_idx = 0; l3_idx < L3_ENTRIES(pfns_num); l3_idx++ )
    {
        unsigned long sl2_list_mfn, *sl2_list;
        unsigned long *dl2_list;
        unsigned long l2_list_max;

        sl2_list_mfn = dl3_list[l3_idx];
        ASSERT(mfn_valid(_mfn(sl2_list_mfn)));
        sl3_list[l3_idx] = sl2_list_mfn;

        dl2_list = p2m_fll_linear[L3_PAGES(pfns_num) + l3_idx];
        sl2_list = map_domain_page(_mfn(sl2_list_mfn));

        l2_list_max = MIN(L2_ENTRIES(pfns_num) - l3_idx * P2M_ENTRIES, P2M_ENTRIES);
        for ( int l2_idx = 0; l2_idx < l2_list_max; l2_idx++ )
        {
            unsigned long sl1_list_mfn, *sl1_list;
            unsigned long *dl1_list;
            unsigned long l1_list_max;

            sl1_list_mfn = dl2_list[l2_idx];
            ASSERT(mfn_valid(_mfn(sl1_list_mfn)));
            sl2_list[l2_idx] = sl1_list_mfn;

            dl1_list = p2m_fll_linear[L3_PAGES(pfns_num) + L3_ENTRIES(pfns_num) + l3_idx * P2M_ENTRIES + l2_idx];
            sl1_list = map_domain_page(_mfn(sl1_list_mfn));

            l1_list_max = MIN(pfns_num - l3_idx * P2M_ENTRIES * P2M_ENTRIES - l2_idx * P2M_ENTRIES, P2M_ENTRIES);
            memcpy(sl1_list, dl1_list, l1_list_max * sizeof(unsigned long));

            unmap_domain_page(sl1_list);
        }

        unmap_domain_page(sl2_list);
    }

    unmap_domain_page(sl3_list);

out:
    return rc;
}

void p2m_fll_backup_delete(struct domain *d)
{
    void **p2m_fll_linear;
    unsigned long p2m_fll_pages_num;

    p2m_fll_linear = d->arch.cloning.fuzzing_backup.p2m_fll_linear;
    if ( p2m_fll_linear )
    {
        p2m_fll_pages_num = p2m_fll_get_lists_num(d);

        for ( int i = 0; i < p2m_fll_pages_num; i++ )
        {
            if ( p2m_fll_linear[i] )
                free_xenheap_pages(p2m_fll_linear[i], 0);
        }
        xfree(p2m_fll_linear);
        d->arch.cloning.fuzzing_backup.p2m_fll_linear = NULL;
    }
}

int p2m_pv_iter_start_l2(struct p2m_pv_iter *ppi)
{
    unsigned long l2_list_mfn;

    if ( ppi->l2_list )
        unmap_domain_page(ppi->l2_list);

    l2_list_mfn = ppi->l3_list[ppi->l3_idx];
    if ( !mfn_valid(_mfn(l2_list_mfn)) )
        return -1;

    ppi->l2_list = map_domain_page(_mfn(l2_list_mfn));
    ppi->l2_num = MIN(L2_ENTRIES(ppi->pfn_num) - ppi->l3_idx * P2M_ENTRIES, P2M_ENTRIES);
    ppi->l2_idx = 0;

    return 0;
}

int p2m_pv_iter_start_l1(struct p2m_pv_iter *ppi)
{
    unsigned long l1_list_mfn;

    if ( ppi->l1_list )
        unmap_domain_page(ppi->l1_list);

    l1_list_mfn = ppi->l2_list[ppi->l2_idx];
    if ( !mfn_valid(_mfn(l1_list_mfn)) )
        return -1;

    ppi->l1_list = map_domain_page(_mfn(l1_list_mfn));
    ppi->l1_num = MIN(ppi->pfn_num - ppi->l3_idx * P2M_ENTRIES * P2M_ENTRIES - ppi->l2_idx * P2M_ENTRIES, P2M_ENTRIES);//TODO
    ppi->l1_idx = 0;

    return 0;
}

int p2m_pv_iter_start(struct domain *d, struct p2m_pv_iter *ppi)
{
    unsigned long l3_list_mfn;
    int rc;

    ppi->pfn_num = domain_get_maximum_gpfn(d) + 1;

    l3_list_mfn = arch_get_pfn_to_mfn_frame_list_list(d);
    if ( !mfn_valid(_mfn(l3_list_mfn)) )
    {
        rc = -1;
        goto out;
    }

    ppi->l3_list = map_domain_page(_mfn(l3_list_mfn));
    ppi->l3_num = L3_ENTRIES(ppi->pfn_num);
    ppi->l3_idx = 0;

    ppi->l2_list = NULL;
    rc = p2m_pv_iter_start_l2(ppi);
    if ( rc )
        goto out;

    ppi->l1_list = NULL;
    rc = p2m_pv_iter_start_l1(ppi);
    if ( rc )
        goto out;

out:
    return rc;
}

/*
 * Page table
 */

struct pt_pv_iter {
    l4_pgentry_t *l4t, *l4e;
    l3_pgentry_t *l3t, *l3e;
    l2_pgentry_t *l2t, *l2e;
    l1_pgentry_t *l1t, *l1e;
    unsigned long l4i, l3i, l2i, l1i;
    mfn_t l4mfn, l3mfn, l2mfn, l1mfn;
};

#define DECLARE_PT_PV_ITER_INIT(lvl) \
static int pt_pv_iter_l##lvl##_init(struct pt_pv_iter *iter, mfn_t mfn, unsigned long index) \
{ \
    int rc = 0; \
    \
    iter->l##lvl##t = map_domain_page(mfn); \
    iter->l##lvl##i = index; \
    iter->l##lvl##e = iter->l##lvl##t + iter->l##lvl##i; \
    iter->l##lvl##mfn = mfn; \
    \
    if ( (l##lvl##e_get_flags(*iter->l##lvl##e) & _PAGE_PRESENT) == 0 ) \
        rc = -ENOENT; \
    \
    return rc; \
}

DECLARE_PT_PV_ITER_INIT(4);
DECLARE_PT_PV_ITER_INIT(3);
DECLARE_PT_PV_ITER_INIT(2);
DECLARE_PT_PV_ITER_INIT(1);

static int pt_pv_iter_start(struct pt_pv_iter *iter,
        struct domain *d, unsigned long va)
{
    struct vcpu *v = d->vcpu[0];
    int rc;

    mfn_t mfn = (v->arch.flags & TF_kernel_mode
                      ? pagetable_get_mfn(v->arch.guest_table)
                      : pagetable_get_mfn(v->arch.guest_table_user));


    rc = pt_pv_iter_l4_init(iter, mfn, l4_table_offset(va));
    if ( rc )
        goto out;

    mfn = l4e_get_mfn(*iter->l4e);
    rc = pt_pv_iter_l3_init(iter, mfn, l3_table_offset(va));
    if ( rc )
        goto out;

    mfn = l3e_get_mfn(*iter->l3e);
    rc = pt_pv_iter_l2_init(iter, mfn, l2_table_offset(va));
    if ( rc )
        goto out;

    mfn = l2e_get_mfn(*iter->l2e);
    rc = pt_pv_iter_l1_init(iter, mfn, l1_table_offset(va));
    if ( rc )
        goto out;

out:
    return rc;
}

static void pt_pv_iter_stop(struct pt_pv_iter *iter)
{
    unmap_domain_page(iter->l1t);
    unmap_domain_page(iter->l2t);
    unmap_domain_page(iter->l3t);
    unmap_domain_page(iter->l4t);
}

static int pt_pv_iter_next(struct pt_pv_iter *iter)
{
    mfn_t mfn;
    int rc = 0;

    if ( likely(iter->l1i < L1_PAGETABLE_ENTRIES - 1) )
    {
        iter->l1i++;
        iter->l1e = iter->l1t + iter->l1i;
    }
    else
    {
        if ( likely(iter->l2i < L2_PAGETABLE_ENTRIES - 1) )
        {
            iter->l2i++;
            iter->l2e = iter->l2t + iter->l2i;
        }
        else
        {
            if ( likely(iter->l3i < L3_PAGETABLE_ENTRIES - 1) )
            {
                iter->l3i++;
                iter->l3e = iter->l3t + iter->l3i;
            }
            else
            {
                if ( likely(iter->l4i < L4_PAGETABLE_ENTRIES - 1) )
                {
                    iter->l4i++;
                    iter->l4e = iter->l4t + iter->l4i;
                }
                else
                {
                    rc = -EINVAL;
                    goto out;
                }

                mfn = l4e_get_mfn(*iter->l4e);
                unmap_domain_page(iter->l3t);
                rc = pt_pv_iter_l3_init(iter, mfn, 0);
            }

            mfn = l3e_get_mfn(*iter->l3e);
            unmap_domain_page(iter->l2t);
            rc = pt_pv_iter_l2_init(iter, mfn, 0);
        }

        mfn = l2e_get_mfn(*iter->l2e);
        unmap_domain_page(iter->l1t);
        rc = pt_pv_iter_l1_init(iter, mfn, 0);
    }

out:
    return rc;
}

int cloning_copy_special_pages(struct domain_clone_helper *dch, unsigned long va, unsigned long pages_num)
{
    struct pt_pv_iter iter;
    mfn_t smfn;
    unsigned long gpfn, dmfn;
    int rc = 0, i;

    for ( rc = pt_pv_iter_start(&iter, dch->parent.domain, va), i = 0;
          rc == 0;
          rc = pt_pv_iter_next(&iter) )
    {
        smfn = l1e_get_mfn(*iter.l1e);
        gpfn = get_gpfn_from_mfn(mfn_x(smfn));

        if ( test_bit(gpfn, dch->pfns_physmem.bm) )
        {
            rc = p2m_fll_get_entry(dch->child.domain, gpfn, &dmfn);
            if ( rc )
            {
                gdprintk(XENLOG_ERR, "Error p2m_fll_get_entry()=%d\n", rc);
                break;
            }
        }
        else
            dch_replace_child_mfn(dch, mfn_x(smfn), &dmfn);

        if ( !mfn_valid(_mfn(dmfn)) )
        {
            gdprintk(XENLOG_ERR, "Invalid mfn=%lx va=%lx i=%d physmem=%x\n",
                dmfn, va, i, test_bit(gpfn, dch->pfns_physmem.bm));
            rc = -1;
            break;
        }

        copy_domain_page(_mfn(dmfn), smfn);

        if ( ++i == pages_num )
            break;
    }

    pt_pv_iter_stop(&iter);

    return rc;
}

static
int pt_pv_l1e_get(struct domain *d, unsigned long va, l1_pgentry_t **ppl1e,
        struct page_info **pgl1pg, mfn_t *pgl1mfn)
{
    struct pt_pv_iter iter;
    l1_pgentry_t *pl1e = NULL;
    mfn_t gl1mfn;
    struct page_info *gl1pg;
    int rc;

    rc = pt_pv_iter_start(&iter, d, va);
    if ( rc )
        goto out;

    rc = -EINVAL;
    pl1e = iter.l1e;
    if ( unlikely(!pl1e) )
        goto out_iter_stop;

    gl1mfn = iter.l1mfn;
    gfn_lock(p2m_get_hostp2m(d), gl1mfn, 0);

    gl1pg = get_page_from_mfn(gl1mfn, d);
    if ( unlikely(!gl1pg) )
        goto out_iter_stop;

    if ( !page_lock(gl1pg) )
    {
        put_page(gl1pg);
        goto out_iter_stop;
    }

    if ( (gl1pg->u.inuse.type_info & PGT_type_mask) != PGT_l1_page_table )
    {
        page_unlock(gl1pg);
        put_page(gl1pg);
        goto out_iter_stop;
    }

    *ppl1e = pl1e;
    *pgl1pg = gl1pg;
    if ( pgl1mfn )
        *pgl1mfn = gl1mfn;

    rc = 0;

out_iter_stop:
//    pt_pv_iter_stop(&iter);
    unmap_domain_page(iter.l2t);
    unmap_domain_page(iter.l3t);
    unmap_domain_page(iter.l4t);
out:
    if ( rc )
    {
        if ( pl1e )
            unmap_domain_page(pl1e);
    }
    return rc;
}

static
void pt_pv_l1e_put(struct domain *d, l1_pgentry_t *pl1e,
        struct page_info *gl1pg, mfn_t gl1mfn)
{
    page_unlock(gl1pg);
    put_page(gl1pg);
    gfn_unlock(p2m_get_hostp2m(d), gl1mfn, 0);
    unmap_domain_page(pl1e);
}

/*
 * TODO this is very similar to do_cow()
 */
#if 0
#define COW_LOG(fmt, ...) printk(fmt, __VA_ARGS__)
#else
#define COW_LOG(fmt, ...)
#endif

int do_domain_cow(struct domain *d, unsigned long va, unsigned long *new_mfn)
{
    struct vcpu *v = d->vcpu[0];
    struct page_info *gl1pg, *page;
    mfn_t gl1mfn = INVALID_MFN_INITIALIZER;
    l1_pgentry_t *pl1e, nl1e;
    unsigned long gmfn, smfn, cmfn = 0;
    int rc;

//    TRACE_1D(TRC_CLONE_COW, 1);

    rc = pt_pv_l1e_get(d, va, &pl1e, &gl1pg, &gl1mfn);
    if ( rc )
        goto out;

    smfn = l1e_get_pfn(*pl1e);
    gmfn = get_gpfn_from_mfn(smfn);
    if ( gmfn == INVALID_M2P_ENTRY )
    {
        rc = -ESRCH;
        goto out_l1e_put;
    }

    rc = mem_sharing_unshare_page_pv(d, gmfn, smfn, false, &cmfn);
    if ( rc ) {
//        gdprintk(XENLOG_ERR, "Could not unshare gmfn=%lx\n", gmfn);
        goto out_l1e_put;
    }

    COW_LOG("%s domid=%d addr=%lx rip=%lx rsp=%lx",
        __FUNCTION__, d->domain_id, va, v->arch.user_regs.rip, v->arch.user_regs.rsp);

    /* set type on new page */
    page = mfn_to_page(_mfn(cmfn));
    BUG_ON(page == NULL);
    if ( !get_page_and_type(page, d, PGT_writable_page) )
        BUG();

    /* new entry */
    nl1e = l1e_from_pfn(cmfn, l1e_get_flags(*pl1e));
    l1e_add_flags(nl1e, _PAGE_RW);

    paging_write_guest_entry(v,
        &l1e_get_intpte(*pl1e), l1e_get_intpte(nl1e), gl1mfn);

    rc = p2m_fll_set_entry(d, gmfn, cmfn);
    if ( rc )
    {
        gdprintk(XENLOG_ERR, "Error calling p2m_fll_set_entry(%d, %lx, %lx)=%d\n",
                d->domain_id, gmfn, cmfn, rc);
        goto out_l1e_put;
    }

    atomic_inc(&d->cow_pages);

    if ( new_mfn )
        *new_mfn = cmfn;

    COW_LOG(" shr_pages=%d cow_pages=%d gmfn=%lx mfn=%lx new mfn=%lx\n",
        atomic_read(&d->shr_pages), atomic_read(&d->cow_pages),
        gmfn, smfn, cmfn);

out_l1e_put:
    pt_pv_l1e_put(d, pl1e, gl1pg, gl1mfn);
out:
//    TRACE_1D(TRC_CLONE_COW, 0);
    return rc;
}

//#define PT_CLONING_STATS 1

#if PT_CLONING_STATS
static struct pt_cloning_stats {
    unsigned long l4e_present;
    unsigned long l3e_present;
    unsigned long l2e_present;
    unsigned long l1e_present;
    unsigned long l1e_regular;
    unsigned long l1e_pt;
} ptc_stats;

#define PT_CLONING_STATS_INIT() \
    memset(&ptc_stats, 0, sizeof(ptc_stats));

#define PT_CLONING_STATS_INC(field)   (ptc_stats.field++)

static void pt_cloning_stats_print(void)
{
    printk("\tl4e_present=%lu\n", ptc_stats.l4e_present);
    printk("\tl3e_present=%lu\n", ptc_stats.l3e_present);
    printk("\tl2e_present=%lu\n", ptc_stats.l2e_present);
    printk("\tl1e_present=%lu\n", ptc_stats.l1e_present);
    printk("\tl1e_regular=%lu\n", ptc_stats.l1e_regular);
    printk("\tl1e_pt=%lu\n", ptc_stats.l1e_pt);
}
#define PT_CLONING_STATS_PRINT() \
    pt_cloning_stats_print()

#else

#define PT_CLONING_STATS_INIT()
#define PT_CLONING_STATS_INC(field)
#define PT_CLONING_STATS_PRINT()
#endif

extern
int gnttab_page_clone(struct domain_clone_helper *dch, unsigned long mfn, unsigned long *dmfn);

extern
unsigned long p2m_type_to_flags(const struct p2m_domain *p2m,
                                       p2m_type_t t,
                                       mfn_t mfn,
                                       unsigned int level);


static void l1e_clone(l1_pgentry_t *dpl1e, l1_pgentry_t *spl1e,
        unsigned long gl1mfn, struct domain_clone_helper *dch)
{
    struct domain *parent = dch->parent.domain;
    struct domain *child = dch->child.domain;
    unsigned long gpfn, smfn, dmfn;
    struct page_info *page;
    u32 flags;
    int rc;

    smfn  = l1e_get_pfn(*spl1e);
    flags = l1e_get_flags(*spl1e);

    page = mfn_to_page(_mfn(smfn));//TODO lock page or smth
    ASSERT(page != NULL);

    if ( unlikely(is_xen_heap_page(page)) )
    {
        /* grant table pages */
        if ( gnttab_page_clone(dch, smfn, &dmfn) )
        {
            *dpl1e = l1e_from_pfn(dmfn, flags);
        }
        /* shared info */
        else if ( smfn == virt_to_mfn(parent->shared_info) )
        {
            dmfn = virt_to_mfn(child->shared_info);
            *dpl1e = l1e_from_pfn(dmfn, flags);
        }
        else
            BUG();
        rc = get_page_from_l1e(*dpl1e, child, child);
        ASSERT(rc == 0);
        return;
    }

    /* skip page table pages */
    switch ( page->u.inuse.type_info & PGT_type_mask )
    {
    case PGT_l1_page_table:
    case PGT_l2_page_table:
    case PGT_l3_page_table:
    case PGT_l4_page_table:
        /* TODO deal with this in a more serious manner */
        dpl1e->l1 = 0;
        PT_CLONING_STATS_INC(l1e_pt);
        return;
    }

    gpfn = get_gpfn_from_mfn(smfn);
    /* own pages */
    if ( unlikely(test_bit(gpfn, dch->pfns_physmem.bm)) )
    {
        rc = p2m_fll_get_entry(child, gpfn, &dmfn);
        ASSERT(rc == 0);
        *dpl1e = l1e_from_pfn(dmfn, flags);
        rc = get_page_from_l1e(*dpl1e, child, child);
        ASSERT(rc == 0);
    }
    else
    {
        unsigned long type_count = page->u.inuse.type_info & PGT_count_mask;
        bool writable = flags & _PAGE_RW;
        bool shared = test_bit(gpfn, dch->pfns_shared.bm);
        bool restore_rw = false;
        p2m_type_t l1t;
        bool l1t_is_shared;

        if ( writable && (!shared || type_count == 1) )
        {
            put_page_type(page);
            spl1e->l1 &= ~_PAGE_RW;
            flags &= ~_PAGE_RW;

            /*
             * Special case: writable shared pages. This is used for "IPC"
             * communication between related domains. It is the first time
             * Xen supports shared pages as writable as well. A writable
             * shared page needs to be marked as read-only only before
             * setting it as shared the first time.
             */
            if ( shared )
                restore_rw = true;
        }

        l1t = p2m_flags_to_type(flags & ~_PAGE_GUEST_KERNEL);
        l1t_is_shared = p2m_is_shared(l1t);

        if ( !l1t_is_shared )
        {
            /* clear type count if not already shared */
            /* we need to reach type_count=0 and count_info=1 */
            if ( type_count > 1 )
            {
                for ( int i = 1; i < type_count; i++ )
                    put_page_and_type(page);
            }
            else
                put_page(page);
        }

        rc = mem_sharing_share_to_child(parent, child, smfn, gpfn, l1t,
                shared ? writable : false);
        ASSERT(rc == 0);

        if ( !l1t_is_shared )
        {
            /* update source l1 entry */
            *spl1e = l1e_from_pfn(smfn,
                    p2m_type_to_flags(NULL, p2m_ram_shared, _mfn(smfn), 0));

            /* restore type count */
            if ( type_count > 1 )
            {
                for ( int i = 1; i < type_count; i++ )
                {
                    rc = get_page_and_type(page, dom_cow, PGT_shared_page);
                    ASSERT(rc != 0);
                }
            }
        }

        if ( restore_rw )
            spl1e->l1 |= _PAGE_RW;

        *dpl1e = *spl1e;

        PT_CLONING_STATS_INC(l1e_regular);
    }
}

static void l1e_reset(l1_pgentry_t *dpl1e, l1_pgentry_t *spl1e,
        struct domain_clone_helper *dch)
{
    struct domain *parent = dch->parent.domain;
    struct domain *child = dch->child.domain;
    unsigned long gpfn, smfn, dmfn, type_info;
    struct page_info *page, *dpage;
    u32 flags, dflags;
    p2m_type_t l1t;
    shr_handle_t sh;
    int rc;

    dflags = l1e_get_flags(*dpl1e);

    l1t = p2m_flags_to_type(dflags & ~_PAGE_GUEST_KERNEL);
    if ( p2m_is_shared(l1t) )
        return;

    smfn  = l1e_get_pfn(*spl1e);
    flags = l1e_get_flags(*spl1e);

    page = mfn_to_page(_mfn(smfn));//TODO lock page or smth
    ASSERT(page != NULL);

    /* TODO does any heap page change? */
    if ( unlikely(is_xen_heap_page(page)) )
        return;

    /* skip page table pages */
    type_info = page->u.inuse.type_info & PGT_type_mask;
    if ( PGT_l1_page_table <= type_info && type_info <= PGT_l4_page_table )
        return;

    gpfn = get_gpfn_from_mfn(smfn);
    /* own pages */
    if ( unlikely(test_bit(gpfn, dch->pfns_physmem.bm)) )
    {
        /* TODO support IO pages */
    }
    else
    {
        unsigned long type_count = page->u.inuse.type_info & PGT_count_mask;
        bool writable = flags & _PAGE_RW;
        bool shared = test_bit(gpfn, dch->pfns_shared.bm);

        /* TODO IPC pages? */


        l1t = p2m_flags_to_type(flags & ~_PAGE_GUEST_KERNEL);

        dmfn = l1e_get_pfn(*dpl1e);
        dpage = mfn_to_page(_mfn(dmfn));//TODO lock page or smth
        ASSERT(dpage != NULL);
        put_page_and_type(dpage);
        free_domheap_page(dpage);

        /* clear type count if not already shared */
        if ( !p2m_is_shared(l1t) )//TODO maybe not needed
        {
            /* we need to reach type_count=0 and count_info=1 */
            if ( type_count > 1 )
            {
                for ( int i = 1; i < type_count; i++ )
                    put_page_and_type(page);
            }
            else
                put_page(page);
        }

        gfn_lock(p2m_get_hostp2m(parent), gpfn, 0);
        gfn_lock(p2m_get_hostp2m(child), gpfn, 0);

        rc = mem_sharing_nominate_page(parent, _gfn(gpfn),
                _mfn(smfn), l1t, p2m_access_n /* TODO this is not used now */,
                0, shared ? writable : false, false, &sh);
        ASSERT(rc == 0);
        *spl1e = l1e_from_pfn(smfn,
                p2m_type_to_flags(NULL, p2m_ram_shared, _mfn(smfn), 0));
        rc = mem_sharing_add_to_physmap(parent, _mfn(smfn), sh, child, gpfn, true);
        ASSERT(rc == 0);

        gfn_unlock(p2m_get_hostp2m(child), gpfn, 0);
        gfn_unlock(p2m_get_hostp2m(parent), gpfn, 0);

        /* restore type count */
        if ( !p2m_is_shared(l1t) )
        {
            if ( type_count > 1 )
            {
                for ( int i = 1; i < type_count; i++ )
                {
                    rc = get_page_and_type(page, dom_cow, PGT_shared_page);
                    ASSERT(rc != 0);
                }
            }
        }

        *dpl1e = *spl1e;

#if CONFIG_MEMSHR_STATS
        child->memshr_stats.fuzz.sum_reset_pages++;
#endif
    }
}

//TODO use paging_lock(d); l4

#define DEFINE_lxtab_clone(lvl, nxt_lvl, entries_num) \
static void l##lvl##tab_clone( \
        unsigned long dl##lvl##tab_mfn, \
        unsigned long sl##lvl##tab_mfn, \
        struct domain_clone_helper *dch) \
{ \
    l##lvl##_pgentry_t *sl##lvl##tab, *dl##lvl##tab; \
    \
    sl##lvl##tab = map_domain_page(_mfn(sl##lvl##tab_mfn)); \
    dl##lvl##tab = map_domain_page(_mfn(dl##lvl##tab_mfn)); \
    for ( int i = 0; i < (entries_num); i++ ) \
    { \
        uint32_t flags = l##lvl##e_get_flags(sl##lvl##tab[i]); \
        if ( flags & _PAGE_PRESENT ) { \
            LXE_CLONE_PRESENT(lvl, nxt_lvl); \
            PT_CLONING_STATS_INC(l##lvl##e_present); \
        } else \
            dl##lvl##tab[i] = sl##lvl##tab[i]; \
    } \
    LXTAB_POST_LOOP(); \
    unmap_domain_page(dl##lvl##tab); \
    unmap_domain_page(sl##lvl##tab); \
}

#define DEFINE_lxtab_reset(lvl, nxt_lvl, entries_num) \
static void l##lvl##tab_reset( \
        unsigned long dl##lvl##tab_mfn, \
        unsigned long sl##lvl##tab_mfn, \
        struct domain_clone_helper *dch) \
{ \
    l##lvl##_pgentry_t *sl##lvl##tab, *dl##lvl##tab; \
    \
    sl##lvl##tab = map_domain_page(_mfn(sl##lvl##tab_mfn)); \
    dl##lvl##tab = map_domain_page(_mfn(dl##lvl##tab_mfn)); \
    for ( int i = 0; i < (entries_num); i++ ) \
    { \
        uint32_t flags = l##lvl##e_get_flags(sl##lvl##tab[i]); \
        if ( flags & _PAGE_PRESENT ) \
		    LXE_RESET_PRESENT(lvl, nxt_lvl); \
        else \
            dl##lvl##tab[i] = sl##lvl##tab[i]; \
    } \
    unmap_domain_page(dl##lvl##tab); \
    unmap_domain_page(sl##lvl##tab); \
}



/********************************* L1 *****************************************/

#define LXE_CLONE_PRESENT(lvl, nxt_lvl) \
    l1e_clone(&dl1tab[i], &sl1tab[i], sl1tab_mfn, dch)

#define LXTAB_POST_LOOP()  /* nothing */

DEFINE_lxtab_clone(1, 0, L1_PAGETABLE_ENTRIES);



#define LXE_RESET_PRESENT(lvl, nxt_lvl) \
    l1e_reset(&dl1tab[i], &sl1tab[i], dch)

DEFINE_lxtab_reset(1, 0, L1_PAGETABLE_ENTRIES);

/********************************* L2, L3 *************************************/

#undef  LXE_CLONE_PRESENT
#define LXE_CLONE_PRESENT(lvl, nxt_lvl) \
({ \
    unsigned long smfn, dmfn; \
    struct page_info *page; \
    int rc; \
    \
    smfn = l##lvl##e_get_pfn(sl##lvl##tab[i]); \
    dch_replace_child_mfn(dch, smfn, &dmfn); \
    dl##lvl##tab[i] = l##lvl##e_from_pfn(dmfn, flags); \
    l##nxt_lvl##tab_clone(dmfn, smfn, dch); \
    page = mfn_to_page(_mfn(dmfn)); \
    ASSERT(page != NULL); \
    page->nr_validated_ptes = L##nxt_lvl##_PAGETABLE_ENTRIES; \
    page->u.inuse.type_info |= PGT_partial; \
    rc = get_page_from_l##lvl##e(dl##lvl##tab[i], _mfn(dl##lvl##tab_mfn), dch->child.domain, 0); \
    ASSERT(rc == 0); \
    page->u.inuse.type_info &= ~PGT_partial; \
})

DEFINE_lxtab_clone(2, 1, L2_PAGETABLE_ENTRIES);
DEFINE_lxtab_clone(3, 2, L3_PAGETABLE_ENTRIES);



#undef  LXE_RESET_PRESENT
#define LXE_RESET_PRESENT(lvl, nxt_lvl) \
({ \
    unsigned long smfn, dmfn; \
    \
    smfn = l##lvl##e_get_pfn(sl##lvl##tab[i]); \
    dmfn = l##lvl##e_get_pfn(dl##lvl##tab[i]); \
    l##nxt_lvl##tab_reset(dmfn, smfn, dch); \
})

DEFINE_lxtab_reset(2, 1, L2_PAGETABLE_ENTRIES);
DEFINE_lxtab_reset(3, 2, L3_PAGETABLE_ENTRIES);

/********************************* L4 *****************************************/

#undef  LXTAB_POST_LOOP
#define LXTAB_POST_LOOP() \
({ \
    unsigned long gpfn, smfn, dmfn; \
    int rc; \
    \
    dl4tab[256] = sl4tab[256]; \
    dl4tab[261] = sl4tab[261]; \
    dl4tab[262] = sl4tab[262]; \
    \
    smfn = l4e_get_pfn(sl4tab[258]); \
    gpfn = get_gpfn_from_mfn(smfn); \
    rc = p2m_fll_get_entry(dch->parent.domain, gpfn, &dmfn); \
    ASSERT(rc == 0); \
    dl4tab[258] = l4e_from_pfn(dmfn, l4e_get_flags(sl4tab[258])); \
    \
    for (int i = 263; i < L4_PAGETABLE_ENTRIES; i++) \
        dl4tab[i] = sl4tab[i]; \
})

DEFINE_lxtab_clone(4, 3, L4_PAGETABLE_ENTRIES / 2);


DEFINE_lxtab_reset(4, 3, L4_PAGETABLE_ENTRIES / 2);



static int pin_table(struct domain *child, unsigned long mfn)
{
    struct page_info *page;
    int rc;

    page = mfn_to_page(_mfn(mfn));
    ASSERT(page != NULL);
    rc = get_page(page, child);
    ASSERT(rc == 1);
    page->nr_validated_ptes = L4_PAGETABLE_ENTRIES;
    page->u.inuse.type_info |= PGT_partial;

    do
    {
        rc = get_page_type_preemptible(page, PGT_l4_page_table);
    } while ( rc == -ERESTART || rc == -EINTR );

    page->u.inuse.type_info &= ~PGT_partial;

    rc = test_and_set_bit(_PGT_pinned, &page->u.inuse.type_info);
    ASSERT(rc == 0);

    /* A page is dirtied when its pin status is set. */
    paging_mark_dirty(child, page_to_mfn(page));

    return rc;
}

extern int mem_sharing_do_p2m_set_entry;

void page_table_clone(unsigned long dmfn, unsigned long smfn,
        struct domain_clone_helper *dch)
{
    struct domain *parent, *child;
    struct p2m_domain *parent_p2m, *child_p2m;

    PT_CLONING_STATS_INIT();

    parent = dch->parent.domain;
    parent_p2m = p2m_get_hostp2m(parent);

    child = dch->child.domain;
    child_p2m = p2m_get_hostp2m(child);

    if ( !pagetable_get_pfn(p2m_get_pagetable(child_p2m)) )
        child_p2m->phys_table = pagetable_from_mfn(_mfn(dmfn));

    p2m_lock(parent_p2m);
    p2m_lock(child_p2m);

    mem_sharing_do_p2m_set_entry = 0;
    l4tab_clone(dmfn, smfn, dch);
    mem_sharing_do_p2m_set_entry = 1;

    p2m_unlock(child_p2m);
    p2m_unlock(parent_p2m);

    pin_table(child, dmfn);

    PT_CLONING_STATS_PRINT();
}

void page_table_reset(unsigned long dmfn, unsigned long smfn,
        struct domain_clone_helper *dch)
{
    mem_sharing_do_p2m_set_entry = 0;
    l4tab_reset(dmfn, smfn, dch);
    mem_sharing_do_p2m_set_entry = 1;
}

