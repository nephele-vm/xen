/*
 * dump_mem.c
 *
 *  Created on: May 14, 2019
 *      Author: wolf
 */
#include <xen/types.h>
#include <xen/domain_page.h>
#include <xen/spinlock.h>
#include <xen/rwlock.h>
#include <xen/mm.h>
#include <xen/grant_table.h>
#include <xen/sched.h>
#include <xen/rcupdate.h>
#include <xen/guest_access.h>
#include <xen/vm_event.h>
#include <xen/keyhandler.h>
#include <asm/page.h>
#include <asm/string.h>
#include <asm/p2m.h>
#include <asm/altp2m.h>
#include <asm/atomic.h>
#include <asm/event.h>
#include <xsm/xsm.h>

#include "mm-locks.h"


#if 1
#undef P2M_PRINTK
#define P2M_PRINTK(f, a...) \
    printk("p2m: %s(): " f, __func__, ##a)
#endif

#if 0
#undef mfn_to_page
#define mfn_to_page(_m) __mfn_to_page(mfn_x(_m))
#undef mfn_valid
#define mfn_valid(_mfn) __mfn_valid(mfn_x(_mfn))
#undef page_to_mfn
#define page_to_mfn(_pg) _mfn(__page_to_mfn(_pg))
#endif

#define MYSTR_DATA_SIZE 128
struct mystr {
    char *data;
    int pos;
};
static void add_to_str(struct mystr *s, const char *v)
{
    if ( s->pos > 0 )
        s->data[s->pos++] = '|';
    memcpy(&s->data[s->pos], v, strlen(v));
    s->pos += strlen(v);
    s->data[s->pos] = '\0';
}

/********* COUNT_INFO *********/
struct report_key_count_info {
    unsigned long mfn, gfn, count_info;
};
static struct report_key_count_info report_key_count_info_ctor(unsigned long mfn, unsigned long gfn, unsigned long count_info)
{
    struct report_key_count_info k = {
        .mfn = mfn,
        .gfn = gfn,
        .count_info = count_info,
    };
    return k;
}
static int delta_is_0_count_info(struct report_key_count_info *first, struct report_key_count_info *last)
{
    return (first->gfn == last->gfn && first->count_info == last->count_info);
}
static int delta_is_1_count_info(struct report_key_count_info *first, struct report_key_count_info *last)
{
    return (first->gfn + 1 == last->gfn && first->count_info == last->count_info);
}
static void print_count_info(unsigned long count_info)
{
    char mystr_data[MYSTR_DATA_SIZE];
    struct mystr s;

    mystr_data[0] = '\0';
    s.data = mystr_data;
    s.pos = 0;

    if ( (count_info & PGC_allocated) == PGC_allocated )
        add_to_str(&s, "PGC_allocated");
    if ( (count_info & PGC_xen_heap) == PGC_xen_heap )
        add_to_str(&s, "PGC_xen_heap");
    if ( (count_info & PGC_page_table) == PGC_page_table )
        add_to_str(&s, "PGC_page_table");

    /* 3-bit PAT/PCD/PWT cache-attribute hint. */
    //TODO #define PGC_cacheattr_mask PG_mask(7, 6)

    if ( (count_info & PGC_broken) == PGC_broken )
        add_to_str(&s, "PGC_broken");

    if ( (count_info & PGC_state) )
    {
        if ( (count_info & PGC_state_free) == PGC_state_free )
            add_to_str(&s, "PGC_state_free");
        else if ( (count_info & PGC_state_offlined) == PGC_state_offlined )
            add_to_str(&s, "PGC_state_offlined");
        else if ( (count_info & PGC_state_offlining) == PGC_state_offlining )
            add_to_str(&s, "PGC_state_offlining");
        else if ( (count_info & PGC_state_inuse) == PGC_state_inuse )
            add_to_str(&s, "PGC_state_inuse");
    }
    printk("count_info=%s|count=%lu (%#lx)", s.data, (count_info & PGT_count_mask), count_info);
}
static void print_count_info_cycle(struct report_key_count_info *first, struct report_key_count_info *last, int cycle_len)
{
    P2M_PRINTK("mfn=%#lx, gfn=%#lx, ", first->mfn, first->gfn);
    print_count_info(first->count_info);

    if ( !delta_is_0_count_info(first, last) )
    {
        printk("\n");
        if ( !delta_is_1_count_info(first, last) )
            P2M_PRINTK("...\n");
        P2M_PRINTK("mfn=%#lx, gfn=%#lx, ", last->mfn, last->gfn);
        print_count_info(last->count_info);
    }
    printk(" (cycle_len=%d)\n", cycle_len);
}

static void audit_p2m_domain_count_info(struct domain *d)
{
    struct page_info *page;
    unsigned long mfn, gfn;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    struct report_key_count_info first, last, crnt;
    int started = 0, cycle_len = 0;

    p2m_lock(p2m);
    pod_lock(p2m);

    spin_lock(&d->page_alloc_lock);
    page_list_for_each ( page, &d->page_list )
    {
        mfn = mfn_x(page_to_mfn(page));
        gfn = get_gpfn_from_mfn(mfn);

        crnt = report_key_count_info_ctor(mfn, gfn, page->count_info);
        cycle_len++;

        if ( !started )
        {
            first = last = crnt;
            started = 1;
        }
        else if ( !delta_is_1_count_info(&last, &crnt) )
        {
            /* end of cycle */
            print_count_info_cycle(&first, &last, cycle_len - 1);
            first = last = crnt;
            cycle_len = 1;
        }
        else
            last = crnt;
    }
    spin_unlock(&d->page_alloc_lock);
    print_count_info_cycle(&first, &last, cycle_len);

    mfn = virt_to_mfn(d->shared_info);
    page = mfn_to_page(_mfn(mfn));
    print_count_info(page->count_info);

    pod_unlock(p2m);
    p2m_unlock(p2m);
}

/********* TYPE_INFO *********/
struct report_key {
    unsigned long mfn, gfn, p2mfn, type;
};
static struct report_key report_key_ctor(unsigned long mfn, unsigned long gfn, unsigned long p2mfn, unsigned long type)
{
    struct report_key k = {
        .mfn = mfn,
        .gfn = gfn,
        .p2mfn = p2mfn,
        .type = type,
    };
    return k;
}
static int delta_is_0(struct report_key *first, struct report_key *last)
{
    return (first->gfn == last->gfn && first->type == last->type);
}

static int delta_is_1(struct report_key *first, struct report_key *last)
{
    return (first->gfn + 1 == last->gfn && first->type == last->type);
}
static void print_type(unsigned long type)
{
    char mystr_data[MYSTR_DATA_SIZE];
    struct mystr s;

    mystr_data[0] = '\0';
    s.data = mystr_data;
    s.pos = 0;

    if ( type & PGT_type_mask )
    {
        if ( (type & PGT_writable_page) == PGT_writable_page )
            add_to_str(&s, "PGT_writable_page");
        else if ( (type & PGT_seg_desc_page) == PGT_seg_desc_page )
            add_to_str(&s, "PGT_seg_desc_page");
        else if ( (type & PGT_l4_page_table) == PGT_l4_page_table )
            add_to_str(&s, "PGT_l4_page_table");
        else if ( (type & PGT_l3_page_table) == PGT_l3_page_table )
            add_to_str(&s, "PGT_l3_page_table");
        else if ( (type & PGT_l2_page_table) == PGT_l2_page_table )
            add_to_str(&s, "PGT_l2_page_table");
        else if ( (type & PGT_l1_page_table) == PGT_l1_page_table )
            add_to_str(&s, "PGT_l1_page_table");

        if ( (type & PGT_shared_page) == PGT_shared_page )
            add_to_str(&s, "PGT_shared_page");

        if ( (type & PGT_pinned) == PGT_pinned )
            add_to_str(&s, "PGT_pinned");
        if ( (type & PGT_validated) == PGT_validated )
            add_to_str(&s, "PGT_validated");
        if ( (type & PGT_pae_xen_l2) == PGT_pae_xen_l2 )
            add_to_str(&s, "PGT_pae_xen_l2");
        if ( (type & PGT_partial) == PGT_partial )
            add_to_str(&s, "PGT_partial");
        if ( (type & PGT_locked) == PGT_locked )
            add_to_str(&s, "PGT_locked");
    }
    printk("type=%s|count=%lu (%#lx)", s.data, (type & PGT_count_mask), type);
}
static void print_cycle(struct report_key *first, struct report_key *last, int cycle_len)
{
    P2M_PRINTK("mfn=%#lx, gfn=%#lx, "/*p2mfn=%#lx, "*/,
            first->mfn, first->gfn/*, first->p2mfn*/);
    print_type(first->type);

    if ( !delta_is_0(first, last) )
    {
        printk("\n");
        if ( !delta_is_1(first, last) )
            P2M_PRINTK("...\n");
        P2M_PRINTK("mfn=%#lx, gfn=%#lx, "/*p2mfn=%#lx, "*/,
                last->mfn, last->gfn/*, last->p2mfn*/);
        print_type(last->type);
    }
    printk(" (cycle_len=%d)\n", cycle_len);
}

static void audit_p2m_domain(struct domain *d)
{
    struct page_info *page;
    struct domain *od;
    unsigned long mfn, gfn;
    mfn_t p2mfn = INVALID_MFN_INITIALIZER;
    unsigned long orphans_count = 0, mpbad = 0, pmbad = 0;
    p2m_access_t p2ma;
    p2m_type_t type;
    struct p2m_domain *p2m = p2m_get_hostp2m(d);
    struct report_key first, last, crnt;
    int started = 0, cycle_len = 0;

#if 0
    if ( !paging_mode_translate(d) )
        goto out_p2m_audit;
#endif

    P2M_PRINTK("p2m audit starts\n");

    p2m_lock(p2m);
    pod_lock(p2m);

#if P2M_AUDIT
    if (p2m->audit_p2m)
        pmbad = p2m->audit_p2m(p2m);
#endif

    /* Audit part two: walk the domain's page allocation list, checking
     * the m2p entries. */
    spin_lock(&d->page_alloc_lock);
    page_list_for_each ( page, &d->page_list )
    {
        mfn = mfn_x(page_to_mfn(page));
        //P2M_PRINTK("auditing guest page, mfn=%#lx\n", mfn);

        od = page_get_owner(page);
        if ( od != d )
        {
            P2M_PRINTK("wrong owner %#lx -> %p(%u) != %p(%u)\n",
                       mfn, od, (od?od->domain_id:-1), d, d->domain_id);
            continue;
        }

        gfn = get_gpfn_from_mfn(mfn);
        if ( gfn == INVALID_M2P_ENTRY )
        {
            orphans_count++;
            P2M_PRINTK("orphaned guest page: mfn=%#lx has invalid gfn\n",
                           mfn);
            continue;
        }
        if ( gfn == SHARED_M2P_ENTRY )
        {
            P2M_PRINTK("shared mfn (%lx) on domain page list!\n",
                    mfn);
            continue;
        }

        if ( paging_mode_translate(p2m->domain) )
        {
            p2mfn = get_gfn_type_access(p2m, gfn, &type, &p2ma, 0, NULL);
            if ( mfn_x(p2mfn) != mfn )
            {
                mpbad++;
                P2M_PRINTK(
                        "map mismatch mfn %#lx -> gfn %#lx -> mfn %#lx" " (-> gfn %#lx)\n",
                        mfn, gfn, mfn_x(p2mfn),
                        (mfn_valid(p2mfn) ? get_gpfn_from_mfn(mfn_x(p2mfn)) : -1u));
                /* This m2p entry is stale: the domain has another frame in
                 * this physical slot.  No great disaster, but for neatness,
                 * blow away the m2p entry. */
                set_gpfn_from_mfn(mfn, INVALID_M2P_ENTRY);
            }
        }
        __put_gfn(p2m, gfn);

#if 0
        P2M_PRINTK("OK: mfn=%#lx, gfn=%#lx, p2mfn=%#lx, type=%#lx\n",
                       mfn, gfn, mfn_x(p2mfn), page->u.inuse.type_info);
#else
        crnt = report_key_ctor(mfn, gfn, mfn_x(p2mfn), page->u.inuse.type_info);
        cycle_len++;

        if ( !started )
        {
            first = last = crnt;
            started = 1;
        }
        else if ( !delta_is_1(&last, &crnt) )
        {
            /* end of cycle */
            print_cycle(&first, &last, cycle_len - 1);
            first = last = crnt;
            cycle_len = 1;
        }
        else
            last = crnt;
#endif
    }
    spin_unlock(&d->page_alloc_lock);
    print_cycle(&first, &last, cycle_len);

    pod_unlock(p2m);
    p2m_unlock(p2m);

    P2M_PRINTK("p2m audit complete\n");
    if ( orphans_count | mpbad | pmbad )
        P2M_PRINTK("p2m audit found %lu orphans\n", orphans_count);
    if ( mpbad | pmbad )
    {
        P2M_PRINTK("p2m audit found %lu odd p2m, %lu bad m2p entries\n",
                   pmbad, mpbad);
        WARN();
    }

//out_p2m_audit:
    return;
}

static void dump_mem_info(unsigned char key)
{
    struct domain *d;

    printk("'%c' pressed -> dumping mem info\n", key);

    rcu_read_lock(&domlist_read_lock);

    for_each_domain ( d )
    {
        if ( d->domain_id > 0 )
        {
            if ( key == 'X' )
            {
                audit_p2m_domain(d);
                break;
            }
            else if ( key == 'Y' )
            {
                audit_p2m_domain_count_info(d);
                break;
            }
            else if ( key == 'Z' )
            {
                audit_p2m_domain(d);
                audit_p2m_domain_count_info(d);
            }
        }
    }

    rcu_read_unlock(&domlist_read_lock);
}

static int __init dump_mem_info_init(void)
{
    register_keyhandler('X', dump_mem_info, "dump mem info", 1);
    register_keyhandler('Y', dump_mem_info, "dump mem info", 1);
    register_keyhandler('Z', dump_mem_info, "dump mem info", 1);
    return 0;
}
__initcall(dump_mem_info_init);
