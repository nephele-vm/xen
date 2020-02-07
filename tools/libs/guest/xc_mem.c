/*
 * xc_mem.c
 *
 *  Created on: Nov 12, 2018
 *      Author: wolf
 */

#if 1
#include <inttypes.h>

#include "xc_private.h"
#include "xg_private.h"
#include "xg_save_restore.h"

#include <xen/xen.h>


/* max mfn of the whole machine */
static unsigned long max_mfn;

/* Address size of the guest */
static unsigned int guest_width;

/* #levels of page tables used by the current guest */
static unsigned int pt_levels;

/* Live mapping of system MFN to PFN table. */
static xen_pfn_t *live_m2p = NULL;

#define mfn_to_pfn(_mfn)  (live_m2p[(_mfn)])



/* number of pfns this guest has (i.e. number of entries in the P2M) */
static unsigned long p2m_size;

/* Live mapping of the table mapping each PFN to its current MFN. */
static xen_pfn_t *live_p2m = NULL;

#define pfn_to_mfn(_pfn)                                \
  ((xen_pfn_t) ((guest_width==8)                       \
                ? (((uint64_t *)live_p2m)[(_pfn)])      \
                : (((uint32_t *)live_p2m)[(_pfn)])))

static inline int get_platform_info(xc_interface *xch, uint32_t dom,
                                    /* OUT */ unsigned long *max_mfn,
                                    /* OUT */ unsigned long *hvirt_start,
                                    /* OUT */ unsigned int *pt_levels,
                                    /* OUT */ unsigned int *guest_width)
{
    xen_capabilities_info_t xen_caps = "";
    xen_platform_parameters_t xen_params;

    if (xc_version(xch, XENVER_platform_parameters, &xen_params) != 0)
        return 0;

    if (xc_version(xch, XENVER_capabilities, &xen_caps) != 0)
        return 0;

    if (xc_maximum_ram_page(xch, max_mfn))
        return 0;

    *hvirt_start = xen_params.virt_start;

    if ( xc_domain_get_guest_width(xch, dom, guest_width) != 0)
        return 0;

    /* 64-bit tools will see the 64-bit hvirt_start, but 32-bit guests
     * will be using the compat one. */
    if ( *guest_width < sizeof (unsigned long) )
        /* XXX need to fix up a way of extracting this value from Xen if
         * XXX it becomes variable for domU */
        *hvirt_start = 0xf5800000;

    if (strstr(xen_caps, "xen-3.0-x86_64"))
        /* Depends on whether it's a compat 32-on-64 guest */
        *pt_levels = ( (*guest_width == 8) ? 4 : 3 );
    else if (strstr(xen_caps, "xen-3.0-x86_32p"))
        *pt_levels = 3;
    else
        return 0;

    return 1;
}

/*
 ** Map the top-level page of MFNs from the guest.1
 */
static void *map_frame_list_list(xc_interface *xch, uint32_t dom, shared_info_any_t *shinfo)
{
    void *p;
    uint64_t fll;

#define GET_FIELD(_p, _f, _w) (((_w) == 8) ? ((_p)->x64._f) : ((_p)->x32._f))
    fll = GET_FIELD(shinfo, arch.pfn_to_mfn_frame_list_list, guest_width);
    if ( fll == 0 )
    {
        ERROR("Timed out waiting for frame list updated.");
        return NULL;
    }

    p = xc_map_foreign_range(xch, dom, PAGE_SIZE, PROT_READ, fll);
    if ( p == NULL )
        PERROR("Couldn't map p2m_frame_list_list");

    return p;
}

#if 0

/* Number of xen_pfn_t in a page */
#define FPP             (PAGE_SIZE/(guest_width))

/* Number of entries in the pfn_to_mfn_frame_list_list */
#define P2M_FLL_ENTRIES (((p2m_size)+(FPP*FPP)-1)/(FPP*FPP))

/* Number of entries in the pfn_to_mfn_frame_list */
#define P2M_FL_ENTRIES  (((p2m_size)+FPP-1)/FPP)
#endif

/* Number of xen_pfn_t in a page */
#define FPP             (PAGE_SIZE/(dinfo->guest_width))

/* Number of entries in the pfn_to_mfn_frame_list_list */
#define P2M_FLL_ENTRIES (((dinfo->p2m_size)+(FPP*FPP)-1)/(FPP*FPP))

/* Number of entries in the pfn_to_mfn_frame_list */
#define P2M_FL_ENTRIES  (((dinfo->p2m_size)+FPP-1)/FPP)

/* Size in bytes of the pfn_to_mfn_frame_list     */
#define P2M_FL_SIZE     ((P2M_FL_ENTRIES)*(guest_width))

#define DEFINE_DINFO \
    struct domain_info_context _di = { .guest_width = guest_width, .p2m_size = p2m_size }; \
    struct domain_info_context *dinfo = &_di;


static xen_pfn_t *map_and_save_p2m_table(xc_interface *xch,
                                         uint32_t dom,
                                         unsigned long p2m_size,
                                         shared_info_any_t *live_shinfo)
{
    struct domain_info_context _di = { .guest_width = guest_width, .p2m_size = p2m_size };
    struct domain_info_context *dinfo = &_di;

    /* Double and single indirect references to the live P2M table */
    void *live_p2m_frame_list_list = NULL;
    void *live_p2m_frame_list = NULL;

    /* Copies of the above. */
    xen_pfn_t *p2m_frame_list_list = NULL;
    xen_pfn_t *p2m_frame_list = NULL;

    /* The mapping of the live p2m table itself */
    xen_pfn_t *p2m = NULL;

    int i, success = 0;

    live_p2m_frame_list_list = map_frame_list_list(xch, dom, live_shinfo);
    if ( !live_p2m_frame_list_list )
        goto out;

    /* Get a local copy of the live_P2M_frame_list_list */
    if ( !(p2m_frame_list_list = malloc(PAGE_SIZE)) )
    {
        ERROR("Couldn't allocate p2m_frame_list_list array");
        goto out;
    }
    memcpy(p2m_frame_list_list, live_p2m_frame_list_list, PAGE_SIZE);

    /* Canonicalize guest's unsigned long vs ours */
    if ( guest_width > sizeof(unsigned long) )
        for ( i = 0; i < PAGE_SIZE/sizeof(unsigned long); i++ )
            if ( i < PAGE_SIZE/guest_width )
                p2m_frame_list_list[i] = ((uint64_t *)p2m_frame_list_list)[i];
            else
                p2m_frame_list_list[i] = 0;
    else if ( guest_width < sizeof(unsigned long) )
        for ( i = PAGE_SIZE/sizeof(unsigned long) - 1; i >= 0; i-- )
            p2m_frame_list_list[i] = ((uint32_t *)p2m_frame_list_list)[i];

    live_p2m_frame_list =
        xc_map_foreign_pages(xch, dom, PROT_READ,
                             p2m_frame_list_list,
                             P2M_FLL_ENTRIES);
    if ( !live_p2m_frame_list )
    {
        ERROR("Couldn't map p2m_frame_list");
        goto out;
    }

    /* Get a local copy of the live_P2M_frame_list */
    if ( !(p2m_frame_list = malloc(P2M_FL_SIZE)) )
    {
        ERROR("Couldn't allocate p2m_frame_list array");
        goto out;
    }
    memcpy(p2m_frame_list, live_p2m_frame_list, P2M_FL_SIZE);

    /* Canonicalize guest's unsigned long vs ours */
    if ( guest_width > sizeof(unsigned long) )
        for ( i = 0; i < P2M_FL_ENTRIES; i++ )
            p2m_frame_list[i] = ((uint64_t *)p2m_frame_list)[i];
    else if ( guest_width < sizeof(unsigned long) )
        for ( i = P2M_FL_ENTRIES - 1; i >= 0; i++ )
            p2m_frame_list[i] = ((uint32_t *)p2m_frame_list)[i];


    /* Map all the frames of the pfn->mfn table. For migrate to succeed,
       the guest must not change which frames are used for this purpose.
       (its not clear why it would want to change them, and we'll be OK
       from a safety POV anyhow. */

    p2m = xc_map_foreign_pages(xch, dom, PROT_READ,
                               p2m_frame_list,
                               P2M_FL_ENTRIES);
    if ( !p2m )
    {
        ERROR("Couldn't map p2m table");
        goto out;
    }
    live_p2m = p2m; /* So that translation macros will work */

    /* Canonicalise the pfn-to-mfn table frame-number list. */
    for ( i = 0; i < p2m_size; i += FPP )
    {
#if 0//TODO check against m2p
        if ( !MFN_IS_IN_PSEUDOPHYS_MAP(p2m_frame_list[i/FPP]) )
        {
            ERROR("Frame# in pfn-to-mfn frame list is not in pseudophys");
            ERROR("entry %d: p2m_frame_list[%ld] is 0x%"PRIx64", max 0x%lx",
                  i, i/FPP, (uint64_t)p2m_frame_list[i/FPP], max_mfn);
            if ( p2m_frame_list[i/FPP] < max_mfn )
            {
                ERROR("m2p[0x%"PRIx64"] = 0x%"PRIx64,
                      (uint64_t)p2m_frame_list[i/FPP],
                      (uint64_t)live_m2p[p2m_frame_list[i/FPP]]);
                ERROR("p2m[0x%"PRIx64"] = 0x%"PRIx64,
                      (uint64_t)live_m2p[p2m_frame_list[i/FPP]],
                      (uint64_t)p2m[live_m2p[p2m_frame_list[i/FPP]]]);

            }
            goto out;
        }
#endif
        p2m_frame_list[i/FPP] = mfn_to_pfn(p2m_frame_list[i/FPP]);
    }

    success = 1;

 out:

    if ( !success && p2m )
        munmap(p2m, ROUNDUP(p2m_size * sizeof(xen_pfn_t), PAGE_SHIFT));

    if ( live_p2m_frame_list_list )
        munmap(live_p2m_frame_list_list, PAGE_SIZE);

    if ( live_p2m_frame_list )
        munmap(live_p2m_frame_list, P2M_FLL_ENTRIES * PAGE_SIZE);

    if ( p2m_frame_list_list )
        free(p2m_frame_list_list);

    if ( p2m_frame_list )
        free(p2m_frame_list);

    return success ? p2m : NULL;
}

#define ENTRIES_NUM (PAGE_SIZE / sizeof(unsigned long))

struct table_node {
    int level;
    unsigned long pfn;
    unsigned long entries[ENTRIES_NUM];
    struct table_node *children[ENTRIES_NUM];
};

static
struct table_node *find_table_node_by_pfn(struct table_node *from, unsigned long pfn)
{
    struct table_node *c = NULL, *res = NULL;

    if (from->pfn == pfn)
        return from;

    for ( int i = 0; i < ENTRIES_NUM; i++ )
    {
        c = from->children[i];
        if (c) {
            res = find_table_node_by_pfn(c, pfn);
            if (res)
                break;
        }
    }

    return res;
}

struct table_node *pt_base;

static void set_pte(struct table_node *me, unsigned long pfn, unsigned long *pte_page, int level)
{
    struct domain_info_context _di = { .guest_width = guest_width, .p2m_size = p2m_size };
    struct domain_info_context *dinfo = &_di;

    struct table_node *c = NULL;

    for ( int i = 0; i < ENTRIES_NUM; i++ )
    {
        unsigned long pte = pte_page[i];

        if ( pte )
        {
            if ( level > 1 )
            {
                c = calloc(1, sizeof(struct table_node));
                c->level = level - 1;
                c->pfn = mfn_to_pfn((pte & MFN_MASK_X86) >> PAGE_SHIFT);

                me->children[i] = c;
            }

            me->entries[i] = pte;
        }
        else
        {
        }
    }
}

#define __AC(X,Y)   (X##Y)
#define _AC(X,Y)    __AC(X,Y)
#define PADDR_BITS              52
#define PADDR_MASK              ((_AC(1,UL) << PADDR_BITS) - 1)
#define lxe_get_pfn(pte) \
    ((unsigned long)((pte & (PADDR_MASK&PAGE_MASK)) >> PAGE_SHIFT))
#define get_pte_flags(x) (((int)((x) >> 40) & ~0xFFF) | ((int)(x) & 0xFFF))

struct report_key {
    int level;
    int index;
    unsigned long pte;
    unsigned long pfn;
    unsigned long flags;
};
static struct report_key report_key_ctor(int level, int index, unsigned long pte)
{
    struct report_key k = {
        .level = level,
        .index = index,
        .pte = pte,
        .pfn = lxe_get_pfn(pte),
        .flags = get_pte_flags(pte),
    };
    return k;
}
static int delta_is_0(struct report_key *first, struct report_key *last)
{
    return (first->pte == last->pte);
}

static int delta_is_1(struct report_key *first, struct report_key *last)
{
    return (first->pfn + 1 == last->pfn && first->flags == last->flags);
}

static void __print_pte_64(int level, int index, unsigned long pte)
{
    struct domain_info_context _di = { .guest_width = guest_width, .p2m_size = p2m_size };
    struct domain_info_context *dinfo = &_di;
    char ident[4], index_str[16], global[5], dirty[5];
    unsigned long pfn;

    memset(ident, '\t', 4 - level);
    ident[4 - level] = '\0';
    if ( index >= 0 )
        sprintf(index_str, "[%d] ", index);
    else
        index_str[0] = '\0';

    if ( level == 1 )
    {
        sprintf(global, " G=%d", (pte & _PAGE_GLOBAL ? 1 : 0));
        sprintf(dirty,  " D=%d", (pte & _PAGE_DIRTY  ? 1 : 0));
    }
    else
    {
        global[0] = '\0';
        dirty[0]  = '\0';
    }
    pfn = (pte & MFN_MASK_X86) >> PAGE_SHIFT;

    //fprintf(stderr, "pte=%016lx NX=%d AVL=%d A=%d PCD=%d PWT=%d U=%d W=%d P=%d\n",
    fprintf(stderr, "%s%spte=%016lx mfn=%016lx (pfn=%016lx) A=%d PCD=%d PWT=%d U=%d W=%d P=%d%s%s",
            ident, index_str, pte,
            pfn, mfn_to_pfn(pfn),
            //(pte & _PAGE_ACCESSED ? 1 : 0),
            //6, 6,
            //level == 1 ? (pte & xxx ? 1 : 0) : "",
            (pte & _PAGE_ACCESSED ? 1 : 0),
            (pte & _PAGE_PCD ? 1 : 0),
            (pte & _PAGE_PWT ? 1 : 0),
            (pte & _PAGE_USER ? 1 : 0),
            (pte & _PAGE_RW ? 1 : 0),
            (pte & _PAGE_PRESENT ? 1 : 0),
            global, dirty);
}

static void print_cycle(struct report_key *first, struct report_key *last, int cycle_len)
{
    __print_pte_64(first->level, first->index, first->pte);

    if ( !delta_is_0(first, last) )
    {
        fprintf(stderr, "\n");
        if ( !delta_is_1(first, last) )
        {
            char ident[4];

            memset(ident, '\t', 4 - first->level);
            ident[4 - first->level] = '\0';
            fprintf(stderr, "%s ...\n", ident);
        }
        __print_pte_64(last->level, last->index, last->pte);
    }
    fprintf(stderr, " (cycle_len=%d)\n", cycle_len);
}

static void print_pt_page2(struct table_node *me, int level)
{
    struct report_key first, last, crnt;
    int started = 0, cycle_len = 0;

    for ( int i = 0; i < ENTRIES_NUM; i++ )
    {
        unsigned long pte = me->entries[i];
        struct table_node *c = me->children[i];

        if (!pte)
            continue;

        crnt = report_key_ctor(level, i, pte);
        cycle_len++;

        if ( !started )
        {
            first = last = crnt;
            started = 1;
        }
        else if ( !delta_is_1(&last, &crnt))
        {
            /* end of cycle */
            print_cycle(&first, &last, cycle_len - 1);
            first = last = crnt;
            cycle_len = 1;
        }
        else
            last = crnt;

        if (c) {
            /* restart */
            print_cycle(&first, &last, cycle_len - 1);
            started = 0;

            print_pt_page2(c, level - 1);
        }
    }
    if (started)
        print_cycle(&first, &last, cycle_len);
}

struct table_lookup {
    unsigned long pfn;
    unsigned long pte;
    int entry_index;
};

#if 0
static void make_pte_ro(xc_interface *xch, domid_t domid, struct table_lookup *lookup)
{
    int rc;
    struct xc_mmu *mmu;
    uint64_t ptr, val;

    if ( !lookup->pte || !(lookup->pte & _PAGE_RW))
        return;

    mmu = xc_alloc_mmu_updates(xch, domid | ((domid + 1) << 16));   //TODO check

    ptr = ((pfn_to_mfn(lookup->pfn) << PAGE_SHIFT) + (lookup->entry_index * sizeof(unsigned long)));
    val = lookup->pte & ~_PAGE_RW;

    rc = xc_add_mmu_update(xch, mmu, ptr, val);

    rc = xc_flush_mmu_updates(xch, mmu);

    free(mmu);
}
#endif

static void make_ptes_ro(xc_interface *xch, domid_t domid, unsigned long pfn, unsigned long *pte_page)
{
    struct domain_info_context _di = { .guest_width = guest_width, .p2m_size = p2m_size };
    struct domain_info_context *dinfo = &_di;

    int rc;
    struct xc_mmu *mmu;

    xc_dominfo_t info;
    if ( xc_domain_getinfo(xch, domid, 1, &info) != 1 )
    {
        ERROR("Could not get domain info");
        return;
    }

    mmu = xc_alloc_mmu_updates(xch, domid | ((domid + 1) << 16));//TODO check

    for ( int i = 0; i < (PAGE_SIZE / sizeof(unsigned long)); i++ )
    {
        uint64_t ptr, val, this_mfn;
        unsigned long pte = pte_page[i];

        if ( !pte || !(pte & _PAGE_RW) )
            continue;

        this_mfn = (pte & MFN_MASK_X86) >> PAGE_SHIFT;
        if (this_mfn == info.shared_info_frame) {
            //TODO do we really want to skip shared info page?
            continue;
        }

        ptr = ((pfn_to_mfn(pfn) << PAGE_SHIFT) + (i * sizeof(unsigned long)));
        val = pte & ~_PAGE_RW;

        rc = xc_add_mmu_update(xch, mmu, ptr, val);
    }

    rc = xc_flush_mmu_updates(xch, mmu);

    free(mmu);
}

#if 1

typedef unsigned long pgentry_t;
#define MADDR_BITS_X86  ((dinfo->guest_width == 8) ? 52 : 44)
#define MFN_MASK_X86    ((1ULL << (MADDR_BITS_X86 - PAGE_SHIFT_X86)) - 1)
#define MADDR_MASK_X86  (MFN_MASK_X86 << PAGE_SHIFT_X86)
#define pte_to_mfn(_pte)           (((_pte) & (MADDR_MASK_X86&PAGE_MASK)) >> L1_PAGETABLE_SHIFT_X86_64)
#define VIRT_START                 0UL /*((unsigned long)&_text)*/
#define to_virt(x)                 ((void *)((unsigned long)(x)+VIRT_START))
#define pte_to_virt(_pte)          to_virt(mfn_to_pfn(pte_to_mfn(_pte)) << PAGE_SHIFT)

/* Given a virtual address, get an entry offset into a page table. */
#define l1_table_offset(a)         \
    (((a) >> L1_PAGETABLE_SHIFT_X86_64) & (L1_PAGETABLE_ENTRIES_X86_64 - 1))
#define l2_table_offset(a)         \
    (((a) >> L2_PAGETABLE_SHIFT_X86_64) & (L2_PAGETABLE_ENTRIES_X86_64 - 1))
#define l3_table_offset(a)         \
    (((a) >> L3_PAGETABLE_SHIFT_X86_64) & (L3_PAGETABLE_ENTRIES_X86_64 - 1))
#define l4_table_offset(a)         \
    (((a) >> L4_PAGETABLE_SHIFT_X86_64) & (L4_PAGETABLE_ENTRIES_X86_64 - 1))


static void page_walk(struct table_node *pt_base, unsigned long virt_address, struct table_lookup *lookup)
{
    struct domain_info_context _di = { .guest_width = guest_width, .p2m_size = p2m_size };
    struct domain_info_context *dinfo = &_di;

	pgentry_t *tab = pt_base->entries, pte;
	unsigned long addr = virt_address;
	unsigned long pfn;
	struct table_node *who;

	fprintf(stderr, "Pagetable walk from virt %lx, base %p:\n", virt_address, pt_base);

#if defined(__x86_64__)
	pte = tab[l4_table_offset(addr)];
	pfn = mfn_to_pfn(pte_to_mfn(pte));

	who = find_table_node_by_pfn(pt_base, pfn);
	tab = who->entries;            //pte_to_virt(page);
	fprintf(stderr, " L4 = %lx (%p)  [offset = %lx]\n", pte, tab, l4_table_offset(addr));
#endif
	pte = tab[l3_table_offset(addr)];
	pfn = mfn_to_pfn(pte_to_mfn(pte));
	who = find_table_node_by_pfn(who, pfn);
	tab = who->entries;
	//tab = pte_to_virt(page);
	fprintf(stderr, "  L3 = %lx (%p)  [offset = %lx]\n", pte, tab, l3_table_offset(addr));
	pte = tab[l2_table_offset(addr)];
	pfn = mfn_to_pfn(pte_to_mfn(pte));
	who = find_table_node_by_pfn(who, pfn);
	tab = who->entries;
	//tab = pte_to_virt(page);
	fprintf(stderr, "   L2 = %lx (%p)  [offset = %lx]\n", pte, tab, l2_table_offset(addr));

	pte = tab[l1_table_offset(addr)];
	fprintf(stderr, "    L1 = %lx [offset = %lx]\n", pte, l1_table_offset(addr));

	lookup->pfn = pfn;
	lookup->pte = pte;
	lookup->entry_index = l1_table_offset(addr);
}
#endif

int xc_memory(xc_interface *xch, domid_t domid, int make_ro);
int xc_memory(xc_interface *xch, domid_t domid, int make_ro)
{
    int i, rc = -1;
    unsigned long hvirt_start;

    xc_dominfo_t info;
    /* The new domain's shared-info frame number. */
    unsigned long shared_info_frame;
    /* Live mapping of shared info structure */
    shared_info_any_t *live_shinfo = NULL;

    //TODO xen_pfn_t *m2p_table;


    /* Live mapping of the table mapping each PFN to its current MFN. */
    static xen_pfn_t *live_p2m = NULL;

    /* A table containing the type of each PFN (/not/ MFN!). */
    unsigned long *pfn_type = NULL;
    /* base of the region in which domain memory is mapped */
    unsigned char *region_base = NULL;
    int count;

    struct table_node *pt_base;
    struct table_lookup lookup;

#if 0
    rc = xc_maximum_ram_page(xch, &max_mfn);
    if ( rc )
    {
        PERROR("Failed to get maximum RAM page");
        return -1;
    }
#endif

    if ( !get_platform_info(xch, domid, &max_mfn, &hvirt_start, &pt_levels, &guest_width) )
    {
        ERROR("Unable to get platform info.");
        return 1;
    }


    /* XXX 10 */
    /* Setup the mfn_to_pfn table mapping */
    if ( !(live_m2p = xc_map_m2p(xch, max_mfn, PROT_READ, NULL)) )
    {
        ERROR("Failed to map live M2P table");
        goto out;
    }

    /* XXX 2 */
    if ( xc_domain_getinfo(xch, domid, 1, &info) != 1 )
    {
        ERROR("Could not get domain info");
        return 1;
    }

    /* XXX 3 MISSING */
    shared_info_frame = info.shared_info_frame;

    live_shinfo = xc_map_foreign_range(xch, domid, PAGE_SIZE, PROT_READ, shared_info_frame);
    if ( !live_shinfo )
    {
        ERROR("Couldn't map live_shinfo");
        goto out;
    }

    /* Get the size of the P2M table */
    p2m_size = do_memory_op(xch, XENMEM_maximum_gpfn, &domid, sizeof(domid)) + 1;


    /* Map the P2M table, and write the list of P2M frames */
    live_p2m = map_and_save_p2m_table(xch, domid, p2m_size, live_shinfo);
    if ( live_p2m == NULL )
    {
        ERROR("Failed to map/save the p2m frame list");
        goto out;
    }

    pfn_type = calloc(p2m_size, sizeof(*pfn_type));
    if ( pfn_type == NULL )
    {
        ERROR("failed to alloc memory for pfn_type array");
        errno = ENOMEM;
        goto out;
    }
    for ( i = 0; i < p2m_size; i++ )
        pfn_type[i] = pfn_to_mfn(i);


    region_base = xc_map_foreign_pages(xch, domid, PROT_READ, pfn_type, p2m_size);
    if ( region_base == NULL )
    {
        ERROR("map batch failed");
        rc = errno;
        goto out;
    }

    count = 0;
    while ( count < p2m_size )
    {
        int batch_size = MIN(p2m_size - count, 1024);

        if ( xc_get_pfn_type_batch(xch, domid, batch_size, pfn_type + count) )
        {
            PERROR("get_pfn_type_batch failed");
            rc = errno;
            goto out;
        }

        count += batch_size;
    }

#if 1

    rc = xc_domain_pause(xch, domid);

    pt_base = calloc(1, sizeof(struct table_node));
    pt_base->level = 4;

    for ( i = 0; i < p2m_size; i++ )
    {
        unsigned long pfn, pagetype;
        void *spage = (char *) region_base + (PAGE_SIZE * i);

        pfn      = pfn_type[i] & ~XEN_DOMCTL_PFINFO_LTAB_MASK;
        pagetype = pfn_type[i] &  XEN_DOMCTL_PFINFO_LTAB_MASK;

        /* write out pages in batch */
        if ( pagetype == XEN_DOMCTL_PFINFO_XTAB )
            continue;

        pagetype &= XEN_DOMCTL_PFINFO_LTABTYPE_MASK;

        if ( (pagetype >= XEN_DOMCTL_PFINFO_L1TAB) &&
             (pagetype <= XEN_DOMCTL_PFINFO_L4TAB) )
        {
            struct table_node *who = NULL;
            int level = pagetype >> XEN_DOMCTL_PFINFO_LTAB_SHIFT;

            switch (level) {
            case 4:
                pt_base->pfn = i;
            case 3:
            case 2:
            case 1:
                who = find_table_node_by_pfn(pt_base, i);
                break;
            }

#if PRINT_V1
            print_pt_page(i, spage, level);
#endif

            if (!who) {
                ERROR("fatal");
            }

            set_pte(who, pfn, spage, level);

#if 1//TODO reenable
            if ( make_ro )
            {
                if ( level == 1 )
                    make_ptes_ro(xch, domid, i, spage);
            }
#endif
        }
        else
        {
        }

#if 0
        if ( (pfn_type[i] & XEN_DOMCTL_PFINFO_LTAB_MASK) == XEN_DOMCTL_PFINFO_XTAB )
        {
            DPRINTF("type fail: page %i mfn %08lx\n", i, pfn_type[i]);
            continue;
        }

        if ( /*debug*/1 )
            DPRINTF("pfn= %08lx mfn= %08lx [mfn]= %08lx"
                    " sum= %08lx\n",
                    (pfn_type[i] & XEN_DOMCTL_PFINFO_LTAB_MASK) | pfn_batch[i],
                    pfn_type[i],
                    mfn_to_pfn(pfn_type[i] & ~XEN_DOMCTL_PFINFO_LTAB_MASK),
                    csum_page(region_base + (PAGE_SIZE*i)));

        /* canonicalise mfn->pfn */
        pfn_type[j] = (pfn_type[j] & XEN_DOMCTL_PFINFO_LTAB_MASK) |
            pfn_batch[j];
#endif
    }
#endif

    print_pt_page2(pt_base, 4);

    //page_walk(pt_base, 0x286a0, &lookup);
    page_walk(pt_base, 0xbff68, &lookup);
    page_walk(pt_base, 0x29610, &lookup);
    page_walk(pt_base, 0x6dbe8, &lookup);
    //make_pte_ro(xch, domid, &lookup);

    munmap(region_base, p2m_size * PAGE_SIZE);

out:
    if ( live_shinfo )
        munmap(live_shinfo, PAGE_SIZE);

    if ( live_p2m )
        munmap(live_p2m, ROUNDUP(p2m_size * sizeof(xen_pfn_t), PAGE_SHIFT));

    if ( live_m2p )
        munmap(live_m2p, M2P_SIZE(max_mfn));

    free(pfn_type);
    //TODO free(pfn_batch);

    return rc;
}
#endif
