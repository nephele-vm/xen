/******************************************************************************
 * include/asm-x86/mem_sharing.h
 *
 * Memory sharing support.
 *
 * Copyright (c) 2009 Citrix Systems, Inc. (Grzegorz Milos)
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
#ifndef __MEM_SHARING_H__
#define __MEM_SHARING_H__

#include <public/domctl.h>
#include <public/memory.h>

#ifdef CONFIG_MEM_SHARING

#define mem_sharing_enabled(d) ((d)->arch.mem_sharing.enabled)

/* Auditing of memory sharing code? */
#ifndef NDEBUG
#define MEM_SHARING_AUDIT 1
#else
#define MEM_SHARING_AUDIT 0
#endif

typedef uint64_t shr_handle_t;

typedef struct rmap_hashtab {
    struct list_head *bucket;
    /*
     * Overlaps with prev pointer of list_head in union below.
     * Unlike the prev pointer, this can be NULL.
     */
    void *flag;
} rmap_hashtab_t;

struct page_sharing_info
{
    struct page_info *pg;   /* Back pointer to the page. */
    shr_handle_t handle;    /* Globally unique version / handle. */
    bool writable;//TODO revisit
    atomic_t refcount;
#if MEM_SHARING_AUDIT
    struct list_head entry; /* List of all shared pages (entry). */
    struct rcu_head rcu_head; /* List of all shared pages (entry). */
#endif
    /* Reverse map of <domain,gfn> tuples for this shared frame. */
    union {
        struct list_head    gfns;
        rmap_hashtab_t      hash_table;
    };
};

unsigned int mem_sharing_get_nr_saved_mfns(void);
unsigned int mem_sharing_get_nr_shared_mfns(void);

int mem_sharing_nominate_page(struct domain *d, gfn_t gfn,
                         mfn_t mfn, int p2mt, int p2ma,
                         int expected_refcnt,
                         bool writable,
                         bool validate_only,
                         shr_handle_t *phandle);

int mem_sharing_add_to_physmap(struct domain *sd, mfn_t smfn, shr_handle_t sh,
                               struct domain *cd, unsigned long cgfn, bool clone);

int mem_sharing_share_to_child(struct domain *parent, struct domain *child,
        unsigned long mfn, unsigned long gpfn,
        int l1t, bool writable);

/* Only fails with -ENOMEM. Enforce it with a BUG_ON wrapper. */
int __mem_sharing_unshare_page(struct domain *d,
                               unsigned long gfn,
                               bool destroy);

static inline int mem_sharing_unshare_page(struct domain *d,
                                           unsigned long gfn)
{
    int rc = __mem_sharing_unshare_page(d, gfn, false);
    BUG_ON(rc && (rc != -ENOMEM));
    return rc;
}

int __mem_sharing_unshare_page_raw(struct domain *d,
                               unsigned long gfn,
                               mfn_t mfn,
                               bool destroy,
                               bool must_exist,
                               unsigned long *new_mfn);
static inline int mem_sharing_unshare_page_pv(struct domain *d,
                                           unsigned long gfn,
                                           unsigned long mfn,
                                           bool destroy,
                                           unsigned long *new_mfn)
{
    int rc = __mem_sharing_unshare_page_raw(d, gfn, _mfn(mfn), destroy, false, new_mfn);
    BUG_ON( rc && (rc != -ENOMEM && rc != -ESRCH) );
    return rc;
}

static inline bool mem_sharing_is_fork(const struct domain *d)
{
    return d->parent;
}

int mem_sharing_fork_page(struct domain *d, gfn_t gfn,
                          bool unsharing);

/*
 * If called by a foreign domain, possible errors are
 *   -EBUSY -> ring full
 *   -ENOSYS -> no ring to begin with
 * and the foreign mapper is responsible for retrying.
 *
 * If called by the guest vcpu itself and allow_sleep is set, may
 * sleep on a wait queue, so the caller is responsible for not
 * holding locks on entry. It may only fail with ENOSYS
 *
 * If called by the guest vcpu itself and allow_sleep is not set,
 * then it's the same as a foreign domain.
 */
int mem_sharing_notify_enomem(struct domain *d, unsigned long gfn,
                              bool allow_sleep);
int mem_sharing_memop(XEN_GUEST_HANDLE_PARAM(xen_mem_sharing_op_t) arg);
int mem_sharing_domctl(struct domain *d,
                       struct xen_domctl_mem_sharing_op *mec);

/*
 * Scans the p2m and relinquishes any shared pages, destroying
 * those for which this domain holds the final reference.
 * Preemptible.
 */
int relinquish_shared_pages(struct domain *d);
int relinquish_shared_pages_pv(struct domain *d);

#else

#define mem_sharing_enabled(d) false

static inline unsigned int mem_sharing_get_nr_saved_mfns(void)
{
    return 0;
}

static inline unsigned int mem_sharing_get_nr_shared_mfns(void)
{
    return 0;
}

static inline int mem_sharing_unshare_page(struct domain *d, unsigned long gfn)
{
    ASSERT_UNREACHABLE();
    return -EOPNOTSUPP;
}

static inline int mem_sharing_notify_enomem(struct domain *d, unsigned long gfn,
                                            bool allow_sleep)
{
    ASSERT_UNREACHABLE();
    return -EOPNOTSUPP;
}

static inline bool mem_sharing_is_fork(const struct domain *d)
{
    return false;
}

static inline int mem_sharing_fork_page(struct domain *d, gfn_t gfn, bool lock)
{
    return -EOPNOTSUPP;
}

#endif

extern int page_sharing_info_pool_enabled;
int page_sharing_info_allocator_init(unsigned int max_pages);
void page_sharing_info_show_stats(void);

int mem_sharing_pools_init(struct domain *d);
int mem_sharing_pools_fini(struct domain *d);

#endif /* __MEM_SHARING_H__ */
