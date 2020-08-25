#ifndef __XEN_CLONE_H__
#define __XEN_CLONE_H__

int map_cloning_notification_ring(unsigned long va, unsigned long pages_num,
        void **out_mapping);
int unmap_cloning_notification_ring(void *mapping);


struct clone_domain {
    struct domain *domain;
    unsigned long start_info_mfn;
    unsigned long xenstore_mfn;
    unsigned long console_mfn;
};


//TODO rename and move
enum grant_cloning_sm_state {
    NOT_STARTED,
    IN_PROGRES,
    COMPLETED,
};
struct gnttab_cloning_sm {
    enum grant_cloning_sm_state state;
    int next_idx;
};

struct pfns_bm {
    unsigned long size;
    unsigned long *bm;
};

struct domain_clone_helper {
    struct clone_domain parent;
    struct clone_domain child;

    struct pfns_bm pfns_physmem;
    struct pfns_bm pfns_shared;

    struct {
        xen_pfn_t *array;
        int num;
        int first_free;
    } mfns;

    struct {
        int order;
        int size;
        int num;
    } mfns_batch;

    struct gnttab_cloning_sm sm;
};

unsigned long dch_alloc_mfn(struct domain_clone_helper *dch);
void dch_set_child_physmem_mfn(struct domain_clone_helper *dch,
        unsigned long gpfn, unsigned long dmfn);
void dch_replace_child_mfn(struct domain_clone_helper *dch,
        unsigned long smfn, unsigned long *pdmfn);

struct clone_child_info {
    domid_t domid;
    uint32_t ring_id;
    unsigned long start_info_mfn;
};

struct clone_op_state {
    bool in_progress;
    struct domain_clone_helper dch;
    struct cpu_user_regs saved_regs;
    unsigned long stack_pages;
    uint8_t saved_evtchn_upcall_mask;
    struct clone_child_info *child_info;
    uint32_t nr_requested;
    uint32_t nr_created;
    uint32_t nr_queued_to_notification;
    uint32_t nr_queued_to_completion;
    uint32_t nr_done;
};

struct cloning_domain {
    bool enabled;
    bool triggered;/*TODO rename; disable if no COWed page remaining */
    bool fuzzing;
    struct clone_op_state state;
    void *gfn_info_pool;
    struct {
        void *shared_info;
        void **p2m_fll_linear;
    } fuzzing_backup;
};

int cloning_domctl(struct domain *d, struct xen_domctl_cloning_op *cloneop);

int clone_fini(struct domain *d);

#endif /* __XEN_CLONE_H__ */
