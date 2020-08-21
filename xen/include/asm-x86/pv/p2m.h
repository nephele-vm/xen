/*
 * asm-x86/pv/p2m.h
 *
 * physical-to-machine interfaces for PV domains
 *
 * Copyright (C) 2020 Costin Lupu <costin.lupu@cs.pub.ro>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms and conditions of the GNU General Public
 * License, version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __X86_PV_P2M_H__
#define __X86_PV_P2M_H__

/*
 * P2M
 */

int p2m_fll_set_entry(struct domain *d, unsigned long gfn, unsigned long mfn);
int p2m_fll_get_entry(struct domain *d, unsigned long gfn, unsigned long *mfn);

int p2m_fll_get_lists_num(struct domain *d);
int p2m_fll_clone(struct domain *d, struct domain *s,
        struct domain_clone_helper *dch);

int p2m_fll_backup_save(struct domain *d);
int p2m_fll_backup_restore(struct domain *d);
void p2m_fll_backup_delete(struct domain *d);

struct p2m_pv_iter {
    unsigned long pfn_num;
    unsigned long *l3_list, l3_num, l3_idx;
    unsigned long *l2_list, l2_num, l2_idx;
    unsigned long *l1_list, l1_num, l1_idx;
};

static inline
int p2m_pv_iter_is_valid(struct p2m_pv_iter *ppi)
{
    return ppi->l1_idx != -1;
}

static inline
unsigned long p2m_pv_iter_data(struct p2m_pv_iter *ppi)
{
    return ppi->l1_list[ppi->l1_idx];
}

int p2m_pv_iter_start(struct domain *d, struct p2m_pv_iter *ppi);
int p2m_pv_iter_start_l2(struct p2m_pv_iter *ppi);
int p2m_pv_iter_start_l1(struct p2m_pv_iter *ppi);

static inline
void p2m_pv_iter_next(struct p2m_pv_iter *ppi)
{
    if ( ++ppi->l1_idx == ppi->l1_num )
    {
        /* new l1 list */
        if ( ++ppi->l2_idx == ppi->l2_num )
        {
            /* new l2 list */
            if ( ++ppi->l3_idx == ppi->l3_num )
            {
                /* the end */
                unmap_domain_page(ppi->l1_list);
                ppi->l1_idx = -1;
                unmap_domain_page(ppi->l2_list);
                ppi->l2_idx = -1;
                unmap_domain_page(ppi->l3_list);
                ppi->l3_idx = -1;
                return;
            }

            p2m_pv_iter_start_l2(ppi);
        }

        p2m_pv_iter_start_l1(ppi);
    }
}

/*
 * Page table
 */

void page_table_clone(unsigned long dmfn, unsigned long smfn,
        struct domain_clone_helper *dch);
void page_table_reset(unsigned long dmfn, unsigned long smfn,
        struct domain_clone_helper *dch);

int cloning_copy_special_pages(struct domain_clone_helper *dch,
        unsigned long va, unsigned long pages_num);

int do_domain_cow(struct domain *d, unsigned long va,
        unsigned long *new_mfn);


#endif /* __X86_PV_P2M_H__ */
