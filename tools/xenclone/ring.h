/******************************************************************************
 * Copyright (c) 2020 Costin Lupu
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

#ifndef __XENCLONE_RING_H__
#define __XENCLONE_RING_H__

#include <xen/io/ring.h>
#include "mem.h"

#if XENCLONED_DEBUG_RING
#define DEBUG_RING(...)     DEBUG(__VA_ARGS__)
#else
#define DEBUG_RING(...)
#endif

#define RING_IDX(r, idx) ((idx) & (RING_SIZE(r) - 1))


#define __RING_COPY_REQ(src_fring, dst_fring, idx) \
({ \
	sreq = RING_GET_REQUEST(src_fring, idx); \
	dreq = RING_GET_REQUEST(dst_fring, idx); \
	*dreq = *sreq; \
	DEBUG_RING("\treq[%d] = %d", idx, sreq->gref); \
})
#define RING_COPY_REQ(src_fring, dst_fring, idx) \
({ \
	typeof((src_fring)->sring->ring[0]) *sreq, *dreq; \
	__RING_COPY_REQ(src_fring, dst_fring, idx); \
})

#define RING_DEEP_COPY_REQ(src_fring, dst_fring, idx, src_domid, dst_domid) \
({ \
	typeof((src_fring)->sring->ring[0].req) *sreq, *dreq; \
	__RING_COPY_REQ(src_fring, dst_fring, idx); \
	rc = grant_ref_clone(sreq->gref, src_domid, dst_domid); \
})


#define __RING_COPY_RSP(src_fring, dst_fring, idx) \
({ \
	srsp = RING_GET_RESPONSE(src_fring, idx); \
	drsp = RING_GET_RESPONSE(dst_fring, idx); \
	*drsp = *srsp; \
	DEBUG_RING("\trsp[%d] = %d", idx, srsp->id); \
})
#define RING_COPY_RSP(src_fring, dst_fring, idx) \
({ \
	typeof((src_fring)->sring->ring[0].rsp) *srsp, *drsp; \
	__RING_COPY_RSP(src_fring, dst_fring, idx); \
})


#define RING_COPY(src_fring, dst_fring, src_domid, dst_domid) \
({ \
	RING_IDX idx = 0; \
	int rc = 0; \
	\
	if (RING_IDX(src_fring, (src_fring)->sring->rsp_prod) <= RING_IDX(src_fring, (src_fring)->sring->req_prod)) { \
		while (idx < (src_fring)->sring->rsp_prod) { \
			RING_COPY_RSP(src_fring, dst_fring, idx); \
			idx++; \
		} \
		while (idx < (src_fring)->sring->req_prod) { \
			rc = RING_DEEP_COPY_REQ(src_fring, dst_fring, idx, src_domid, dst_domid); \
			if (rc) { \
				PERROR("Failed to copy shared memory"); \
				goto __out_rc; \
			} \
			idx++; \
		} \
		while (idx < RING_SIZE(src_fring)) { \
			RING_COPY_RSP(src_fring, dst_fring, idx); \
			idx++; \
		} \
	} else { \
		while (idx < (src_fring)->sring->req_prod) { \
			rc = RING_DEEP_COPY_REQ(src_fring, dst_fring, idx, src_domid, dst_domid); \
			if (rc) { \
				PERROR("Failed to copy shared memory"); \
				goto __out_rc; \
			} \
			idx++; \
		} \
		while (idx < (src_fring)->sring->rsp_prod) { \
			RING_COPY_RSP(src_fring, dst_fring, idx); \
			idx++; \
		} \
		while (idx < RING_SIZE(src_fring)) { \
			rc = RING_DEEP_COPY_REQ(src_fring, dst_fring, idx, src_domid, dst_domid); \
			if (rc) { \
				PERROR("Failed to copy shared memory"); \
				goto __out_rc; \
			} \
			idx++; \
		} \
	} \
__out_rc: \
	rc; \
})

#endif /* __XENCLONE_RING_H__ */
