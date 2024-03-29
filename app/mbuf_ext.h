/*
 * Copyright (c) 2023 deadcafe.beef@gmail.com All Rights Reserved.
 *
 * Unauthorized inspection, duplication, utilization or modification
 * of this file is prohibited.  Other related documents, whether
 * explicitly marked or implied, may also fall under this copyright.
 * Distribution of information obtained from this file and other related
 * documents to a third party is not permitted under any circumstances.
 */

#ifndef _MBUF_EXT_H_
#define _MBUF_EXT_H_

#include <rte_net.h>

struct mbuf_ext_s {
    struct rte_net_hdr_lens hdr_lens;
    uint32_t teid;
} __attribute__((aligned(128)));

static inline struct mbuf_ext_s *
eng_mbuf2ext(struct rte_mbuf *m)
{
    return (struct mbuf_ext_s *) (m + 1);
}

#endif /* !_MBUF_EXT_H_ */
