/*
 * Copyright (c) 2023 deadcafe.beef@gmail.com All Rights Reserved.
 *
 * Unauthorized inspection, duplication, utilization or modification
 * of this file is prohibited.  Other related documents, whether
 * explicitly marked or implied, may also fall under this copyright.
 * Distribution of information obtained from this file and other related
 * documents to a third party is not permitted under any circumstances.
 */

#ifndef _APP_MBUF_H_
#define _APP_MBUF_H_

#include <rte_mbuf.h>
#include <rte_prefetch.h>

static inline void
app_mbuf_prefetch(struct rte_mbuf *m)
{
    (void) m;
}

#endif /* !_APP_MBUF_H_ */
