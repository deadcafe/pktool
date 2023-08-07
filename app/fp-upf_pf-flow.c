/** @addtogroup fp
 *  @{
 *    @addtogroup fp-modules
 *    @{
 *      @addtogroup upf_pf
 *      @{
 *        @addtogroup dataplane
 *        @{
 *
 *  @file     fp-modules/upf_pf/dataplane/fp-upf_pf-flow.c
 *  @brief    flow cache
 *
 */

/*
 * Copyright (c) 2023 deadcafe.beef@gmail.com All Rights Reserved.
 *
 * Unauthorized inspection, duplication, utilization or modification
 * of this file is prohibited.  Other related documents, whether
 * explicitly marked or implied, may also fall under this copyright.
 * Distribution of information obtained from this file and other related
 * documents to a third party is not permitted under any circumstances.
 */

#include <sys/queue.h>
#include <immintrin.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <rte_hash_crc.h>
#include <rte_hash.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_prefetch.h>

#if defined(DPDK_DIRECT_AP)	/* for UT */
# define LOG_UPF_PF(type, fmt, args...)                                  \
        fprintf(stderr, "%s:%d: " fmt "\n", __func__, __LINE__, ## args)
# define TRACE_UPF_PF(fmt, args...)	LOG_UPF_PF(DEBUG, fmt, ## args)
#else	/* !DPDK_DIRECT_AP */
# include <fpn.h>
# include <fpn-intercore.h>
# include <fp-includes.h>
# include <fp-log.h>
# include <fp-bulk.h>
# include "fp-upf_pf-var.h"
# include "fp-upf_pf.h"
#endif	/* !DPDK_DIRECT_AP */

#include "fp-upf_pf-flow.h"
#include "fp-upf_pf-utest.h"


/**
 * @struct  fp_upf_pf_flow_cache_s
 * @brief   flow cache table per lcore
 */
struct fp_upf_pf_flow_cache_s {
        struct fp_upf_pf_flow_list_s head;	/*!< used flow chain */
        uint64_t hits;				/*!< hit counter */
        uint64_t miss;				/*!< miss counter */
        uint64_t recycles;			/*!< re-cycle flow counter */
        uint64_t cycles;			/*!< cpu cycles */
        struct rte_hash *hash;			/*!< hash table */

        unsigned nb_flows;	/*!< number of flows */
        int lcore_id;		/*!< lcore ID */

        uint64_t find;		/*!< hash find call counter */
	uint64_t add;		/*!< hash add counter */
	uint64_t del;		/*!< hash del counter */
        uint64_t exist;		/*!< hash add exist counter */
        uint64_t reject;	/*!< hash reject counter */
        uint64_t priority;	/*!< hash low priority counter */
        uint64_t del_errs;	/*!< hash del error counter (Bug) */
        uint64_t add_errs;	/*!< hash add error counter (Bug) */
};

/*
 * compare 16 bytes
 */
static inline int
cmp_k16(const void *key1,
        const void *key2)
{
        const __m128i k1 = _mm_loadu_si128((const __m128i *) key1);
        const __m128i k2 = _mm_loadu_si128((const __m128i *) key2);
        const __m128i x = _mm_xor_si128(k1, k2);
        return !_mm_test_all_zeros(x, x);
}

static inline int
cmp_k32(const void *key1,
        const void *key2)
{
        const __m256i k1 = _mm256_loadu_si256((const __m256i *) key1);
        const __m256i k2 = _mm256_loadu_si256((const __m256i *) key2);
        const __m256i x = _mm256_xor_si256(k1, k2);
        return !_mm256_testz_si256(x, x);
}

static inline int
cmp_k48(const void *key1,
        const void *key2)
{
        return cmp_k32(key1, key2) ||
                cmp_k16((const char *) key1 + 32,
                        (const char *) key2 + 32);
}

/*
 *
 */
static inline int
cmp_flow_key(const void *key1,
             const void *key2,
             size_t len __rte_unused)
{
        const struct fp_upf_pf_flow_s *flow1 = key1;
        const struct fp_upf_pf_flow_s *flow2 = key2;

        return cmp_k48(&flow1->key, &flow2->key);
}

/*
 * calc hash value
 */
static inline uint32_t
flow_hash(const void *k,
          uint32_t len,
          uint32_t init)
{
        const struct fp_upf_pf_flow_s *flow = k;

        len = sizeof(flow->key);	/* length over write */
        return rte_hash_crc(&flow->key, len, init);
}

/*
 * for debug
 */
static struct fp_upf_pf_flow_cache_s *FlowCache[RTE_MAX_LCORE];

/*
 * called per Rx thread
 */
struct fp_upf_pf_flow_cache_s *
fp_upf_pf_flow_cache_create(int lcore_id,
                            unsigned nb_flows)
{
        char name[RTE_HASH_NAMESIZE];
        unsigned extra_flag = 0;
        struct fp_upf_pf_flow_cache_s *fcache = NULL;

        TRACE_UPF_PF("start. %d nb_flows:%u", rte_lcore_id(), nb_flows);
	if (lcore_id < 0 || lcore_id >= RTE_MAX_LCORE) {
                LOG_UPF_PF(ERR, "invalid lcore_id:%d", lcore_id);
		return NULL;
        }
        if (FlowCache[lcore_id]) {
                LOG_UPF_PF(ERR, "already exist flow cache. lcore_id:%d",
                           lcore_id);
                return NULL;
        }

        snprintf(name, sizeof(name), "flow hash_%d", lcore_id);

        //        extra_flag |= RTE_HASH_EXTRA_FLAGS_EXT_TABLE;
        if (rte_cpu_get_flag_enabled(RTE_CPUFLAG_RTM))
                extra_flag |= RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT;

        struct rte_hash_parameters param = {
                .name               = name,
                .entries            = rte_align32pow2(nb_flows + 1),
                .key_len            = sizeof(struct fp_upf_pf_flow_s),
                .hash_func          = flow_hash,
                .hash_func_init_val = 0,
                .socket_id          = rte_socket_id(),
                .extra_flag         = extra_flag,
        };

        fcache = rte_zmalloc_socket(NULL, sizeof(*fcache),
                                    RTE_CACHE_LINE_SIZE, param.socket_id);
        if (fcache) {
                memset(fcache, -1, sizeof(*fcache));
                fp_upf_pf_flow_counter_clear(fcache);

                TAILQ_INIT(&fcache->head);
                fcache->nb_flows = nb_flows;
                fcache->hash = rte_hash_create(&param);
                if (fcache->hash) {
			fcache->lcore_id = lcore_id;
                        rte_hash_set_cmp_func(fcache->hash, cmp_flow_key);
                        FlowCache[lcore_id] = fcache;
                } else {
                        fp_upf_pf_flow_cache_free(fcache);
                        fcache = NULL;
                }
        } else {
                LOG_UPF_PF(ERR, "failed to alloc flow cache. lcore_id:%d nb:%u",
                           lcore_id, nb_flows);
        }

        TRACE_UPF_PF("end. fcache:%p lcore:%d", fcache, lcore_id);
        return fcache;
}

/*
 * destroy flow cache
 */
void
fp_upf_pf_flow_cache_free(struct fp_upf_pf_flow_cache_s *fcache)
{
        if (fcache) {
                TRACE_UPF_PF("free fcache:%p lcore:%d",
                             fcache, fcache->lcore_id);

                fp_upf_pf_flow_reset(fcache);
                if (fcache->hash) {
			FlowCache[fcache->lcore_id] = NULL;
                        rte_hash_free(fcache->hash);
                        fcache->hash = NULL;
                }
                rte_free(fcache);
        }
}

/*
 *
 */
static inline int
flow_del(struct fp_upf_pf_flow_cache_s *fcache,
	 struct fp_upf_pf_flow_s *flow)
{
        int pos = rte_hash_del_key_with_hash(fcache->hash, flow, flow->sig);
        if (likely(pos >= 0)) {
                TAILQ_REMOVE(&fcache->head, flow, node);
		fcache->del += 1;

                flow->sig = 0;
                flow->data = NULL;
                flow->last_time = 0;
                flow->position = 0;
		pos = 0;
        } else {
                LOG_UPF_PF(ERR,
                           "failed to del key(%d). lcore:%d hash:%p flow:%p sig:%u",
                           pos, fcache->lcore_id, fcache->hash, flow, flow->sig);
        }
        return pos;
}

/*
 * return number of hit_mask bits.
 */
unsigned
fp_upf_pf_flow_find(struct fp_upf_pf_flow_cache_s *fcache,
                    struct fp_upf_pf_flow_s **keys,
                    unsigned nb_keys,
                    uint64_t *hit_mask,
                    struct fp_upf_pf_flow_s *flows[])
{
#if 0
        int32_t positions[64];
        hash_sig_t sigs[64];

	if (likely(!TAILQ_EMPTY(&fcache->head))) {
	        rte_prefetch0(TAILQ_FIRST(&fcache->head));
        	rte_prefetch0(TAILQ_LAST(&fcache->head, fp_upf_pf_flow_list_s));
	}

//        TRACE_UPF_PF("start. fcache:%p nb:%u", fcache, nb_keys);

        unsigned num = rte_hash_lookup_bulk_sig(fcache->hash,
                                                (const void **) keys,
                                                nb_keys,
                                                positions,
                                                sigs,
                                                hit_mask);
        uint64_t mask = *hit_mask;
        uint64_t now = rte_rdtsc();

        for (unsigned i = 0; mask; i++, mask >>= 1) {
                if (mask & UINT64_C(1)) {
                        /* found */

                        flows[i] = rte_hash_key_from_position(fcache->hash,
                                                              positions[i]);
                        TAILQ_REMOVE(&fcache->head, flows[i], node);

                        flows[i]->last_time = now;
                        TAILQ_INSERT_HEAD(&fcache->head, flows[i], node);
                }
        }

        if (num == nb_keys)
                goto end;

        mask = *hit_mask;
        unsigned hash_count = rte_hash_count(fcache->hash);
        for (unsigned i = 0; i < nb_keys; i++) {
                struct fp_upf_pf_flow_s *flow;

                if (mask & (UINT64_C(1) << i))
                        continue;	/* found flow */

                /* not found */

                unsigned old_count = hash_count;
                int position = rte_hash_add_key_with_hash(fcache->hash,
                                                          keys[i], sigs[i]);
                hash_count = rte_hash_count(fcache->hash);

                if (likely(position >= 0)) {
                        /* add success */
                        flow = rte_hash_key_from_position(fcache->hash,
                                                          position);

                        if ((likely(old_count < hash_count))) {
                                /* added */
                                flow->sig       = sigs[i];
                                flow->position  = position;
                                flow->data      = NULL;
                                fcache->add += 1;
                        } else {
                                /* already exist */
                                fcache->exist += 1;
                                TAILQ_REMOVE(&fcache->head, flow, node);
                        }
                        flow->last_time = now;
                        TAILQ_INSERT_HEAD(&fcache->head, flow, node);
                        flows[i] = flow;
                } else {
                        /* Bug */
                        flows[i] = NULL;
                        fcache->add_errs += 1;
                        LOG_UPF_PF(ERR, "failed to add key(%d). hash:%p sig:%u",
                                   position, fcache->hash, sigs[i]);
                }

                /* check limit */
                if (hash_count > fcache->nb_flows) {
                        flow = TAILQ_LAST(&fcache->head, fp_upf_pf_flow_list_s);
                        rte_prefetch0(TAILQ_PREV(flow,
                                                 fp_upf_pf_flow_list_s, node));
                        if (unlikely(flow_del(fcache, flow))) {
                                /* Bug */
                                fcache->del_errs += 1;
                        } else {
                                fcache->recycles += 1;
                                hash_count -= 1;
                        }
                }
        }

 end:
        fcache->hits += num;
        fcache->miss += (nb_keys - num);
        fcache->find += 1;
        fcache->cycles += (rte_rdtsc() - now);

//        TRACE_UPF_PF("end. num:%u mask:0x%"PRIx64, num, *hit_mask);
        return num;
#endif
        return 0;
}

/*
 *
 */
void
fp_upf_pf_flow_stats(const struct fp_upf_pf_flow_cache_s *fcache)
{
        LOG_UPF_PF(INFO, "<<< FlowCache Stats lcore:%d >>>",
                   fcache->lcore_id);
        uint64_t sum = fcache->hits + fcache->miss;
        if (!sum)
                sum = 1;
        uint64_t call = fcache->find;
        if (!call)
                call = 1;

        LOG_UPF_PF(INFO, "lcore:%d nb:%u count:%u",
                   fcache->lcore_id, fcache->nb_flows,
                   rte_hash_count(fcache->hash));
        LOG_UPF_PF(INFO, "hits:%"PRIu64" miss:%"PRIu64" %f%% recycles:%"PRIu64,
                   fcache->hits, fcache->miss,
                   (double) (fcache->hits * 100 / sum), fcache->recycles);
        LOG_UPF_PF(INFO, "find:%"PRIu64" add:%"PRIu64" del:%"PRIu64" recycles:%"PRIu64" exist:%"PRIu64" reject:%"PRIu64" priority:%"PRIu64,
                   fcache->find, fcache->add, fcache->del, fcache->recycles,
                   fcache->exist, fcache->reject, fcache->priority);
        LOG_UPF_PF(INFO, "add_errs:%"PRIu64" del_errs:%"PRIu64,
                   fcache->add_errs, fcache->del_errs);
        LOG_UPF_PF(INFO, "%"PRIu64" cycles/packet %"PRIu64" cycles/call",
                   fcache->cycles / sum, fcache->cycles / call);
}

/*
 * delete flow
 */
int
fp_upf_pf_flow_reject(struct fp_upf_pf_flow_cache_s *fcache,
                      struct fp_upf_pf_flow_s *flow)
{
        TRACE_UPF_PF("start. fcache:%p lcore:%d flow:%p sig:%u pos:%d",
                     fcache, fcache->lcore_id, flow, flow->sig, flow->position);

	int ret = flow_del(fcache, flow);
        fcache->reject += 1;

        TRACE_UPF_PF("end. ret:%d", ret);
        return ret;
}

/*
 * set hit of low priority flow
 */
void
fp_upf_pf_flow_low_priority(struct fp_upf_pf_flow_cache_s *fcache,
                            struct fp_upf_pf_flow_s *flow)
{
        TRACE_UPF_PF("start. fcache:%p lcore:%d flow:%p sig:%u",
                     fcache, fcache->lcore_id, flow, flow->sig);

        TAILQ_REMOVE(&fcache->head, flow, node);
        TAILQ_INSERT_TAIL(&fcache->head, flow, node);
        fcache->priority += 1;

        TRACE_UPF_PF("end.");
}

/*
 * clear counters
 */
void
fp_upf_pf_flow_counter_clear(struct fp_upf_pf_flow_cache_s *fcache)
{
        TRACE_UPF_PF("start. fcache:%p lcore:%d", fcache, fcache->lcore_id);

        fcache->hits = 0;
        fcache->miss = 0;
        fcache->recycles = 0;
        fcache->cycles = 0;
        fcache->del_errs = 0;
        fcache->add_errs = 0;
        fcache->add = 0;
        fcache->del = 0;
        fcache->reject = 0;
        fcache->priority = 0;
        fcache->find = 0;
        fcache->exist = 0;

        //        TRACE_UPF_PF("end. fcache:%p", fcache);
}

/*
 * reset  hash table
 */
void
fp_upf_pf_flow_reset(struct fp_upf_pf_flow_cache_s *fcache)
{
        TRACE_UPF_PF("start. fcache:%p lcore:%d", fcache, fcache->lcore_id);

#if 0	/* too slow */
        struct fp_upf_pf_flow_s *flow;
        TAILQ_FOREACH(flow, &fcache->head, node) {
                flow->sig = 0;
                flow->data = NULL;
                flow->last_time = 0;
        }
#endif

        rte_hash_reset(fcache->hash);
        TAILQ_INIT(&fcache->head);
        fp_upf_pf_flow_counter_clear(fcache);

        //        TRACE_UPF_PF("end. fcache:%p", fcache);
}

/*
 * for UT
 */
int
fp_upf_pf_flow_walk(struct fp_upf_pf_flow_cache_s *fcache,
                    int (*func)(struct fp_upf_pf_flow_s *, void *),
                    void *func_arg)
{
        struct fp_upf_pf_flow_s *flow;
        int ret = 0;

        TAILQ_FOREACH(flow, &fcache->head, node) {
                ret = func(flow, func_arg);
                if (ret)
                        break;
        }
        return ret;
}

/*
 * get flow cache
 * CLI front end
 */
struct fp_upf_pf_flow_cache_s *
fp_upf_pf_flow_cache_get(int lcore)
{
        struct fp_upf_pf_flow_cache_s *fcache = NULL;
        if (0 <= lcore && lcore < RTE_MAX_LCORE)
                fcache = FlowCache[lcore];
        return fcache;
}

#if !defined(DPDK_DIRECT_AP)
/*
 * stats handler
 */
static void
fcache_stats_handler(struct fpn_bulk *bulk __rte_unused,
                     void *arg)
{
        struct fp_upf_pf_flow_cache_s *fcache = arg;
        int lcore = rte_lcore_id();

        if (!fcache) {
                LOG_UPF_PF(ERR, "lcore:%d fcache is NULL", lcore);
                return;
        }
        if (fcache->lcore_id != lcore) {
                LOG_UPF_PF(ERR, "lcore:%d invalid fcache:%d",
                           lcore, fcache->lcore_id);
                return;
        }
        fp_upf_pf_flow_stats(fcache);
}

/*
 * reset handler
 */
static void
fcache_reset_handler(struct fpn_bulk *bulk __rte_unused,
                     void *arg)
{
        struct fp_upf_pf_flow_cache_s *fcache = arg;
        int lcore = rte_lcore_id();

        if (!fcache) {
                LOG_UPF_PF(ERR, "lcore:%d fcache is NULL", lcore);
                return;
        }
        if (fcache->lcore_id != lcore) {
                LOG_UPF_PF(ERR, "lcore:%d invalid fcache:%d",
                           lcore, fcache->lcore_id);
                return;
        }
        fp_upf_pf_flow_reset(fcache);
}

/*
 * clear handler
 */
static void
fcache_clear_handler(struct fpn_bulk *bulk __rte_unused,
                     void *arg)
{
        struct fp_upf_pf_flow_cache_s *fcache = arg;
        int lcore = rte_lcore_id();

        if (!fcache) {
                LOG_UPF_PF(ERR, "lcore:%d fcache is NULL", lcore);
                return;
        }
        if (fcache->lcore_id != lcore) {
                LOG_UPF_PF(ERR, "lcore:%d invalid fcache:%d",
                           lcore, fcache->lcore_id);
                return;
        }
        fp_upf_pf_flow_counter_clear(fcache);
}

/*
 * flow cache control
 */
int
fp_upf_pf_flow_cache_ctrl(struct fp_upf_pf_flow_cache_s *fcache,
                          enum fp_upf_pf_flow_ctrl_e ctrl)
{
        int ret = -1;
        struct fpn_bulk bulk;
        void (*handler)(struct fpn_bulk *, void *) = NULL;

        if (!fcache) {
                LOG_UPF_PF(ERR, "fcache is NULL");
                goto end;
        }

        fpn_bulk_clear(&bulk);

        switch (ctrl) {
        case FP_UPF_PF_FLOW_CTRL_STATS:
                handler = fcache_stats_handler;
                break;
        case FP_UPF_PF_FLOW_CTRL_CLEAR:
                handler = fcache_clear_handler;
                break;
        case FP_UPF_PF_FLOW_CTRL_RESET:
                handler = fcache_reset_handler;
                break;
        default:
                LOG_UPF_PF(ERR, "invalid ctrl:%d", ctrl);
                goto end;
        }
        ret = fpn_intercore_enqueue(&bulk, fcache->lcore_id,
                                    handler, fcache);
        if (ret) {
                LOG_UPF_PF(ERR, "failed to enqueue:%d", fcache->lcore_id);
        }
 end:
        return ret;
}
#endif	/* !DPDK_DIRECT_AP */

#if 0
/*******************************************************
 * Unit Test code
 *******************************************************/

static int
verify_flow(struct fp_upf_pf_flow_s *flow,
            void *arg)
{
        unsigned *counter = arg;
        unsigned *data = flow->data;
        int ret = 0;

	if (data) {
		LOG_UPF_PF(INFO, "flow:%p counter:%u data:%u",
                           flow, *counter, *data);
        	if (*data + *counter != 63)
                	ret = -1;
	}

        *counter += 1;
        return ret;
}

/*
 *
 */
static int
raw_test(struct fp_upf_pf_flow_cache_s *fcache)
{
        struct fp_upf_pf_flow_s key[64];
        struct fp_upf_pf_flow_s *key_p[64];
        int ret = 0;

        for (unsigned i = 0; i < 64; i++) {
                key_p[i] = &key[i];
                memset(key_p[i], 0, sizeof(*key_p[i]));
        }

        unsigned max = rte_align32pow2(fcache->nb_flows + 1);
        for (unsigned addr = 0; !ret && addr < max; addr += 64) {
                unsigned i;
                uint64_t mask;
                unsigned num;

                for (i = 0; (i < 64) && (i + addr < max); i++)
                        key[i].key.l3.ipv4.src = addr + i;

                unsigned nb_keys = i;
                int32_t positions[64];
                hash_sig_t sigs[64];

                num = rte_hash_lookup_bulk_sig(fcache->hash,
                                               (const void **) key_p,
                                               nb_keys,
                                               positions,
                                               sigs,
                                               &mask);
                if (num) {
                        LOG_UPF_PF(ERR, "mismatched num. num:%u key:%u",
                                   num, addr + i);
                        ret = -1;
                        break;
                }

                for (i = 0; i < nb_keys; i++) {
                        positions[i] = rte_hash_add_key_with_hash(fcache->hash,
                                                                  key_p[i],
                                                                  sigs[i]);

                        if (positions[i] < 0) {
                                LOG_UPF_PF(ERR, "failed to add. %d key:%u",
                                           positions[i], addr + i);
                                ret = -1;
                                break;
                        }
                }
        }

        fp_upf_pf_flow_stats(fcache);
        fp_upf_pf_flow_reset(fcache);

        return ret;
}

/*
 * cleared check
 */
static bool
is_cleared(const struct fp_upf_pf_flow_cache_s *fcache)
{
        return (TAILQ_EMPTY(&fcache->head) &&
                !fcache->hits &&
                !fcache->miss &&
                !fcache->recycles &&
                !fcache->del_errs &&
                !fcache->add_errs &&
                !fcache->add &&
                !fcache->del &&
                !fcache->exist &&
                !fcache->find &&
                !fcache->reject &&
                !fcache->priority &&
                fcache->nb_flows &&
                rte_hash_count(fcache->hash) == 0);
}

/*
 * hash size test
 */
static int
max_test(int lcore_id)
{
        unsigned nb = 1024;
        struct fp_upf_pf_flow_cache_s *fcache = NULL;
        struct fp_upf_pf_flow_s key[64];
        struct fp_upf_pf_flow_s *key_p[64];
        int ret = 0;

        for (unsigned i = 0; i < 64; i++) {
                key_p[i] = &key[i];
                memset(key_p[i], 0, sizeof(*key_p[i]));
        }

        while (!ret &&
               (fcache = fp_upf_pf_flow_cache_create(lcore_id, nb)) != NULL) {

                /* check cleared counters */
                if (!is_cleared(fcache)) {
                        LOG_UPF_PF(ERR, "flowCache Bad init! nb:%u", nb);
			fp_upf_pf_flow_stats(fcache);
                        ret = -1;
                        continue;
                }

                if(raw_test(fcache)) {
                        ret = -1;
                        continue;
                } else {
                        LOG_UPF_PF(INFO, "raw test Ok.");
                }

                unsigned max = nb << 1;
                for (unsigned addr = 0; addr < max; addr += 64) {
                        unsigned i;
                        uint64_t mask;
                        unsigned num;

                        for (i = 0; (i < 64) && (i + addr < max); i++)
                                key[i].key.l3.ipv4.src = addr + i;

                        struct fp_upf_pf_flow_s *flows[64];

                        num = fp_upf_pf_flow_find(fcache, key_p, i,
                                                  &mask, flows);
                        if (num) {
                                LOG_UPF_PF(ERR, "mismatched num. num:%u", num);
                                ret = -1;
                                break;
                        }
                }

                fp_upf_pf_flow_stats(fcache);

                fp_upf_pf_flow_reset(fcache);
                if (!is_cleared(fcache)) {
                        LOG_UPF_PF(ERR, "flowCache Bad init! nb:%u", nb);
                        fp_upf_pf_flow_stats(fcache);
                        ret = -1;
                }
                fp_upf_pf_flow_cache_free(fcache);
                fcache = NULL;
                LOG_UPF_PF(INFO, "max test %u ok", nb);
                nb <<= 1;
        }

        if (!ret)
                LOG_UPF_PF(INFO, "lcore:%d, max test Ok. limit:%u",
                           lcore_id, nb >> 1);

        if (fcache)
                fp_upf_pf_flow_cache_free(fcache);

        return ret;
}

static int
normal_test(int lcore_id)
{
        struct fp_upf_pf_flow_cache_s *fcache = NULL;
        int ret = -1;

        fcache = fp_upf_pf_flow_cache_create(lcore_id, 1024);
        if (!fcache) {
                LOG_UPF_PF(ERR, "failed flow cache create.");
                goto end;
        }

        struct fp_upf_pf_flow_s key[64];
        struct fp_upf_pf_flow_s *key_p[64];
        unsigned data[64];
        for (unsigned i = 0; i < 64; i++) {
                data[i] = i;
                key_p[i] = &key[i];
                memset(&key_p[i]->key, 0, sizeof(key_p[i]->key));
                key_p[i]->key.l3.ipv4.src = i;
        }

        struct fp_upf_pf_flow_s *flows[64];
        unsigned num;
        uint64_t hit_mask;

        /* first lookup */
        num = fp_upf_pf_flow_find(fcache, key_p, 64, &hit_mask, flows);
        if (num) {
                LOG_UPF_PF(ERR, "invalid found num. %u", num);
                goto end;
        }
        if (hit_mask) {
                LOG_UPF_PF(ERR, "invalid hit_mask:0x%"PRIx64, hit_mask);
                goto end;
        }
        if (fcache->hits != 0 || fcache->miss != 64) {
                LOG_UPF_PF(ERR, "invalid counter hits:%"PRIu64" miss:%"PRIu64,
                           fcache->hits, fcache->miss);
                goto end;
        }

        for (unsigned i = 0; i < 64; i++) {
                if (flows[i]) {
                        flows[i]->data = &data[i];
                } else {
                        LOG_UPF_PF(ERR, "nothing flow:%u", i);
                        goto end;
                }
        }

        /* second lookup */
        num = fp_upf_pf_flow_find(fcache, key_p, 64, &hit_mask, flows);
        if (num != 64) {
                LOG_UPF_PF(ERR, "invalid found num. %u", num);
                goto end;
        }
        if (hit_mask != UINT64_C(-1)) {
                LOG_UPF_PF(ERR, "invalid hit_mask:0x%"PRIx64, hit_mask);
                goto end;
        }
        if (fcache->hits != 64 || fcache->miss != 64) {
                LOG_UPF_PF(ERR, "invalid counter hits:%"PRIu64" miss:%"PRIu64,
                           fcache->hits, fcache->miss);
                goto end;
        }

        /* check data pointer */
        for (unsigned i = 0; i < 64; i++) {
                if (flows[i]->data != &data[i]) {
                        LOG_UPF_PF(ERR, "invalid flow %u data:%p",
                                   i, flows[i]->data);
                        goto end;
                }
        }

        /* check order */
        unsigned count = 0;
        if (fp_upf_pf_flow_walk(fcache, verify_flow, &count)) {
                LOG_UPF_PF(ERR, "walk failed %u", count);
                goto end;
        }
	LOG_UPF_PF(INFO, "walk Ok");

        uint64_t del_cnt = fcache->del;
        uint64_t add_cnt = fcache->add;

        for (unsigned i = 0; i < 64; i++) {
                if (fp_upf_pf_flow_reject(fcache, flows[i])) {
                        LOG_UPF_PF(ERR, "reject failed %u", i);
                        goto end;
                }
        }

	int hcnt = rte_hash_count(fcache->hash);
        if (hcnt ||
            !TAILQ_EMPTY(&fcache->head) ||
            add_cnt != fcache->add ||
            del_cnt + 64 != fcache->del) {
                LOG_UPF_PF(ERR, "mismatched hash counter:%d", hcnt);
                goto end;
        }

        if (fcache->del_errs || fcache->add_errs) {
                LOG_UPF_PF(ERR, "major error");
                goto end;
        }

        LOG_UPF_PF(INFO, "normal Add/Del test Ok");
        ret = 0;
 end:
        if (fcache)
                fp_upf_pf_flow_cache_free(fcache);
        return ret;
}

static int
recycle_test(int lcore_id)
{
        struct fp_upf_pf_flow_cache_s *fcache = NULL;
        struct fp_upf_pf_flow_s key[129];
        struct fp_upf_pf_flow_s *key_p[129];
        struct fp_upf_pf_flow_s *flows[129];
        uint64_t mask;

        int ret = -1;

        for (unsigned i = 0; i < 129; i++) {
                key_p[i] = &key[i];
                memset(key_p[i], 0, sizeof(*key_p[i]));
                key[i].key.l3.ipv4.src = i;
        }

        fcache = fp_upf_pf_flow_cache_create(lcore_id, 128);
        if (!fcache) {
                goto end;
        }

        fp_upf_pf_flow_find(fcache, &key_p[0],  64, &mask, &flows[0]);
        fp_upf_pf_flow_find(fcache, &key_p[64], 64, &mask, &flows[64]);
        fp_upf_pf_flow_find(fcache, &key_p[128], 1, &mask, &flows[128]);

        struct fp_upf_pf_flow_s *last =
                TAILQ_LAST(&fcache->head, fp_upf_pf_flow_list_s);

        if (fcache->recycles != 1 || last != flows[1]) {
                LOG_UPF_PF(ERR, "mismatched recycle. last:%p %p",
                           last, flows[1]);
                fp_upf_pf_flow_stats(fcache);
                goto end;
        }

        /* order change */
        fp_upf_pf_flow_low_priority(fcache, flows[128]);
        last = TAILQ_LAST(&fcache->head, fp_upf_pf_flow_list_s);
        if (last != flows[128]) {
                LOG_UPF_PF(ERR, "mismatched last. last:%p %p",
                           last, flows[128]);
                fp_upf_pf_flow_stats(fcache);
                goto end;
        }

        fp_upf_pf_flow_find(fcache, &key_p[0], 1, &mask, &flows[0]);
        last = TAILQ_LAST(&fcache->head, fp_upf_pf_flow_list_s);
        if (fcache->recycles != 2 || last != flows[1]) {
                LOG_UPF_PF(ERR, "mismatched last. last:%p %p",
                           last, flows[1]);
                fp_upf_pf_flow_stats(fcache);
                goto end;
        }

        LOG_UPF_PF(INFO, "re-cycle test Ok");
        ret = 0;

 end:
        if (fcache)
                fp_upf_pf_flow_cache_free(fcache);
        return ret;
}

static int
skip_test(int lcore_id)
{
        struct fp_upf_pf_flow_cache_s *fcache = NULL;
        int ret = -1;

        fcache = fp_upf_pf_flow_cache_create(lcore_id, 1024);
        if (!fcache) {
                LOG_UPF_PF(ERR, "failed flow cache create.");
                goto end;
        }

        struct fp_upf_pf_flow_s key[64];
        struct fp_upf_pf_flow_s *flows[64];
        struct fp_upf_pf_flow_s *key_1[64];
        struct fp_upf_pf_flow_s *key_2[64];
        unsigned num;
        uint64_t mask;

        memset(key, 0, sizeof(key));
        for (unsigned i = 0; i < 64; i++) {
                key_1[i] = &key[i];
                key_2[i] = &key[i / 2];
                key_1[i]->key.l3.ipv4.src = i;
        }

        num = fp_upf_pf_flow_find(fcache, key_2, 64, &mask, flows);
        if (num ||
            fcache->add != 32 ||
            fcache->hits ||
            fcache->miss != 64 ||
            fcache->exist != 32 ||
            rte_hash_count(fcache->hash) != 32) {
                LOG_UPF_PF(ERR, "mismatched. num:%u", num);
                fp_upf_pf_flow_stats(fcache);
                goto end;
        }

        num = fp_upf_pf_flow_find(fcache, key_1, 64, &mask, flows);
        if (num != 32 ||
            fcache->add != 64 ||
            fcache->hits != 32 ||
            fcache->miss != 96 ||
            fcache->exist != 32 ||
            rte_hash_count(fcache->hash) != 64) {
                LOG_UPF_PF(ERR, "mismatched. num:%u", num);
                fp_upf_pf_flow_stats(fcache);
                goto end;
        }

        LOG_UPF_PF(INFO, "skip test Ok");
        ret = 0;

 end:
        if (fcache)
                fp_upf_pf_flow_cache_free(fcache);
        return ret;
}


/*
 *
 */
int
fp_upf_pf_flow_UT(int lcore_id)
{
        int ret = -1;

        if (max_test(lcore_id)) {
                LOG_UPF_PF(ERR, "failed max test. lcore:%d", lcore_id);
                goto end;
        }

        if (normal_test(lcore_id)) {
                LOG_UPF_PF(ERR, "failed normal test. lcore:%d", lcore_id);
                goto end;
        }

        if (recycle_test(lcore_id)) {
                LOG_UPF_PF(ERR, "failed recycle test. lcore:%d", lcore_id);
                goto end;
        }

        if (skip_test(lcore_id)) {
                LOG_UPF_PF(ERR, "failed skip test. lcore:%d", lcore_id);
                goto end;
        }

        LOG_UPF_PF(INFO, "flow test All ok.");
        ret = 0;
 end:
        return ret;
}

#ifdef CONFIG_MCORE_DEBUG
/****************************************************************************
 * unit test (fpdebug upf_pf-utest)
 ****************************************************************************/
int
test_cmp_k16(const void *key1, const void *key2)
{
        return cmp_k16(key1, key2);
}
int
test_cmp_k32(const void *key1, const void *key2)
{
        return cmp_k32(key1, key2);
}
int
test_cmp_k48(const void *key1, const void *key2)
{
        return cmp_k48(key1, key2);
}
int
test_cmp_flow_key(const void *key1, const void *key2,  size_t len)
{
        return cmp_flow_key(key1, key2, len);
}
uint32_t
test_flow_hash(const void *k, uint32_t len, uint32_t init)
{
        return flow_hash(k, len, init);
}
int
test_flow_del(struct fp_upf_pf_flow_cache_s *fcache,
         struct fp_upf_pf_flow_s *flow)
{
        return flow_del(fcache, flow);
}
void
test_fcache_stats_handler(struct fpn_bulk *bulk, void *arg)
{
        fcache_stats_handler(bulk, arg);
}
void
test_fcache_reset_handler(struct fpn_bulk *bulk, void *arg)
{
        fcache_reset_handler(bulk, arg);
}
void
test_fcache_clear_handler(struct fpn_bulk *bulk, void *arg)
{
        fcache_clear_handler(bulk, arg);
}

void
test_set_internal_flowcache(unsigned lcore_id, void *value)
{
        FlowCache[lcore_id] = value;
}
void *
test_get_internal_flowcache(unsigned lcore_id)
{
        return FlowCache[lcore_id];
}
#endif //CONFIG_MCORE_DEBUG
#endif //#if 0
