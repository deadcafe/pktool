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
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>

#include <rte_spinlock.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_hash_crc.h>
#include <rte_hash.h>
#include <rte_malloc.h>

#include <eng_thread.h>
#include <eng_addon.h>

#include "app_modules.h"
#include "global_db.h"
#include "task_hash.h"

#include "fp-upf_pf-flow.h"

#define ARRAYOF(_a)     (sizeof(_a)/sizeof(_a[0]))


#if 0
# define DBGPRINT(...)	fprintf(stderr, __VA_ARGS__)
#else
# define DBGPRINT(...)
#endif

#if 1
# define NB_PACKETS	(7 * 1024 * 1024)
#else
# define NB_PACKETS	(64)
#endif

#if 1
# define NB_FLOWS	(6 * 1024 * 1024)
#else
# define NB_FLOWS	(64)
#endif

struct test_pkt_s {
        struct rte_ether_hdr eth;
        struct rte_ipv4_hdr ip;
        struct rte_udp_hdr udp;
        TAILQ_ENTRY(test_pkt_s) node;
} __attribute__((packed, aligned(64)));

static struct test_pkt_s *
create_test_pkt(unsigned nb)
{
        struct test_pkt_s *top = rte_calloc(NULL, nb, sizeof(*top), 64);
        if (top) {
                TAILQ_HEAD(pkt_list_s, test_pkt_s) head =
                        TAILQ_HEAD_INITIALIZER(head);

                for (unsigned i = 0; i < nb; i++) {
                        if (i & 1)
                                TAILQ_INSERT_TAIL(&head, &top[i], node);
                        else
                                TAILQ_INSERT_HEAD(&head, &top[i], node);
                }

                struct test_pkt_s *pkt;
                for (unsigned i = 0; i < nb; i++) {
                        uint64_t r = rte_rand();

                        r %= nb;
                        pkt = &top[r];

                        TAILQ_REMOVE(&head, pkt, node);
                        TAILQ_INSERT_TAIL(&head, pkt, node);
                }

                uint32_t sip = 0x80000000;
                uint32_t dip = 0xa0000000;
                uint16_t sport = 1000;
                uint16_t dport = 8000;
                TAILQ_FOREACH(pkt, &head, node) {
                        pkt->eth.ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
                        pkt->ip.src_addr = sip++;
                        pkt->ip.dst_addr = dip++;
                        pkt->ip.next_proto_id = IPPROTO_UDP;
                        pkt->udp.src_port = sport++;
                        pkt->udp.dst_port = dport++;
                }
        } else {
                fprintf(stderr,
                        "failed to allocate packets:%u\n", nb);
                exit(0);
        }
        return top;
}

static inline void
set_key(struct fp_upf_pf_flow_key_s *key,
        const struct test_pkt_s *pkt)
{
        key->proto_l3 = pkt->eth.ether_type;
        key->proto_l4 = pkt->ip.next_proto_id;
        key->gtp_qfi = 0;
        key->gtp_teid = 0;
        key->vrfid = 0;

        if (key->proto_l4 == IPPROTO_UDP) {
                key->l4.port.src = pkt->udp.src_port;
                key->l4.port.dst = pkt->udp.dst_port;
        } else {
                fprintf(stderr, "not supported\n");
                exit(1);
        }

        if (key->proto_l3 == RTE_BE16(RTE_ETHER_TYPE_IPV4)) {
                key->l3.ipv4.src = pkt->ip.src_addr;
                key->l3.ipv4.dst = pkt->ip.dst_addr;

                key->l3.ipv4.zero_0 = 0;
                key->l3.ipv4.zero_1 = 0;
        } else {
                fprintf(stderr, "not supported\n");
                exit(1);
        }
}

static inline void
create_key(unsigned nb,
           struct fp_upf_pf_flow_s *flow[],
           struct test_pkt_s *pkt[])
{
        for (unsigned i = 0; i < nb; i++)
                set_key(&flow[i]->key, pkt[i]);
}

struct hash_test_s {
        struct fp_upf_pf_flow_cache_s *fcache;
        struct test_pkt_s *pkt_array;
        unsigned nb_packets;
        unsigned nb_flows;

        unsigned start;
        unsigned end;

        uint64_t sum;
        uint64_t hits;
        uint64_t expire;
};

static int
HashTaskInit(struct eng_conf_db_s *conf __rte_unused,
             struct eng_thread_s *th __rte_unused,
             struct eng_task_s *task)
{
        struct hash_test_s *test = (struct hash_test_s *) task->private_area;
        char name[32];

        snprintf(name, sizeof(name), "test hash%u", th->lcore_id);

	if (fp_upf_pf_flow_UT(th->lcore_id)) {
		fprintf(stderr, "test failed %d\n", th->lcore_id);
                exit(0);
	}
	fprintf(stderr, "test success %d\n", th->lcore_id);

        memset(test, 0, sizeof(*test));
        test->nb_packets = NB_PACKETS;
        test->nb_flows   = NB_FLOWS;
        test->sum = 1;
	test->expire = rte_rdtsc() + rte_get_tsc_hz();

        fprintf(stdout, "flow %s size:%zu key size:%zu\n", name,
                sizeof(struct fp_upf_pf_flow_s), sizeof(struct fp_upf_pf_flow_key_s));

        test->fcache = fp_upf_pf_flow_cache_create(th->lcore_id, NB_FLOWS);
        if (!test->fcache) {
                fprintf(stderr, "failed to create hash\n");
                exit(0);
        }

        test->pkt_array = create_test_pkt(test->nb_packets);

        return 0;
}

static inline void
prefetch_flow(struct fp_upf_pf_flow_s *flow)
{
        struct fp_upf_pf_flow_s *next = TAILQ_NEXT(flow, node);
        struct fp_upf_pf_flow_s *prev = TAILQ_PREV(flow, fp_upf_pf_flow_list_s, node);

        if (next)
                rte_prefetch0(next);

        if (prev)
                rte_prefetch0(prev);
}

static unsigned
HashTaskEntry(struct eng_thread_s *th __rte_unused,
              struct eng_task_s *task,
              uint64_t now)
{
        struct hash_test_s *test = (struct hash_test_s *) task->private_area;

#define BULK_SIZE	32

        unsigned start = rte_rand() % (test->nb_packets - BULK_SIZE);

        struct fp_upf_pf_flow_s key[BULK_SIZE];
        struct fp_upf_pf_flow_s *key_p[BULK_SIZE];
        struct test_pkt_s *pkt_p[BULK_SIZE];
        struct fp_upf_pf_flow_s *flows[BULK_SIZE];

        for (unsigned i = 0; i < ARRAYOF(key); i++) {
                pkt_p[i] = &test->pkt_array[start + i];
                key_p[i] = &key[i];
        }

        create_key(ARRAYOF(key_p), key_p, pkt_p);

        uint64_t mask;
        unsigned num;
        num = fp_upf_pf_flow_find(test->fcache,
                                  key_p,
                                  ARRAYOF(key_p),
                                  &mask,
                                  flows);

        DBGPRINT("start:%u cnt:%d\n", test->start, rte_hash_count(test->hash));
#if 0
        if (num != (ARRAYOF(key))) {
                fprintf(stderr, "not found some data:%u start:%u\n", num, start);
                exit(1);
        }
#endif
	test->hits += num;
        test->sum += ARRAYOF(key);
        if (test->expire < now) {
                struct fp_upf_pf_flow_cache_s *fcache =
                        fp_upf_pf_flow_cache_get(rte_lcore_id());

                fprintf(stderr, "hits:%"PRIu64" / sum:%"PRIu64" %f\n",
                        test->hits, test->sum,
                        (double) (test->hits) / (double) (test->sum));
                test->expire = now + (rte_get_tsc_hz() << 3);
		test->start = now;
		fp_upf_pf_flow_stats(fcache);
        }

        return num;
}

/*
 *
 */
static const struct eng_addon_s Addon = {
    .name       = "TkHash",
    .task_init  = HashTaskInit,
    .task_entry = HashTaskEntry,
};

static struct eng_addon_constructor_s AddonConstructor = {
    .addon = &Addon,
};

void
app_task_hash_register(void)
{
    eng_addon_register(&AddonConstructor);
}

#if 0
__attribute__((constructor))
static void debug_dump(void)
{
        printf("size key : %zu\n", sizeof(struct fp_upf_pf_flow_key_s));
        printf("size body: %zu\n", sizeof(struct fp_upf_pf_flow_s));
        exit(0);
}
#endif
