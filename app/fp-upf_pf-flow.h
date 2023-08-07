/** @addtogroup fp
 *  @{
 *    @addtogroup fp-modules
 *    @{
 *      @addtogroup upf_pf
 *      @{
 *        @addtogroup common
 *        @{
 *
 *  @file     fp-modules/upf_pf/common/fp-upf_pf-flow.h
 *  @brief    flow cache header file
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

#if !defined(_FP_UPF_PF_FLOW_H_) && defined(__FastPath__)
#define _FP_UPF_PF_FLOW_H_

#include <sys/queue.h>
#include <inttypes.h>

#include <rte_hash.h>

/**
 * @struct  fp_upf_pf_flow_key_s
 * @brief   flow key: 5 tuples + vrfid
 *          MUST be 48 bytes.
 */
struct fp_upf_pf_flow_key_s {
        uint32_t vrfid;

        struct {
                uint16_t l3;	/*!< L3 protocol ipv4/ipv6 ether_type */
                uint16_t l4;	/*!< L4 protocol ip_p,ip6_nxt (expand 16bits) */
        } proto;

        union {
                struct {
                        uint16_t type;	/*!< icmp type (expand 16bits) */
                        uint16_t zero;	/*!< padding, fixed Zero */
                } icmp;
                struct {
                        uint16_t src;   /*!< L4 source port. network byte order */
                        uint16_t dst;	/*!< L4 destination port. network byte order */
                } port;
        } l4;
        uint32_t zero;		/*!< padding, fixed Zero */

        union {
                struct {
                        uint32_t src;	/*!< IPv4 source address. network byte order */
                        uint32_t dst;	/*!< IPv4 destination address. network byte order */
                        uint64_t zero_0;	/*!< padding, fixed Zero */
                        __uint128_t zero_1;	/*!< padding, fixed Zero */
                } ipv4;
                struct {
                        __uint128_t src;	/*!< IPv6 source address. network byte order */
                        __uint128_t dst;	/*!< IPv6 destination address. network byte order */
                } ipv6;
        } l3;
} __attribute__((packed));

/**
 * @struct  fp_upf_pf_flow_s
 * @brief   flow structuter
 */
struct fp_upf_pf_flow_s {
        TAILQ_ENTRY(fp_upf_pf_flow_s) node;	/*!< tailq entry */
        struct fp_upf_pf_flow_key_s key;	/*!< hash key */

        uint64_t last_time;	/*!< last access cycles */
        void *data;		/*!< service data pointer */
        hash_sig_t sig;		/*!< hash signature */
        int position;		/*!< position */
} __attribute__((packed,aligned(RTE_CACHE_LINE_SIZE)));

TAILQ_HEAD(fp_upf_pf_flow_list_s, fp_upf_pf_flow_s);

/*****************************************************************************
 * API prototyes
 *****************************************************************************/
struct fp_upf_pf_flow_cache_s;

/**
 * @fn      fp_upf_pf_flow_cache_create
 *
 * @brief   create flow cache.
 *
 * @param[in]  lcore_id
 *   本 flow cache を保持する lcore ID.
 * @param[in]  nb_flow
 *   Max Number of flows. 16M -1 が上限だが 12M 程度が実用上限。
 *   2 のべき乗倍の 80% 程度を目安に設定する。
 *
 * @return  struct fp_upf_pf_flow_cache_s *
 *          NULL  fail
 *
 * @note    fastpath module の core 毎の初期化時に呼び出すことを想定している。
 *
 */
extern struct fp_upf_pf_flow_cache_s *
fp_upf_pf_flow_cache_create(int lcore_id, unsigned nb_flows);

/**
 * @fn      fp_upf_pf_flow_cache_free
 *
 * @brief   free flow cache.
 *
 * @param[in]  fcache
 *   flow cache pointer
 *
 * @return  void
 *
 * @note    nothing
 *
 */
extern void
fp_upf_pf_flow_cache_free(struct fp_upf_pf_flow_cache_s *fcache);

/**
 * @fn      fp_upf_pf_flow_find
 *
 * @brief   find flow bulk API.
 *
 * @param[in]  fcache
 *  flow cache pointer
 * @param[in]  keys
 *  key pointers array.key の未設定領域は zero padding.
 * @param[in]  nb_keys
 *  number of keys. <= 64.
 * @param[out] hit_mask
 *  bitmask of hits. 見つかった flow を bit on のbitmaskで返す。
 * @param[out] flows
 *  found flow pointers.
 * @return   population count of hits bitmask.
 *
 * @note    見つからないflowについては当該 flowを登録した上で、data pointer を NULL にした、
 *          flow pointer を返す（bitmap off）。
 *          最大flow数を越えた場合は参照が古い順に re-cycleされる。
 *
 */
extern unsigned
fp_upf_pf_flow_find(struct fp_upf_pf_flow_cache_s *fcache,
                    struct fp_upf_pf_flow_s **keys,
                    unsigned nb_keys,
                    uint64_t *hit_mask,
                    struct fp_upf_pf_flow_s *flows[]);

/**
 * @fn      fp_upf_pf_flow_reject
 *
 * @brief   指定 flow を cache から外す。
 *
 * @param[in]  fcache
 *  flow cache pointer
 * @param[in]  flow
 *  cache から外す flow pointer
 *
 * @return   0 <= flow position.
 *           0 >  fail
 *
 * @note    nothing
 *
 */
extern int
fp_upf_pf_flow_reject(struct fp_upf_pf_flow_cache_s *fcache,
                      struct fp_upf_pf_flow_s *flow);

/**
 * @fn      fp_upf_pf_flow_low_priority
 *
 * @brief   flow を recycle 候補にする。
 *
 * @param[in]   fcache
 *  flow cache pointer
 * @param[in]  flow
 *  flow pointer
 *
 * @return  void
 *
 * @note    当該 flow の参照履歴を一番古くする。
 *
 */
extern void
fp_upf_pf_flow_low_priority(struct fp_upf_pf_flow_cache_s *fcache,
                            struct fp_upf_pf_flow_s *flow);

/**
 * @fn      fp_upf_pf_flow_reset
 *
 * @brief   reset flow cache.
 *
 * @param[in]   fcache
 *   flow cache pointer

 * @return  void
 *
 * @note    初期状態に戻す。
 *
 */
extern void
fp_upf_pf_flow_reset(struct fp_upf_pf_flow_cache_s *fcache);


/**
 * @fn      fp_upf_pf_flow_counter_clear
 *
 * @brief   Zero clear counter in flow cache.
 *
 * @param[in] fcache
 *  flow cahce pointer
 *
 * @return  void
 *
 * @note    for debug use.
 *
 */
extern void
fp_upf_pf_flow_counter_clear(struct fp_upf_pf_flow_cache_s *fcache);

/**
 * @fn      fp_upf_pf_flow_stats
 *
 * @brief   指定 lcore の flow cache をlog出力する
 *
 * @param[in] fcache
 *  flow cache pointer
 *
 * @return  void
 *
 * @note    for debug use(CLI).
 *
 */
extern void
fp_upf_pf_flow_stats(const struct fp_upf_pf_flow_cache_s *fcache);

/**
 * @fn      fp_upf_pf_flow_walk
 *
 * @brief   flow cache 内の flow を priority 順に walk する。
 *
 * @param[in]   fcache
 *  flow cache pointer
 * @param[in]  func
 *  flow 評価関数。zero 以外を返せば終了する。
 * @param[in]  arg
 *  評価関数用の任意の引数
 * @return  評価関数の返した値を返す。
 *
 * @note    UT debug用
 *
 */
extern int
fp_upf_pf_flow_walk(struct fp_upf_pf_flow_cache_s *fcache,
                    int (*func)(struct fp_upf_pf_flow_s *flow, void *arg),
                    void *arg);

/**
 * @fn      fp_upf_pf_flow_cache_get
 *
 * @brief   lcore に対応した flow cahce を求める。
 *
 * @param[in]   lcore
 *  lcore_id
 * @return  flow cache pointer
 *
 * @note    UT debug用
 *
 */
extern struct fp_upf_pf_flow_cache_s *
fp_upf_pf_flow_cache_get(int lcore);


enum fp_upf_pf_flow_ctrl_e {
        FP_UPF_PF_FLOW_CTRL_STATS = 0,
        FP_UPF_PF_FLOW_CTRL_CLEAR,
        FP_UPF_PF_FLOW_CTRL_RESET,

        FP_UPF_PF_FLOW_CTRL_NB,
};

/**
 * @fn      fp_upf_pf_flow_cache_ctrl
 *
 * @brief   exec flow cache ctrol on target lcore
 *
 * @param[in]   fcache
 *  flow cache pointer
 * @param[in]   ctrl
 *  control type
 * @return  0: success
 *          negative: faile
 * @note    UT debug用
 *
 */
extern int
fp_upf_pf_flow_cache_ctrl(struct fp_upf_pf_flow_cache_s *fcache,
                          enum fp_upf_pf_flow_ctrl_e ctrl);
/*
 * for Unit Test
 */
extern int
fp_upf_pf_flow_UT(int lcore_id);

#endif	/* !_FP_UPF_PF_FLOW_H_ */
