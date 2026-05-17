/**
 * Team: ASC - Ion Butura 334CB | Sheker Kotyrova 314CC
 * netem/main.c  –  Keysight Student Challenge 2026
 *
 * Network Emulator with pthreads-based scalable processing.
 *
 * Architecture
 * ============
 *
 *   DPDK lcore 0  → RX port 0 → classify() O(1) → enqueue PQ rings
 *   DPDK lcore 1  → RX port 1 → classify() O(1) → enqueue PQ rings
 *
 *   pthread pool (NUM_WORKER_THREADS, scalable to 1000):
 *     thread 0  → PQ0  → drop/dup/delay → TX
 *     thread 1  → PQ1  → drop/dup/delay → TX
 *     ...
 *     thread 10 → PQ10 → drop/dup/delay → TX
 *
 * Performance metrics:
 *   - Throughput (RX/TX pps) — measured every stats interval
 *   - Delay precision (µs error per PQ) — measured at drain time
 *   - CPU scalability — per-thread TX breakdown
 *
 * Runtime queue configuration (Bonus):
 *   A dedicated pthread reads commands from /tmp/netem_cmd (named pipe).
 *   Commands (one per line):
 *     drop <pq> <n> <m>     — drop n out of m packets on PQ
 *     dup  <pq> <n> <m>     — duplicate n out of m packets on PQ
 *     delay <pq> <us>       — set delay in microseconds on PQ
 *     reset <pq>            — clear all behaviours on PQ
 *     show                  — print current config to stderr
 *
 *   Example usage (from another terminal):
 *     echo "drop 2 1 5"  > /tmp/netem_cmd
 *     echo "delay 0 2000" > /tmp/netem_cmd
 *     echo "reset 3"      > /tmp/netem_cmd
 *
 *   Config is stored in pq_cfg_rt[] with atomic updates via
 *   __atomic builtins — no locks needed on the read path.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#define NETEM_CMD_PIPE  "/tmp/netem_cmd"

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_ring.h>
#include <rte_spinlock.h>

/* =========================================================
 * Constants
 * ========================================================= */
#define RTE_LOGTYPE_NETEM       RTE_LOGTYPE_USER1
#define MAX_PKT_BURST           32
#define BURST_TX_DRAIN_US       100
#define MEMPOOL_CACHE_SIZE      256
#define RX_DESC_DEFAULT         1024
#define TX_DESC_DEFAULT         1024
#define NB_PORTS                2

#define NUM_PQ                  11
#define DEFAULT_PQ              10

#define PQ_RING_SIZE            4096
#define DELAY_RING_SIZE         8192
#define DRAIN_CHECK_US          50

#define DELAY_PKT_POOL_SIZE     65536
#define DELAY_PKT_POOL_CACHE    64

#define NUM_WORKER_THREADS      11

/* =========================================================
 * Fixed packet offsets (GRE-over-IP, verified from hex dump)
 * ========================================================= */
#define OFF_GRE         0x22
#define OFF_OUTER_SRC   0x1a
#define OFF_OUTER_DST   0x1e
#define OFF_INNER_LEN   0x28
#define OFF_PAYLOAD     54
#define MIN_PKT_LEN     (OFF_PAYLOAD + 12)

static const uint8_t GRE_MAGIC[4]   = { 0x00, 0x00, 0x08, 0x00 };
static const uint8_t IP_40_0_0_8[4] = { 0x28, 0x00, 0x00, 0x08 };
static const uint8_t IP_30_0_0_8[4] = { 0x1e, 0x00, 0x00, 0x08 };

/* =========================================================
 * Per-queue behaviour
 * ========================================================= */
struct pq_config {
    uint32_t drop_n, drop_m;
    uint32_t dup_n,  dup_m;
    uint64_t delay_us;
};

/*
 * Runtime-mutable queue config.
 * Written only by the config thread, read by worker threads.
 * We use __atomic_store/__atomic_load on each uint64/uint32 field
 * so readers always see a consistent value without locks.
 * (Fields are independent, so partial updates are acceptable —
 *  worst case is one packet processed with a stale value.)
 */
static struct pq_config pq_cfg[NUM_PQ] = {
    { 1, 10, 0,  0,  0    },
    { 0, 0,  2,  10, 0    },
    { 0, 0,  0,  0,  500  },
    { 1, 10, 0,  0,  200  },
    { 0, 0,  3,  10, 0    },
    { 0, 0,  0,  0,  1000 },
    { 0, 0,  0,  0,  0    },
    { 2, 10, 0,  0,  0    },
    { 0, 0,  1,  10, 0    },
    { 1, 10, 1,  10, 500  },
    { 0, 0,  0,  0,  0    },
};

/*
 * Per-field atomic accessors.
 * uint32_t and uint64_t atomics are lock-free on x86 without -latomic.
 * Workers read each field independently — worst case is one packet
 * sees a mix of old/new values, which is acceptable for network emulation.
 */
static inline struct pq_config
pq_cfg_read(int pq)
{
    struct pq_config c;
    c.drop_n   = __atomic_load_n(&pq_cfg[pq].drop_n,   __ATOMIC_RELAXED);
    c.drop_m   = __atomic_load_n(&pq_cfg[pq].drop_m,   __ATOMIC_RELAXED);
    c.dup_n    = __atomic_load_n(&pq_cfg[pq].dup_n,    __ATOMIC_RELAXED);
    c.dup_m    = __atomic_load_n(&pq_cfg[pq].dup_m,    __ATOMIC_RELAXED);
    c.delay_us = __atomic_load_n(&pq_cfg[pq].delay_us, __ATOMIC_RELAXED);
    return c;
}

static inline void
pq_cfg_write(int pq, const struct pq_config *c)
{
    __atomic_store_n(&pq_cfg[pq].drop_n,   c->drop_n,   __ATOMIC_RELAXED);
    __atomic_store_n(&pq_cfg[pq].drop_m,   c->drop_m,   __ATOMIC_RELAXED);
    __atomic_store_n(&pq_cfg[pq].dup_n,    c->dup_n,    __ATOMIC_RELAXED);
    __atomic_store_n(&pq_cfg[pq].dup_m,    c->dup_m,    __ATOMIC_RELAXED);
    __atomic_store_n(&pq_cfg[pq].delay_us, c->delay_us, __ATOMIC_RELEASE);
}

static const char *pq_desc[NUM_PQ] = {
    "ACK / FIN+ACK",
    "SYN / SYN+ACK",
    "Large HTTP data",
    "HTTP resp header",
    "HTTP GET var A",
    "HTTP GET var B",
    "HTTP GET var C",
    "40.0.0.8 -> 30.0.0.8",
    "MAC aa:bb:cc",
    "MAC aa:bb:cd",
    "Default",
};

/* =========================================================
 * Delayed-packet entry
 * ========================================================= */
struct delayed_pkt {
    struct rte_mbuf *m;
    uint64_t         release_tsc;
    int              pq;
};

/* =========================================================
 * Per-PQ delay precision stats
 * ========================================================= */
struct delay_stats {
    uint64_t count;
    uint64_t sum_us;
    uint64_t max_us;
    uint64_t min_us;
} __rte_cache_aligned;

/* =========================================================
 * Globals
 * ========================================================= */
static volatile bool            force_quit;
static uint16_t                 nb_rxd = RX_DESC_DEFAULT;
static uint16_t                 nb_txd = TX_DESC_DEFAULT;
static struct rte_ether_addr    netem_ports_eth_addr[NB_PORTS];
static struct rte_eth_conf      port_conf = {
    .txmode = { .mq_mode = RTE_ETH_MQ_TX_NONE },
};
static struct rte_mempool      *netem_pktmbuf_pool = NULL;
static struct rte_mempool      *delay_pkt_pool     = NULL;
static rte_spinlock_t           tx_lock[NB_PORTS];
static uint64_t                 timer_period = 1;
static struct rte_ring         *pq_rings[NUM_PQ];
static struct delay_stats       pq_delay_stats[NUM_PQ];

/* Per-PQ end-to-end latency stats (RX timestamp → TX timestamp) */
struct latency_stats {
    uint64_t count;
    uint64_t sum_us;
    uint64_t min_us;
    uint64_t max_us;
} __rte_cache_aligned;
static struct latency_stats pq_lat_stats[NUM_PQ];

/* Last runtime command received — shown in dashboard */
static char last_cmd[128] = "none";
static pthread_mutex_t last_cmd_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t tput_prev_rx  = 0;
static uint64_t tput_prev_tx  = 0;
static uint64_t tput_prev_tsc = 0;
static double   tput_rx_pps   = 0.0;
static double   tput_tx_pps   = 0.0;

/* Number of TX queues actually configured (1 or NUM_WORKER_THREADS) */
static uint16_t port_nb_txq[NB_PORTS];

/* =========================================================
 * Per-RX-lcore context
 * ========================================================= */
struct rx_ctx {
    uint16_t rx_port;
    uint16_t tx_port;
    uint64_t stat_rx;
    uint64_t stat_overflow;
} __rte_cache_aligned;

/* =========================================================
 * Per-worker-thread context
 * ========================================================= */
struct worker_ctx {
    int                           thread_id;
    int                           pq_list[NUM_PQ];
    int                           nb_pq;
    struct rte_eth_dev_tx_buffer *tx_buf[NB_PORTS];
    struct rte_ring              *delay_ring;
    uint64_t                      pq_pkt_count[NUM_PQ];
    uint64_t                      stat_tx;
    uint64_t                      stat_dropped;
    uint64_t                      stat_duplicated;
    uint64_t                      stat_delayed;
    uint64_t                      stat_overflow;
    uint64_t                      stat_pq[NUM_PQ];
    struct delayed_pkt           *pending_dp;
    pthread_t                     thread;
} __rte_cache_aligned;

static struct rx_ctx     rx_ctx_arr[NB_PORTS];
static struct worker_ctx worker_ctx_arr[NUM_WORKER_THREADS];

/* =========================================================
 * TX helpers
 * P1: Per-worker TX queue when multi-queue supported → no lock.
 * Fallback to spinlock for single-queue drivers (PCAP).
 * ========================================================= */
static inline int
tx_buffer_locked(uint16_t port, struct rte_eth_dev_tx_buffer *buf,
                 struct rte_mbuf *m)
{
    /* buf is per-worker, port_nb_txq tells us if we need the lock */
    if (port_nb_txq[port] > 1) {
        /* Multi-queue: caller uses its own queue id → no contention */
        /* Queue id is encoded in the call site via wc->thread_id */
        return rte_eth_tx_buffer(port, 0, buf, m); /* qid set at call site */
    }
    rte_spinlock_lock(&tx_lock[port]);
    int sent = rte_eth_tx_buffer(port, 0, buf, m);
    rte_spinlock_unlock(&tx_lock[port]);
    return sent;
}

static inline int
tx_flush_locked(uint16_t port, struct rte_eth_dev_tx_buffer *buf)
{
    if (port_nb_txq[port] > 1) {
        return rte_eth_tx_buffer_flush(port, 0, buf);
    }
    rte_spinlock_lock(&tx_lock[port]);
    int sent = rte_eth_tx_buffer_flush(port, 0, buf);
    rte_spinlock_unlock(&tx_lock[port]);
    return sent;
}

/*
 * Proper per-worker TX — use wc->thread_id as queue index.
 * This is the main TX path used by worker threads.
 */
static inline int
tx_send(struct worker_ctx *wc, uint16_t port, struct rte_mbuf *m)
{
    uint16_t nb_txq = port_nb_txq[port];
    if (nb_txq > 1) {
        uint16_t qid = (uint16_t)(wc->thread_id % nb_txq);
        return rte_eth_tx_buffer(port, qid, wc->tx_buf[port], m);
    }
    rte_spinlock_lock(&tx_lock[port]);
    int sent = rte_eth_tx_buffer(port, 0, wc->tx_buf[port], m);
    rte_spinlock_unlock(&tx_lock[port]);
    return sent;
}

static inline int
tx_flush_worker(struct worker_ctx *wc, uint16_t port)
{
    uint16_t nb_txq = port_nb_txq[port];
    if (nb_txq > 1) {
        uint16_t qid = (uint16_t)(wc->thread_id % nb_txq);
        return rte_eth_tx_buffer_flush(port, qid, wc->tx_buf[port]);
    }
    rte_spinlock_lock(&tx_lock[port]);
    int sent = rte_eth_tx_buffer_flush(port, 0, wc->tx_buf[port]);
    rte_spinlock_unlock(&tx_lock[port]);
    return sent;
}

/* =========================================================
 * ANSI palette — restrained
 * ========================================================= */
#define RST   "\x1b[0m"
#define BOLD  "\x1b[1m"
#define DIM   "\x1b[2m"
#define RED   "\x1b[31m"
#define GRN   "\x1b[32m"
#define YLW   "\x1b[33m"
#define CYN   "\x1b[36m"
#define WHT   "\x1b[97m"

/* =========================================================
 * print_stats() — bordered, aligned, lightly colored
 *
 * ┌─────────────────────────────────────────────────────────────────────────┐
 * │ NETEM  threads:11  lcores:2  classify:O(1)                              │
 * ├─────────────────────────────────────────────────────────────────────────┤
 * │ RX   1000   TX    992   DROP    50   DUP    42   OVF   0                │
 * │ RX      0 pps   TX      0 pps                                           │
 * ├────┬────────────────────────┬───────┬──────┬─────┬──────────────────────┬──────────────────┤
 * │ PQ │ Description            │  Pkts │ Drop │ Dup │ Config               │ Delay error      │
 * ├────┼────────────────────────┼───────┼──────┼─────┼──────────────────────┼──────────────────┤
 * │  0 │ ACK / FIN+ACK          │   418 │   42 │   0 │ drop 1/10            │ —                │
 * │  2 │ Large HTTP data        │   243 │    0 │   0 │ 500us                │ avg  54us        │
 * ├────┴────────────────────────┴───────┴──────┴─────┴──────────────────────┴──────────────────┤
 * │ CPU  t0:376  t1:214  t2:243  t3:71  t4:20  t5:57  t6:11                                    │
 * └─────────────────────────────────────────────────────────────────────────────────────────────┘
 * ========================================================= */
static void
print_stats(void)
{
    /* Move cursor to top-left without clearing — eliminates flicker */
    printf("\x1b[H");

    /* ---- collect ---- */
    uint64_t total_rx = 0, total_tx = 0;
    uint64_t total_drop = 0, total_dup = 0, total_ov = 0;
    uint64_t pq_pkts[NUM_PQ] = {0};
    uint64_t pq_drop[NUM_PQ] = {0};
    uint64_t pq_dup[NUM_PQ]  = {0};

    for (int p = 0; p < NB_PORTS; p++) {
        total_rx += rx_ctx_arr[p].stat_rx;
        total_ov += rx_ctx_arr[p].stat_overflow;
    }
    for (int w = 0; w < NUM_WORKER_THREADS; w++) {
        struct worker_ctx *wc = &worker_ctx_arr[w];
        total_tx   += wc->stat_tx;
        total_drop += wc->stat_dropped;
        total_dup  += wc->stat_duplicated;
        total_ov   += wc->stat_overflow;
        for (int q = 0; q < NUM_PQ; q++)
            pq_pkts[q] += wc->stat_pq[q];
        for (int i = 0; i < wc->nb_pq; i++) {
            int q = wc->pq_list[i];
            if (pq_pkts[q] == 0) continue;
            uint64_t own = wc->stat_pq[q], tot = 0;
            for (int j = 0; j < wc->nb_pq; j++)
                tot += wc->stat_pq[wc->pq_list[j]];
            if (tot > 0) {
                pq_drop[q] += wc->stat_dropped    * own / tot;
                pq_dup[q]  += wc->stat_duplicated * own / tot;
            }
        }
    }

    /* ---- throughput ---- */
    uint64_t cur_tsc = rte_rdtsc();
    if (tput_prev_tsc > 0) {
        double dt = (double)(cur_tsc - tput_prev_tsc) /
                    (double)rte_get_tsc_hz();
        if (dt > 0.0) {
            tput_rx_pps = (double)(total_rx - tput_prev_rx) / dt;
            tput_tx_pps = (double)(total_tx - tput_prev_tx) / dt;
        }
    }
    tput_prev_rx  = total_rx;
    tput_prev_tx  = total_tx;
    tput_prev_tsc = cur_tsc;

    /*
     * Column layout (all visible widths):
     *  PQ   : 4   │  Desc : 24  │  Pkts : 7  │  Drop : 6
     *  Dup  : 5   │  Config : 30 │  DlyErr : 18
     *  Total separator width = 4+1+24+1+7+1+6+1+5+1+30+1+18 = 100
     */
#define C_PQ    4
#define C_DESC  24
#define C_PKTS  7
#define C_DROP  6
#define C_DUP   5
#define C_CFG   30
#define C_DLY   18
#define SEP_W   (C_PQ+1+C_DESC+1+C_PKTS+1+C_DROP+1+C_DUP+1+C_CFG+1+C_DLY+2)

    /* helper: print N copies of ch */
#define REP(ch, n) do { for(int _=0;_<(n);_++) printf(ch); } while(0)

    /* ---- top border ---- */
    printf("┌"); REP("─", SEP_W); printf("┐\n");

    /* title */
    printf("│ " BOLD "NETEM" RST
           "  threads:" BOLD "%d" RST
           "  lcores:" BOLD "%u" RST
           "  classify:" BOLD "O(1)" RST
           "%*s│\n",
           NUM_WORKER_THREADS, rte_lcore_count(),
           (int)(SEP_W - 5 - 10 - 1 - 9 - 1 - 13), "");

    /* totals separator */
    printf("├"); REP("─", SEP_W); printf("┤\n");

    /* totals line */
    printf("│  RX " BOLD "%7"PRIu64 RST
           "   TX " BOLD "%7"PRIu64 RST
           "   DROP " "%s%5"PRIu64 RST
           "   DUP "  "%s%5"PRIu64 RST
           "   OVF " DIM "%3"PRIu64 RST
           "%*s│\n",
           total_rx, total_tx,
           (total_drop > 0 ? RED BOLD : DIM), total_drop,
           (total_dup  > 0 ? YLW BOLD : DIM), total_dup,
           total_ov,
           (int)(SEP_W - 6 - 9 - 6 - 9 - 8 - 7 - 7 - 7 - 6 - 5), "");

    /* throughput line */
    printf("│  RX " GRN "%9.0f pps" RST
           "   TX " CYN "%9.0f pps" RST
           "%*s│\n",
           tput_rx_pps, tput_tx_pps,
           (int)(SEP_W - 6 - 13 - 6 - 13), "");

    /* latency summary — avg across all active PQs */
    uint64_t lat_total_sum = 0, lat_total_cnt = 0;
    uint64_t lat_max = 0;
    for (int q = 0; q < NUM_PQ; q++) {
        if (pq_lat_stats[q].count > 0) {
            lat_total_sum += pq_lat_stats[q].sum_us;
            lat_total_cnt += pq_lat_stats[q].count;
            if (pq_lat_stats[q].max_us > lat_max)
                lat_max = pq_lat_stats[q].max_us;
        }
    }
    if (lat_total_cnt > 0) {
        uint64_t lat_avg = lat_total_sum / lat_total_cnt;
        printf("│  LATENCY"
               "   avg " BOLD "%6"PRIu64" us" RST
               "   max " BOLD "%6"PRIu64" us" RST
               "%*s│\n",
               lat_avg, lat_max,
               (int)(SEP_W - 9 - 7 - 9 - 7 - 9), "");
    }

    /* ---- table header ---- */
    printf("├"); REP("─", SEP_W); printf("┤\n");

    printf("│ " BOLD "%-*s  %-*s  %*s  %*s  %*s  %-*s  %-*s" RST " │\n",
           C_PQ-2, "PQ",
           C_DESC-1, "Description",
           C_PKTS-1, "Pkts",
           C_DROP-1, "Drop",
           C_DUP-1,  "Dup",
           C_CFG-1,  "Config",
           C_DLY-1,  "Delay error");

    printf("├"); REP("─", SEP_W); printf("┤\n");

    /* ---- rows ---- */
    for (int q = 0; q < NUM_PQ; q++) {
        bool active = (pq_pkts[q] > 0);

        /* config string — plain text, max C_CFG-1 chars */
        char cfg[32] = "-";
        if (pq_cfg[q].drop_m || pq_cfg[q].dup_m || pq_cfg[q].delay_us) {
            cfg[0] = '\0';
            if (pq_cfg[q].drop_m) {
                char t[16];
                snprintf(t, sizeof(t), "drop %u/%u",
                         pq_cfg[q].drop_n, pq_cfg[q].drop_m);
                strncat(cfg, t, sizeof(cfg)-strlen(cfg)-1);
            }
            if (pq_cfg[q].dup_m) {
                if (cfg[0]) strncat(cfg, " ", sizeof(cfg)-strlen(cfg)-1);
                char t[16];
                snprintf(t, sizeof(t), "dup %u/%u",
                         pq_cfg[q].dup_n, pq_cfg[q].dup_m);
                strncat(cfg, t, sizeof(cfg)-strlen(cfg)-1);
            }
            if (pq_cfg[q].delay_us) {
                if (cfg[0]) strncat(cfg, " ", sizeof(cfg)-strlen(cfg)-1);
                char t[16];
                if (pq_cfg[q].delay_us >= 1000)
                    snprintf(t, sizeof(t), "%llums",
                             (unsigned long long)(pq_cfg[q].delay_us/1000));
                else
                    snprintf(t, sizeof(t), "%lluus",
                             (unsigned long long)pq_cfg[q].delay_us);
                strncat(cfg, t, sizeof(cfg)-strlen(cfg)-1);
            }
        }

        /* delay error string — plain, max C_DLY-1 chars */
        char dly[24] = "-";
        if (pq_cfg[q].delay_us > 0 && pq_delay_stats[q].count > 0) {
            uint64_t avg = pq_delay_stats[q].sum_us /
                           pq_delay_stats[q].count;
            uint64_t mn  = (pq_delay_stats[q].min_us == UINT64_MAX) ?
                            0 : pq_delay_stats[q].min_us;
            snprintf(dly, sizeof(dly), "avg%llu max%lluus",
                     (unsigned long long)avg,
                     (unsigned long long)pq_delay_stats[q].max_us);
            (void)mn;
        }

        const char *row  = active ? WHT  : DIM;
        const char *dcol = (pq_drop[q] > 0) ? RED BOLD : DIM;
        const char *ucol = (pq_dup[q]  > 0) ? YLW BOLD : DIM;
        const char *ecol = (pq_delay_stats[q].count > 0) ? CYN : DIM;

        /* Print row without inner │ separators.
         * All fields are plain strings → widths are exact. */
        printf("│ %s%*d" RST "  %s%-*s" RST
               "  %s%*"PRIu64 RST
               "  %s%*"PRIu64 RST
               "  %s%*"PRIu64 RST
               "  %-*s"
               "  %s%-*s" RST " │\n",
               row,  C_PQ-2, q,
               row,  C_DESC-1, pq_desc[q],
               row,  C_PKTS-1, pq_pkts[q],
               dcol, C_DROP-1, pq_drop[q],
               ucol, C_DUP-1,  pq_dup[q],
               C_CFG-1, cfg,
               ecol, C_DLY-1, dly);
    }

    /* ---- cpu scalability ---- */
    printf("├"); REP("─", SEP_W); printf("┤\n");

    printf("│ " BOLD "CPU" RST "  ");
    for (int w = 0; w < NUM_WORKER_THREADS; w++) {
        struct worker_ctx *wc = &worker_ctx_arr[w];
        if (wc->nb_pq == 0) continue;
        const char *tc = (wc->stat_tx > 0) ? GRN : DIM;
        printf("%st%d" RST ":%s%"PRIu64 RST "  ",
               BOLD, w, tc, wc->stat_tx);
    }
    printf("\n");

    /* ---- last command ---- */
    printf("├"); REP("─", SEP_W); printf("┤\n");

    pthread_mutex_lock(&last_cmd_lock);
    char cmd_copy[128];
    strncpy(cmd_copy, last_cmd, sizeof(cmd_copy)-1);
    cmd_copy[sizeof(cmd_copy)-1] = '\0';
    pthread_mutex_unlock(&last_cmd_lock);

    bool is_none = (strcmp(cmd_copy, "none") == 0);
    printf("│ " BOLD "Last cmd:" RST " %s%s" RST "%*s│\n",
           is_none ? DIM : CYN BOLD,
           cmd_copy,
           (int)(SEP_W - 10 - (int)strlen(cmd_copy)), "");

    /* ---- bottom border ---- */
    printf("└"); REP("─", SEP_W); printf("┘\n");

    /* Clear everything below the dashboard (startup text, old lines) */
    printf("\x1b[J");

#undef REP
#undef C_PQ
#undef C_DESC
#undef C_PKTS
#undef C_DROP
#undef C_DUP
#undef C_CFG
#undef C_DLY
#undef SEP_W

    fflush(stdout);
}

/* =========================================================
 * classify() — O(1) fixed-offset GRE/IP parsing
 * ========================================================= */
static inline int
classify(struct rte_mbuf *m)
{
    const uint8_t *data = rte_pktmbuf_mtod(m, const uint8_t *);
    uint32_t       len  = rte_pktmbuf_data_len(m);

    if (unlikely(len < MIN_PKT_LEN))
        return DEFAULT_PQ;

    if (memcmp(&data[OFF_GRE], GRE_MAGIC, 4) == 0) {
        uint16_t inner_len = (uint16_t)((data[OFF_INNER_LEN] << 8) |
                                         data[OFF_INNER_LEN + 1]);
        switch (inner_len) {
        case 0x0034: return 0;
        case 0x0038: return 1;
        case 0x05a4: return 2;
        case 0x00a1: return 3;
        case 0x00f4: return 4;
        case 0x00f5: return 5;
        case 0x00f6: return 6;
        default:     break;
        }
        if (memcmp(&data[OFF_OUTER_SRC], IP_40_0_0_8, 4) == 0 &&
            memcmp(&data[OFF_OUTER_DST], IP_30_0_0_8, 4) == 0)
            return 7;
    }

    if (len > OFF_PAYLOAD + 12) {
        if (memcmp(&data[OFF_PAYLOAD], "GET /4k.html", 12) == 0) return 5;
        if (memcmp(&data[OFF_PAYLOAD], "HTTP/1.0 200", 12) == 0) return 6;
    }

    if (data[0] == 0xaa && data[1] == 0xbb) {
        if (data[2] == 0xcc) return 8;
        if (data[2] == 0xcd) return 9;
    }

    return DEFAULT_PQ;
}

/* =========================================================
 * Delay helpers
 * ========================================================= */
static inline void
enqueue_delayed(struct worker_ctx *wc, struct rte_mbuf *m,
                uint64_t delay_us, int pq)
{
    struct delayed_pkt *dp;
    if (unlikely(rte_mempool_get(delay_pkt_pool, (void **)&dp) < 0)) {
        rte_pktmbuf_free(m);
        wc->stat_dropped++;
        wc->stat_overflow++;
        return;
    }
    dp->m           = m;
    dp->pq          = pq;
    dp->release_tsc = rte_rdtsc() +
                      (rte_get_tsc_hz() * delay_us) / 1000000ULL;

    if (unlikely(rte_ring_enqueue(wc->delay_ring, dp) != 0)) {
        rte_mempool_put(delay_pkt_pool, dp);
        rte_pktmbuf_free(m);
        wc->stat_dropped++;
        wc->stat_overflow++;
        return;
    }
    wc->stat_delayed++;
}

static inline void
record_delay_precision(struct delayed_pkt *dp, uint64_t now_tsc)
{
    int pq = dp->pq;
    if (pq < 0 || pq >= NUM_PQ) return;

    uint64_t hz = rte_get_tsc_hz();
    uint64_t error_us = 0;
    if (now_tsc > dp->release_tsc)
        error_us = (now_tsc - dp->release_tsc) * 1000000ULL / hz;

    struct delay_stats *ds = &pq_delay_stats[pq];
    ds->count++;
    ds->sum_us += error_us;
    if (error_us > ds->max_us) ds->max_us = error_us;
    if (error_us < ds->min_us) ds->min_us = error_us;
}

/*
 * RX timestamp stored in mbuf->dynfield1[0..1] (two uint32_t slots,
 * available for application use without registration).
 */
#define MBUF_RX_TSC_HI(m)  ((m)->dynfield1[0])
#define MBUF_RX_TSC_LO(m)  ((m)->dynfield1[1])

static inline void
mbuf_set_rx_tsc(struct rte_mbuf *m, uint64_t tsc)
{
    MBUF_RX_TSC_HI(m) = (uint32_t)(tsc >> 32);
    MBUF_RX_TSC_LO(m) = (uint32_t)(tsc & 0xFFFFFFFFULL);
}

static inline uint64_t
mbuf_get_rx_tsc(struct rte_mbuf *m)
{
    return ((uint64_t)MBUF_RX_TSC_HI(m) << 32) | MBUF_RX_TSC_LO(m);
}

/* Record end-to-end latency */
static inline void
record_latency(int pq, uint64_t rx_tsc)
{
    if (rx_tsc == 0 || pq < 0 || pq >= NUM_PQ) return;
    uint64_t now    = rte_rdtsc();
    uint64_t hz     = rte_get_tsc_hz();
    uint64_t lat_us = (now > rx_tsc) ?
                      (now - rx_tsc) * 1000000ULL / hz : 0;

    struct latency_stats *ls = &pq_lat_stats[pq];
    ls->count++;
    ls->sum_us += lat_us;
    if (lat_us > ls->max_us) ls->max_us = lat_us;
    if (lat_us < ls->min_us) ls->min_us = lat_us;
}

static inline void
drain_delay_ring(struct worker_ctx *wc)
{
    uint16_t tx_port = 1;
    uint64_t now     = rte_rdtsc();

    if (wc->pending_dp != NULL) {
        if (wc->pending_dp->release_tsc > now)
            return;
        record_delay_precision(wc->pending_dp, now);
        struct rte_mbuf *m = wc->pending_dp->m;
        uint64_t rx_tsc    = mbuf_get_rx_tsc(m);
        int      lat_pq    = wc->pending_dp->pq;
        rte_mempool_put(delay_pkt_pool, wc->pending_dp);
        wc->pending_dp = NULL;
        record_latency(lat_pq, rx_tsc);
        int sent = tx_send(wc, tx_port, m);  /* P1: per-worker queue */
        if (sent) wc->stat_tx += sent;
    }

    struct delayed_pkt *dp;
    while (rte_ring_dequeue(wc->delay_ring, (void **)&dp) == 0) {
        if (dp->release_tsc > now) {
            wc->pending_dp = dp;
            break;
        }
        record_delay_precision(dp, now);
        struct rte_mbuf *m = dp->m;
        uint64_t rx_tsc = mbuf_get_rx_tsc(m);
        rte_mempool_put(delay_pkt_pool, dp);
        record_latency(dp->pq, rx_tsc);
        int sent = tx_send(wc, tx_port, m);  /* P1: per-worker queue */
        if (sent) wc->stat_tx += sent;
    }
}

/* =========================================================
 * Per-packet processing
 * ========================================================= */
static inline void
process_one_pkt(struct worker_ctx *wc, int pq, struct rte_mbuf *m)
{
    struct pq_config cfg_snap = pq_cfg_read(pq);
    const struct pq_config *cfg = &cfg_snap;
    uint64_t cnt     = wc->pq_pkt_count[pq]++;
    uint16_t tx_port = 1;

    wc->stat_pq[pq]++;

    if (cfg->drop_m > 0 && (cnt % cfg->drop_m) < cfg->drop_n) {
        rte_pktmbuf_free(m);
        wc->stat_dropped++;
        return;
    }

    if (cfg->dup_m > 0 && (cnt % cfg->dup_m) < cfg->dup_n) {
        /*
         * P2: rte_pktmbuf_clone() instead of rte_pktmbuf_copy().
         * Clone shares the data buffer (zero-copy), only the mbuf
         * descriptor is duplicated. Much faster for large packets.
         */
        struct rte_mbuf *clone = rte_pktmbuf_clone(m, netem_pktmbuf_pool);
        if (likely(clone != NULL)) {
            wc->stat_duplicated++;
            if (cfg->delay_us > 0)
                enqueue_delayed(wc, clone, cfg->delay_us, pq);
            else {
                int sent = tx_send(wc, tx_port, clone);  /* P1 */
                if (sent) wc->stat_tx += sent;
            }
        }
    }

    if (cfg->delay_us > 0)
        enqueue_delayed(wc, m, cfg->delay_us, pq);
    else {
        record_latency(pq, mbuf_get_rx_tsc(m));
        int sent = tx_send(wc, tx_port, m);  /* P1: per-worker queue */
        if (sent) wc->stat_tx += sent;
    }
}

/* =========================================================
 * Worker thread
 * ========================================================= */
static void *
worker_thread_func(void *arg)
{
    struct worker_ctx *wc = (struct worker_ctx *)arg;

    if (wc->nb_pq == 0) {
        while (!force_quit) usleep(1000);
        return NULL;
    }

    struct rte_mbuf *burst[MAX_PKT_BURST];
    uint64_t prev_tsc  = 0;
    uint64_t delay_tsc = 0;
    wc->pending_dp     = NULL;

    const uint64_t drain_tsc =
        (rte_get_tsc_hz() + 1000000ULL - 1) / 1000000ULL * BURST_TX_DRAIN_US;
    const uint64_t delay_check_tsc =
        (rte_get_tsc_hz() + 1000000ULL - 1) / 1000000ULL * DRAIN_CHECK_US;

    while (!force_quit) {
        uint64_t cur_tsc = rte_rdtsc();
        bool did_work = false;

        if (unlikely(cur_tsc - prev_tsc > drain_tsc)) {
            for (int p = 0; p < NB_PORTS; p++) {
                int sent = tx_flush_worker(wc, p);  /* P1: per-worker flush */
                if (sent) wc->stat_tx += sent;
            }
            prev_tsc = cur_tsc;
        }

        if (unlikely(cur_tsc - delay_tsc > delay_check_tsc)) {
            drain_delay_ring(wc);
            delay_tsc = cur_tsc;
        }

        for (int i = 0; i < wc->nb_pq; i++) {
            int pq = wc->pq_list[i];
            uint16_t nb = rte_ring_dequeue_burst(pq_rings[pq],
                                                  (void **)burst,
                                                  MAX_PKT_BURST, NULL);
            if (nb > 0) {
                did_work = true;
                for (uint16_t j = 0; j < nb; j++)
                    process_one_pkt(wc, pq, burst[j]);
            }
        }

        /*
         * P4: rte_pause() when idle — emits PAUSE/YIELD instruction.
         * Reduces power consumption and bus contention without
         * sacrificing latency when traffic resumes.
         */
        if (!did_work)
            rte_pause();
    }

    for (int p = 0; p < NB_PORTS; p++) {
        int sent = tx_flush_worker(wc, p);  /* P1 */
        if (sent) wc->stat_tx += sent;
    }
    if (wc->pending_dp) {
        rte_pktmbuf_free(wc->pending_dp->m);
        rte_mempool_put(delay_pkt_pool, wc->pending_dp);
        wc->pending_dp = NULL;
    }
    return NULL;
}

/* =========================================================
 * DPDK RX lcore loop
 * ========================================================= */
static void
rx_loop(struct rx_ctx *ctx)
{
    struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
    uint64_t prev_tsc  = 0;
    uint64_t timer_tsc = 0;

    const uint64_t drain_tsc =
        (rte_get_tsc_hz() + 1000000ULL - 1) / 1000000ULL * BURST_TX_DRAIN_US;

    RTE_LOG(INFO, NETEM, "RX lcore %u: port %u started\n",
            rte_lcore_id(), ctx->rx_port);

    while (!force_quit) {
        uint64_t cur_tsc = rte_rdtsc();

        if (unlikely(cur_tsc - prev_tsc > drain_tsc)) {
            if (timer_period > 0) {
                timer_tsc += cur_tsc - prev_tsc;
                if (timer_tsc >= timer_period) {
                    if (rte_lcore_id() == rte_get_main_lcore())
                        print_stats();
                    timer_tsc = 0;
                }
            }
            prev_tsc = cur_tsc;
        }

        uint16_t nb_rx = rte_eth_rx_burst(ctx->rx_port, 0,
                                           pkts_burst, MAX_PKT_BURST);
        if (unlikely(nb_rx == 0)) {
            rte_pause();   /* P4: yield on idle */
            continue;
        }

        ctx->stat_rx += nb_rx;

        uint64_t rx_tsc = rte_rdtsc();   /* single TSC for whole burst */

        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_mbuf *m = pkts_burst[i];
            rte_prefetch0(rte_pktmbuf_mtod(m, void *));
            mbuf_set_rx_tsc(m, rx_tsc);          /* stamp RX time */
            int pq = classify(m);
            if (unlikely(rte_ring_enqueue(pq_rings[pq], m) != 0)) {
                rte_pktmbuf_free(m);
                ctx->stat_rx--;
                ctx->stat_overflow++;
            }
        }
    }
}

/* =========================================================
 * Runtime Queue Configuration Thread
 *
 * Reads commands from named pipe NETEM_CMD_PIPE.
 * Commands:
 *   drop  <pq> <n> <m>   — drop n/m packets on PQ
 *   dup   <pq> <n> <m>   — duplicate n/m packets on PQ
 *   delay <pq> <us>      — delay packets by <us> µs on PQ
 *   reset <pq>           — clear all behaviours on PQ
 *   show                 — print current config to stderr
 *
 * Usage from another terminal:
 *   echo "drop 2 1 5"   > /tmp/netem_cmd
 *   echo "delay 0 2000" > /tmp/netem_cmd
 *   echo "reset 3"      > /tmp/netem_cmd
 *   echo "show"         > /tmp/netem_cmd
 * ========================================================= */
static void *
config_thread_func(__rte_unused void *arg)
{
    /* Create named pipe if it doesn't exist */
    mkfifo(NETEM_CMD_PIPE, 0666);
    fprintf(stderr, "[config] listening on %s\n", NETEM_CMD_PIPE);
    fprintf(stderr, "[config] commands: drop <pq> <n> <m> | "
                    "dup <pq> <n> <m> | delay <pq> <us> | "
                    "reset <pq> | show\n");

    while (!force_quit) {
        /* Open pipe (blocks until a writer connects) */
        int fd = open(NETEM_CMD_PIPE, O_RDONLY);
        if (fd < 0) {
            usleep(100000);
            continue;
        }

        char buf[128] = {0};
        int  buf_len  = 0;
        ssize_t n;

        while ((n = read(fd, buf + buf_len,
                         sizeof(buf) - buf_len - 1)) > 0) {
            buf_len += n;
            buf[buf_len] = '\0';

            /* Process complete lines */
            char *start = buf;
            char *nl;
            while ((nl = strchr(start, '\n')) != NULL) {
                *nl = '\0';

                char cmd[16] = {0};
                int  pq = -1;
                uint32_t a = 0, b = 0;

                int parsed = sscanf(start, "%15s %d %u %u",
                                    cmd, &pq, &a, &b);

                if (strcmp(cmd, "show") == 0) {
                    pthread_mutex_lock(&last_cmd_lock);
                    snprintf(last_cmd, sizeof(last_cmd), "show");
                    pthread_mutex_unlock(&last_cmd_lock);
                    fprintf(stderr, "\n[config] Current PQ config:\n");
                    for (int q = 0; q < NUM_PQ; q++) {
                        struct pq_config c = pq_cfg_read(q);
                        fprintf(stderr,
                                "  PQ%-2d drop=%u/%u dup=%u/%u"
                                " delay=%"PRIu64"us\n",
                                q, c.drop_n, c.drop_m,
                                c.dup_n, c.dup_m, c.delay_us);
                    }

                } else if (pq < 0 || pq >= NUM_PQ) {
                    fprintf(stderr, "[config] invalid PQ %d\n", pq);

                } else if (strcmp(cmd, "drop") == 0 && parsed == 4) {
                    struct pq_config c = pq_cfg_read(pq);
                    c.drop_n = a;
                    c.drop_m = b;
                    pq_cfg_write(pq, &c);
                    pthread_mutex_lock(&last_cmd_lock);
                    snprintf(last_cmd, sizeof(last_cmd),
                             "drop %d %u/%u", pq, a, b);
                    pthread_mutex_unlock(&last_cmd_lock);
                    fprintf(stderr, "[config] PQ%d: drop=%u/%u\n", pq, a, b);

                } else if (strcmp(cmd, "dup") == 0 && parsed == 4) {
                    struct pq_config c = pq_cfg_read(pq);
                    c.dup_n = a;
                    c.dup_m = b;
                    pq_cfg_write(pq, &c);
                    pthread_mutex_lock(&last_cmd_lock);
                    snprintf(last_cmd, sizeof(last_cmd),
                             "dup %d %u/%u", pq, a, b);
                    pthread_mutex_unlock(&last_cmd_lock);
                    fprintf(stderr, "[config] PQ%d: dup=%u/%u\n", pq, a, b);

                } else if (strcmp(cmd, "delay") == 0 && parsed >= 3) {
                    struct pq_config c = pq_cfg_read(pq);
                    c.delay_us = a;
                    pq_cfg_write(pq, &c);
                    pthread_mutex_lock(&last_cmd_lock);
                    snprintf(last_cmd, sizeof(last_cmd),
                             "delay %d %uus", pq, a);
                    pthread_mutex_unlock(&last_cmd_lock);
                    fprintf(stderr, "[config] PQ%d: delay=%uus\n", pq, a);

                } else if (strcmp(cmd, "reset") == 0 && parsed >= 2) {
                    struct pq_config c = {0, 0, 0, 0, 0};
                    pq_cfg_write(pq, &c);
                    pthread_mutex_lock(&last_cmd_lock);
                    snprintf(last_cmd, sizeof(last_cmd), "reset %d", pq);
                    pthread_mutex_unlock(&last_cmd_lock);
                    fprintf(stderr, "[config] PQ%d: reset\n", pq);

                } else {
                    fprintf(stderr,
                            "[config] unknown command: %s\n", start);
                }

                start = nl + 1;
            }

            /* Move remaining partial line to front */
            int remaining = buf_len - (start - buf);
            if (remaining > 0)
                memmove(buf, start, remaining);
            buf_len = remaining;
            buf[buf_len] = '\0';
        }

        close(fd);
    }

    unlink(NETEM_CMD_PIPE);
    return NULL;
}

/* =========================================================
 * Config thread handle
 * ========================================================= */
static pthread_t config_thread;

static int
netem_launch_one_lcore(__rte_unused void *arg)
{
    unsigned lcore_id = rte_lcore_id();
    if (lcore_id >= NB_PORTS) {
        RTE_LOG(INFO, NETEM, "lcore %u: idle\n", lcore_id);
        return 0;
    }
    rx_loop(&rx_ctx_arr[lcore_id]);
    return 0;
}

static void
signal_handler(int signum)
{
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nSignal %d received, exiting...\n", signum);
        force_quit = true;
    }
}

/* =========================================================
 * main()
 * ========================================================= */
int
main(int argc, char **argv)
{
    int      ret;
    uint16_t nb_ports;
    uint16_t portid;
    unsigned lcore_id;

    ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
    argc -= ret;
    argv += ret;

    force_quit = false;
    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);
    timer_period *= rte_get_timer_hz();

    /* Init delay precision stats */
    for (int q = 0; q < NUM_PQ; q++) {
        pq_delay_stats[q].count  = 0;
        pq_delay_stats[q].sum_us = 0;
        pq_delay_stats[q].max_us = 0;
        pq_delay_stats[q].min_us = UINT64_MAX;
        pq_lat_stats[q].count    = 0;
        pq_lat_stats[q].sum_us   = 0;
        pq_lat_stats[q].max_us   = 0;
        pq_lat_stats[q].min_us   = UINT64_MAX;
    }

    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < NB_PORTS)
        rte_exit(EXIT_FAILURE, "Need %u ports, found %u\n",
                 NB_PORTS, nb_ports);

    unsigned int nb_mbufs =
        RTE_MAX(nb_ports * (nb_rxd + nb_txd + MAX_PKT_BURST +
                            2 * MEMPOOL_CACHE_SIZE), 8192U);

    netem_pktmbuf_pool = rte_pktmbuf_pool_create(
        "mbuf_pool", nb_mbufs, MEMPOOL_CACHE_SIZE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!netem_pktmbuf_pool)
        rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

    delay_pkt_pool = rte_mempool_create(
        "delay_pool", DELAY_PKT_POOL_SIZE,
        sizeof(struct delayed_pkt),
        DELAY_PKT_POOL_CACHE, 0,
        NULL, NULL, NULL, NULL,
        rte_socket_id(), 0);
    if (!delay_pkt_pool)
        rte_exit(EXIT_FAILURE, "Cannot create delay_pkt_pool\n");

    for (int p = 0; p < NB_PORTS; p++)
        rte_spinlock_init(&tx_lock[p]);

    for (int q = 0; q < NUM_PQ; q++) {
        char rname[32];
        snprintf(rname, sizeof(rname), "pq_%d", q);
        pq_rings[q] = rte_ring_create(rname, PQ_RING_SIZE,
                                       rte_socket_id(), 0);
        if (!pq_rings[q])
            rte_exit(EXIT_FAILURE, "Cannot create PQ ring %d\n", q);
    }

    for (int w = 0; w < NUM_WORKER_THREADS; w++) {
        worker_ctx_arr[w].thread_id  = w;
        worker_ctx_arr[w].nb_pq      = 0;
        worker_ctx_arr[w].pending_dp = NULL;
    }
    for (int q = 0; q < NUM_PQ; q++) {
        int w = q % NUM_WORKER_THREADS;
        struct worker_ctx *wc = &worker_ctx_arr[w];
        wc->pq_list[wc->nb_pq++] = q;
    }

    for (int w = 0; w < NUM_WORKER_THREADS; w++) {
        struct worker_ctx *wc = &worker_ctx_arr[w];
        for (int p = 0; p < NB_PORTS; p++) {
            wc->tx_buf[p] = rte_zmalloc_socket(
                "wtx", RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST),
                0, rte_socket_id());
            if (!wc->tx_buf[p])
                rte_exit(EXIT_FAILURE,
                         "Cannot alloc TX buf thread %d\n", w);
            rte_eth_tx_buffer_init(wc->tx_buf[p], MAX_PKT_BURST);
        }
        char dname[32];
        snprintf(dname, sizeof(dname), "delay_w%d", w);
        wc->delay_ring = rte_ring_create(dname, DELAY_RING_SIZE,
                                         rte_socket_id(),
                                         RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (!wc->delay_ring)
            rte_exit(EXIT_FAILURE,
                     "Cannot create delay ring thread %d\n", w);
    }

    RTE_ETH_FOREACH_DEV(portid) {
        struct rte_eth_rxconf    rxq_conf;
        struct rte_eth_txconf    txq_conf;
        struct rte_eth_conf      local_port_conf = port_conf;
        struct rte_eth_dev_info  dev_info;

        printf("Initializing port %u...\n", portid);

        ret = rte_eth_dev_info_get(portid, &dev_info);
        if (ret != 0)
            rte_exit(EXIT_FAILURE, "Cannot get dev info port %u\n", portid);

        if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
            local_port_conf.txmode.offloads |=
                RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

        /*
         * P1: Try to configure NUM_WORKER_THREADS TX queues (1 per worker).
         * If the driver supports it (hardware NIC), each worker gets its own
         * private TX queue → zero lock contention.
         * If the driver only supports 1 TX queue (PCAP), we fall back to
         * spinlock-protected single queue.
         */
        uint16_t nb_txq = NUM_WORKER_THREADS;
        ret = rte_eth_dev_configure(portid, 1, nb_txq, &local_port_conf);
        if (ret < 0) {
            /* Fallback: single TX queue with spinlock */
            nb_txq = 1;
            ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
            if (ret < 0)
                rte_exit(EXIT_FAILURE,
                         "Cannot configure port %u: %d\n", portid, ret);
        }

        ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                     "Cannot adjust descriptors port %u\n", portid);

        ret = rte_eth_macaddr_get(portid, &netem_ports_eth_addr[portid]);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Cannot get MAC port %u\n", portid);

        rxq_conf = dev_info.default_rxconf;
        rxq_conf.offloads = local_port_conf.rxmode.offloads;
        ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
                                     rte_eth_dev_socket_id(portid),
                                     &rxq_conf, netem_pktmbuf_pool);
        if (ret < 0)
            rte_exit(EXIT_FAILURE,
                     "RX queue setup failed port %u\n", portid);

        txq_conf = dev_info.default_txconf;
        txq_conf.offloads = local_port_conf.txmode.offloads;

        /* Setup all TX queues (1 per worker if supported, else 1) */
        for (uint16_t q = 0; q < nb_txq; q++) {
            ret = rte_eth_tx_queue_setup(portid, q, nb_txd,
                                         rte_eth_dev_socket_id(portid),
                                         &txq_conf);
            if (ret < 0)
                rte_exit(EXIT_FAILURE,
                         "TX queue %u setup failed port %u\n", q, portid);
        }

        rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL, 0);

        ret = rte_eth_dev_start(portid);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, "Cannot start port %u\n", portid);

        printf("Port %u MAC: " RTE_ETHER_ADDR_PRT_FMT "\n",
               portid, RTE_ETHER_ADDR_BYTES(&netem_ports_eth_addr[portid]));

        rx_ctx_arr[portid].rx_port = portid;
        rx_ctx_arr[portid].tx_port = portid ^ 1;
        port_nb_txq[portid]        = nb_txq;
        printf("Port %u: %u TX queue(s) configured%s\n",
               portid, nb_txq,
               nb_txq > 1 ? " (lock-free per-worker)" : " (spinlock fallback)");
    }

    /* Initial config */
    printf("\nProfile Queue Configuration\n");
    printf("Classification: O(1) fixed-offset GRE/IP parsing\n\n");
    printf("%-4s %-22s %-10s %-10s %-10s\n",
           "PQ", "Description", "Drop", "Dup", "Delay");
    printf("%-4s %-22s %-10s %-10s %-10s\n",
           "──", "─────────────────────", "──────────",
           "──────────", "────────");
    for (int q = 0; q < NUM_PQ; q++) {
        char drop[16] = "—", dup[16] = "—", delay[24] = "—";
        if (pq_cfg[q].drop_m)
            snprintf(drop, sizeof(drop), "%u/%u",
                     pq_cfg[q].drop_n, pq_cfg[q].drop_m);
        if (pq_cfg[q].dup_m)
            snprintf(dup, sizeof(dup), "%u/%u",
                     pq_cfg[q].dup_n, pq_cfg[q].dup_m);
        if (pq_cfg[q].delay_us)
            snprintf(delay, sizeof(delay), "%llus",
                     (unsigned long long)pq_cfg[q].delay_us);
        printf("%-4d %-22s %-10s %-10s %-10s\n",
               q, pq_desc[q], drop, dup, delay);
    }
    printf("\n");

    for (int w = 0; w < NUM_WORKER_THREADS; w++) {
        ret = pthread_create(&worker_ctx_arr[w].thread, NULL,
                             worker_thread_func, &worker_ctx_arr[w]);
        if (ret != 0)
            rte_exit(EXIT_FAILURE,
                     "Cannot create worker thread %d: %s\n",
                     w, strerror(ret));
    }
    printf("Started %d worker threads\n\n", NUM_WORKER_THREADS);

    /* Start runtime config thread */
    ret = pthread_create(&config_thread, NULL, config_thread_func, NULL);
    if (ret != 0)
        fprintf(stderr, "Warning: cannot create config thread: %s\n",
                strerror(ret));
    else
        printf("Runtime config listening on %s\n\n", NETEM_CMD_PIPE);

    tput_prev_tsc = rte_rdtsc();

    rte_eal_mp_remote_launch(netem_launch_one_lcore, NULL, CALL_MAIN);
    RTE_LCORE_FOREACH_WORKER(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0) {
            ret = -1;
            break;
        }
    }

    for (int w = 0; w < NUM_WORKER_THREADS; w++)
        pthread_join(worker_ctx_arr[w].thread, NULL);

    pthread_cancel(config_thread);
    pthread_join(config_thread, NULL);
    unlink(NETEM_CMD_PIPE);

    /* Final performance summary */
    printf("\n=== Final Performance Summary ===\n");
    printf("End-to-end latency per queue:\n");
    for (int q = 0; q < NUM_PQ; q++) {
        if (pq_lat_stats[q].count == 0) continue;
        uint64_t avg = pq_lat_stats[q].sum_us / pq_lat_stats[q].count;
        uint64_t mn  = (pq_lat_stats[q].min_us == UINT64_MAX) ?
                        0 : pq_lat_stats[q].min_us;
        printf("  PQ%-2d %-20s  avg %4llu us  min %4llu us  max %4llu us"
               "  n=%llu\n",
               q, pq_desc[q],
               (unsigned long long)avg,
               (unsigned long long)mn,
               (unsigned long long)pq_lat_stats[q].max_us,
               (unsigned long long)pq_lat_stats[q].count);
    }
    printf("\nDelay precision per queue:\n");
    for (int q = 0; q < NUM_PQ; q++) {
        if (pq_cfg[q].delay_us == 0 || pq_delay_stats[q].count == 0)
            continue;
        uint64_t avg = pq_delay_stats[q].sum_us / pq_delay_stats[q].count;
        uint64_t mn  = (pq_delay_stats[q].min_us == UINT64_MAX) ?
                        0 : pq_delay_stats[q].min_us;
        printf("  PQ%-2d %-20s  target:%4llu us"
               "  err: avg %3llu us  min %3llu us  max %3llu us"
               "  n=%llu\n",
               q, pq_desc[q],
               (unsigned long long)pq_cfg[q].delay_us,
               (unsigned long long)avg,
               (unsigned long long)mn,
               (unsigned long long)pq_delay_stats[q].max_us,
               (unsigned long long)pq_delay_stats[q].count);
    }

    RTE_ETH_FOREACH_DEV(portid) {
        printf("Closing port %u...\n", portid);
        rte_eth_dev_stop(portid);
        rte_eth_dev_close(portid);
    }

    rte_eal_cleanup();
    printf("Bye...\n");
    return ret;
}