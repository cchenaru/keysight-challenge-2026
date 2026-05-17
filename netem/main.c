#include <arpa/inet.h>
#include <errno.h>
#include <generic/rte_pause.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <pthread.h>
#include <rte_ring_core.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
#include <rte_ring.h>

#define RTE_LOGTYPE_NETEM RTE_LOGTYPE_USER1

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100
#define MEMPOOL_CACHE_SIZE 256
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024
#define NB_PORTS 2
#define RING_SIZE 4096
#define N_CLASS_THREADS 4

#define LCORE_RX 0
#define LCORE_WORKER1 1
#define LCORE_WORKER2 2
#define LCORE_TX 3

static volatile bool force_quit;

static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;

static struct rte_ether_addr netem_ports_eth_addr[NB_PORTS];
static struct rte_eth_dev_tx_buffer *tx_buffer[NB_PORTS];
static struct rte_mempool *netem_pktmbuf_pool;

static struct rte_ring *task_ring;
static struct rte_ring *tx_ring;
static struct rte_ring *profile_queue[8];

static pthread_t class_threads[N_CLASS_THREADS];

static uint64_t timer_period = 1;

struct __rte_cache_aligned netem_port_statistics {
  uint64_t tx;
  uint64_t rx;
  uint64_t dropped;
  uint64_t pattern[8];
};
struct netem_port_statistics port_statistics[NB_PORTS];

static struct rte_eth_conf port_conf = {
    .txmode =
        {
            .mq_mode = RTE_ETH_MQ_TX_NONE,
        },
};

static void print_stats(void) {
  uint64_t total_tx = 0, total_rx = 0, total_dropped = 0;

  const char clr[] = {27, '[', '2', 'J', '\0'};
  const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
  printf("%s%s", clr, topLeft);
  printf("\nPort statistics ====================================");

  for (unsigned p = 0; p < NB_PORTS; p++) {
    printf("\nStatistics for port %u ------------------------------"
           "\nPackets sent: %24" PRIu64 "\nPackets received: %20" PRIu64
           "\nPackets dropped: %21" PRIu64,
           p, port_statistics[p].tx, port_statistics[p].rx,
           port_statistics[p].dropped);

    total_tx += port_statistics[p].tx;
    total_rx += port_statistics[p].rx;
    total_dropped += port_statistics[p].dropped;
  }

  printf("\nAggregate statistics ==============================="
         "\nTotal packets sent: %18" PRIu64
         "\nTotal packets received: %14" PRIu64
         "\nTotal packets dropped: %15" PRIu64
         "\n====================================================\n",
         total_tx, total_rx, total_dropped);

  fflush(stdout);
}

static void *classifier_thread(__rte_unused void *arg) {
  struct rte_mbuf *m;

  while (!force_quit) {

    if (rte_ring_dequeue(task_ring, (void **)&m) < 0) {
      rte_pause();
      continue;
    }
    rte_prefetch0(rte_pktmbuf_mtod(m, void *));

    int dst_id = 0;
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

#define TCP_DEST_PORT_MEDIAN 35730
#define IP_PREFIX_MASK 8
#define TCP_DEST_PORT_MASK 2
    if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
      struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
      uint32_t src = rte_be_to_cpu_32(ip->src_addr);
      struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
      if (((src >> 24) & 0xFF) == 30)
        dst_id |= 4;
      if (tcp->dst_port < TCP_DEST_PORT_MEDIAN)
        dst_id |= 2;
      if (tcp->tcp_flags & RTE_TCP_SYN_FLAG)
        dst_id |= 1;
    }

    if (rte_ring_enqueue(profile_queue[dst_id], m) < 0) {
      rte_pktmbuf_free(m);
      port_statistics[0].dropped++;
    }
  }
  return NULL;
}

static void init_classifier_pool(void) {
  for (int i = 0; i < N_CLASS_THREADS; i++)
    pthread_create(&class_threads[i], NULL, classifier_thread, NULL);
}

static void destroy_classifier_pool(void) {
  for (int i = 0; i < N_CLASS_THREADS; i++)
    pthread_join(class_threads[i], NULL);
}

static void io_rx_loop(void) {
  struct rte_mbuf *bursts[MAX_PKT_BURST];
  uint64_t prev_tsc = 0, timer_tsc = 0;
  const uint64_t drain_tsc =
      (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;

  while (!force_quit) {
    uint64_t cur_tsc = rte_rdtsc();
    uint64_t diff_tsc = cur_tsc - prev_tsc;

    if (unlikely(diff_tsc > drain_tsc)) {
      if (timer_period > 0) {
        timer_tsc += diff_tsc;
        if (unlikely(timer_tsc >= timer_period)) {
          print_stats();
          timer_tsc = 0;
        }
      }
      prev_tsc = cur_tsc;
    }

    uint16_t nb_rx = rte_eth_rx_burst(0, 0, bursts, MAX_PKT_BURST);
    if (unlikely(!nb_rx))
      continue;

    port_statistics[0].rx += nb_rx;

    uint16_t enqueued =
        rte_ring_enqueue_burst(task_ring, (void **)bursts, nb_rx, NULL);

    for (uint16_t i = enqueued; i < nb_rx; i++) {
      rte_pktmbuf_free(bursts[i]);
      port_statistics[0].dropped++;
    }
  }
}

static void worker_multi_queue(int start_q, int end_q) {
  struct rte_mbuf *bursts[MAX_PKT_BURST];
  struct rte_mbuf *out[MAX_PKT_BURST * 2];

  while (!force_quit) {
    bool worked = false;

    for (int q = start_q; q < end_q; q++) {

      uint16_t n = rte_ring_dequeue_burst(profile_queue[q], (void **)bursts,
                                          MAX_PKT_BURST, NULL);
      if (!n)
        continue;

      worked = true;

      bool duplicate = (q % 2 != 0);
      int drop_rate = q * 2;

      uint16_t out_n = 0;

      for (uint16_t i = 0; i < n; i++) {

        if (drop_rate > 0 && (rte_rand() % 100) < drop_rate) {
          rte_pktmbuf_free(bursts[i]);
          port_statistics[1].dropped++;
          continue;
        }

        out[out_n++] = bursts[i];

        if (duplicate) {
          struct rte_mbuf *clone =
              rte_pktmbuf_clone(bursts[i], netem_pktmbuf_pool);
          if (likely(clone != NULL)) {
            out[out_n++] = clone;
          } else {
            port_statistics[1].dropped++;
          }
        }
      }

      if (out_n > 0) {
        uint16_t enqueued =
            rte_ring_enqueue_burst(tx_ring, (void **)out, out_n, NULL);
        port_statistics[1].pattern[q] += enqueued;

        for (uint16_t i = enqueued; i < out_n; i++) {
          rte_pktmbuf_free(out[i]);
          port_statistics[1].dropped++;
        }
      }
    }
    if (!worked) {
      rte_pause();
    }
  }
}

static void tx_loop(void) {
  struct rte_mbuf *bursts[MAX_PKT_BURST];
  // cpu core that only sends the packets

  while (!force_quit) {
    uint16_t n =
        rte_ring_dequeue_burst(tx_ring, (void **)bursts, MAX_PKT_BURST, NULL);
    if (!n)
      continue;

    uint16_t sent = rte_eth_tx_burst(1, 0, bursts, n);
    port_statistics[1].tx += sent;

    for (uint16_t i = sent; i < n; i++) {
      rte_pktmbuf_free(bursts[i]);
      port_statistics[1].dropped++;
    }
  }
}

static int lcore_main(__rte_unused void *arg) {
  unsigned id = rte_lcore_id();

  switch (id) {
  case LCORE_RX:
    io_rx_loop();
    break;
  case LCORE_WORKER1:
    worker_multi_queue(0, 4);
    break;
  case LCORE_WORKER2:
    worker_multi_queue(4, 8);
    break;
  case LCORE_TX:
    tx_loop();
    break;
  default:
    printf("error on a core\n");
    break;
  }
  return 0;
}

static void signal_handler(int signum) {
  if (signum == SIGINT || signum == SIGTERM) {
    printf("\n\nSignal %d received, preparing to exit...\n", signum);
    force_quit = true;
  }
}

int main(int argc, char **argv) {
  int ret;
  uint16_t nb_ports_available = 0;
  uint16_t portid;
  unsigned lcore_id;
  unsigned int nb_lcores = 4;
  unsigned int nb_mbufs;

  ret = rte_eal_init(argc, argv);
  if (ret < 0)
    rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
  argc -= ret;
  argv += ret;

  force_quit = false;
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  timer_period *= rte_get_timer_hz();

  if (rte_eth_dev_count_avail() == 0)
    rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

  if (rte_lcore_count() < 4)
    rte_exit(EXIT_FAILURE, "Need at least 4 lcores\n");

  nb_mbufs = RTE_MAX(NB_PORTS * (nb_rxd + nb_txd + MAX_PKT_BURST +
                                 nb_lcores * MEMPOOL_CACHE_SIZE),
                     8192U);

  netem_pktmbuf_pool =
      rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs, MEMPOOL_CACHE_SIZE, 0,
                              RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
  if (!netem_pktmbuf_pool)
    rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

  task_ring = rte_ring_create("tasks", RING_SIZE, rte_socket_id(),
                              RING_F_SP_ENQ | RING_F_MC_HTS_DEQ);
  tx_ring =
      rte_ring_create("tx", RING_SIZE * 2, rte_socket_id(), RING_F_SC_DEQ);

  for (int i = 0; i < 8; ++i) {
    char name[10];
    snprintf(name, sizeof(name), "pq%d", i);
    profile_queue[i] =
        rte_ring_create(name, RING_SIZE, rte_socket_id(), RING_F_SP_ENQ);
    if (!profile_queue[i]) {
      rte_exit(EXIT_FAILURE, "ring creation error\n");
    }
  }

  if (!task_ring || !tx_ring)
    rte_exit(EXIT_FAILURE, "ring creation error\n");

  init_classifier_pool();

  RTE_ETH_FOREACH_DEV(portid) {
    struct rte_eth_rxconf rxq_conf;
    struct rte_eth_txconf txq_conf;
    struct rte_eth_conf local_port_conf = port_conf;
    struct rte_eth_dev_info dev_info;

    nb_ports_available++;

    printf("Initializing port %u... ", portid);
    fflush(stdout);

    ret = rte_eth_dev_info_get(portid, &dev_info);
    if (ret != 0)
      rte_exit(EXIT_FAILURE, "Error during getting device (port %u) info: %s\n",
               portid, strerror(-ret));

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
      local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n", ret,
               portid);

    ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
    if (ret < 0)
      rte_exit(EXIT_FAILURE,
               "Cannot adjust number of descriptors: err=%d, port=%u\n", ret,
               portid);

    ret = rte_eth_macaddr_get(portid, &netem_ports_eth_addr[portid]);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "Cannot get MAC address: err=%d, port=%u\n", ret,
               portid);

    rxq_conf = dev_info.default_rxconf;
    rxq_conf.offloads = local_port_conf.rxmode.offloads;
    ret =
        rte_eth_rx_queue_setup(portid, 0, nb_rxd, rte_eth_dev_socket_id(portid),
                               &rxq_conf, netem_pktmbuf_pool);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n", ret,
               portid);

    txq_conf = dev_info.default_txconf;
    txq_conf.offloads = local_port_conf.txmode.offloads;
    ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
                                 rte_eth_dev_socket_id(portid), &txq_conf);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n", ret,
               portid);

    tx_buffer[portid] =
        rte_zmalloc_socket("tx_buffer", RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST),
                           0, rte_eth_dev_socket_id(portid));
    if (!tx_buffer[portid])
      rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
               portid);

    rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);

    ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid],
                                             rte_eth_tx_buffer_count_callback,
                                             &port_statistics[portid].dropped);
    if (ret < 0)
      rte_exit(EXIT_FAILURE,
               "Cannot set error callback for tx buffer on port %u\n", portid);

    ret = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL, 0);
    if (ret < 0)
      printf("Port %u, Failed to disable Ptype parsing\n", portid);

    ret = rte_eth_dev_start(portid);
    if (ret < 0)
      rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n", ret,
               portid);

    printf("Port %u, MAC address: " RTE_ETHER_ADDR_PRT_FMT "\n\n", portid,
           RTE_ETHER_ADDR_BYTES(&netem_ports_eth_addr[portid]));

    memset(&port_statistics, 0, sizeof(port_statistics));
  }

  if (!nb_ports_available)
    rte_exit(EXIT_FAILURE, "No ports available\n");

  ret = 0;
  rte_eal_mp_remote_launch(lcore_main, NULL, CALL_MAIN);
  RTE_LCORE_FOREACH_WORKER(lcore_id) {
    if (rte_eal_wait_lcore(lcore_id) < 0) {
      ret = -1;
      break;
    }
  }

  destroy_classifier_pool();

  RTE_ETH_FOREACH_DEV(portid) {
    printf("Closing port %d...", portid);
    ret = rte_eth_dev_stop(portid);
    if (ret != 0)
      printf("rte_eth_dev_stop: err=%d, port=%d\n", ret, portid);
    rte_eth_dev_close(portid);
    printf(" Done\n");
  }

  rte_eal_cleanup();
  printf("Bye...\n");
  return ret;
}
