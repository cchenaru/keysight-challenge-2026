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

#include <rte_common.h>
#include <rte_log.h>
#include <rte_ring.h>
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
#include <rte_mbuf_dyn.h>
#include <rte_string_fns.h>

static volatile bool force_quit;

/* 10 hardcoded (flow_id, direction) patterns.
 * direction byte is at offset 8 (cc or cd in the pcap),
 * flow_id byte is at offset 30. */
struct pattern {
    uint8_t flow_id;
    uint8_t direction;
};

static const struct pattern patterns[10] = {
    { 0x16, 0xcd },   /* PQ0 */
    { 0x16, 0xcc },   /* PQ1 */
    { 0x26, 0xcd },   /* PQ2 */
    { 0x26, 0xcc },   /* PQ3 */
    { 0x36, 0xcd },   /* PQ4 */
    { 0x36, 0xcc },   /* PQ5 */
    { 0x53, 0xcd },   /* PQ6 */
    { 0x53, 0xcc },   /* PQ7 */
    { 0x63, 0xcd },   /* PQ8 */
    { 0x63, 0xcc },   /* PQ9 */
};

#define RTE_LOGTYPE_NETEM RTE_LOGTYPE_USER1

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;

/* Number of ports */
#define NB_PORTS 2

/* ethernet addresses of ports */
static struct rte_ether_addr netem_ports_eth_addr[NB_PORTS];

static struct rte_eth_dev_tx_buffer *tx_buffer[NB_PORTS];

static struct rte_eth_conf port_conf = {
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
};

struct rte_mempool * netem_pktmbuf_pool = NULL;

/* Dynamic mbuf field used to store the packet release timestamp.
 * This replaces the old rte_mbuf::udata64 field, which is not available
 * in newer DPDK versions. */
#define RELEASE_TIME_DYNFIELD_NAME "netem_release_time"
static int release_time_dynfield_offset = -1;

static inline uint64_t *
mbuf_release_time(struct rte_mbuf *m)
{
	return RTE_MBUF_DYNFIELD(m, release_time_dynfield_offset, uint64_t *);
}

static void
register_release_time_dynfield(void)
{
	static const struct rte_mbuf_dynfield release_time_dynfield_desc = {
		.name = RELEASE_TIME_DYNFIELD_NAME,
		.size = sizeof(uint64_t),
		.align = __alignof__(uint64_t),
		.flags = 0,
	};

	release_time_dynfield_offset =
		rte_mbuf_dynfield_register(&release_time_dynfield_desc);
	if (release_time_dynfield_offset < 0)
		rte_exit(EXIT_FAILURE,
			"Cannot register release_time dynamic field\n");
}


/* Per-port statistics struct */
struct __rte_cache_aligned netem_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
};
struct netem_port_statistics port_statistics[NB_PORTS];

/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 1; /* default period is 1 seconds */

// The queues
#define NUM_PROFILE_QUEUES 10
#define NUM_WORKERS 2
#define QUEUE_SIZE 4096
#define INPUT_RING_SIZE 4096

/* Input ring: RX thread pushes raw packets, workers consume */
static struct rte_ring *input_ring;

/* Per-queue rings: workers push processed (timestamped) packets, TX consumes */
static struct rte_ring *queue_rings[NUM_PROFILE_QUEUES];

/* TX-side "pending head" — one held-back packet per queue while waiting
 * for its release_time to arrive */
static struct rte_mbuf *pending[NUM_PROFILE_QUEUES];

/* Per-queue packet counter for deterministic drop/dup decisions.
 * Multiple workers may touch the same queue — use atomic add. */
static uint64_t pkt_count[NUM_PROFILE_QUEUES];

/* Fixed ports: RX from port 0, TX to port 1 */
static uint16_t rx_port = 0;
static uint16_t tx_port = 1;

struct queue_rule {
    uint32_t drop_every;
    uint32_t duplicate_every;
    uint32_t delay_us;
};

static struct queue_rule queue_rules[NUM_PROFILE_QUEUES] = {
    /*  drop_every, dup_every, delay_us */
    {   0,           0,         0     },   /* PQ0: passthrough */
    {  10,           0,         0     },   /* PQ1: drop 1/10 */
    {   5,           0,         0     },   /* PQ2: drop 1/5 */
    {   0,          10,         0     },   /* PQ3: dup 1/10 */
    {   0,           3,         0     },   /* PQ4: dup 1/3 */
    {   0,           0,      1000     },   /* PQ5: 1ms delay */
    {   0,           0,     10000     },   /* PQ6: 10ms delay */
    {  10,          10,         0     },   /* PQ7: drop + dup */
    {   5,           0,      1000     },   /* PQ8: drop + delay */
    {   0,           5,     10000     },   /* PQ9: dup + delay */
};

static inline int
classify_packet(struct rte_mbuf *m)
{
    uint8_t *data;
    uint32_t len;
    int i;

    data = rte_pktmbuf_mtod(m, uint8_t *);
    len = rte_pktmbuf_pkt_len(m);

    /*
     * Check to be at least 32 bytes (we look at byte 8 and byte 30).
     */
    if (len < 32)
        return NUM_PROFILE_QUEUES - 1;  /* default queue */

    uint8_t direction = data[8];
    uint8_t flow_id   = data[30];

    for (i = 0; i < NUM_PROFILE_QUEUES; i++) {
        if (patterns[i].flow_id == flow_id &&
            patterns[i].direction == direction)
            return i;
    }

    /*
     * Default queue.
     */
    return NUM_PROFILE_QUEUES - 1;
}

/* Print out statistics on packets dropped */
static void
print_stats(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	unsigned portid;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

		/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

	for (portid = 0; portid < NB_PORTS; portid++) {
		printf("\nStatistics for port %u ------------------------------"
			   "\nPackets sent: %24"PRIu64
			   "\nPackets received: %20"PRIu64
			   "\nPackets dropped: %21"PRIu64,
			   portid,
			   port_statistics[portid].tx,
			   port_statistics[portid].rx,
			   port_statistics[portid].dropped);

		total_packets_dropped += port_statistics[portid].dropped;
		total_packets_tx += port_statistics[portid].tx;
		total_packets_rx += port_statistics[portid].rx;
	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18"PRIu64
		   "\nTotal packets received: %14"PRIu64
		   "\nTotal packets dropped: %15"PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped);
	printf("\n====================================================\n");

	fflush(stdout);
}

/* RX thread: read packets from input port, push raw into input_ring. */
static int
rx_thread(__rte_unused void *arg)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	unsigned nb_rx;

	printf("RX thread on lcore %u, rx_port %u\n", rte_lcore_id(), rx_port);
	RTE_LOG(INFO, NETEM, "entering RX loop on lcore %u\n", rte_lcore_id());

	while (!force_quit) {
		/* Read packet from RX queue */
		nb_rx = rte_eth_rx_burst(rx_port, 0, pkts_burst, MAX_PKT_BURST);
		if (unlikely(nb_rx == 0))
			/* Nothing received? Continue. */
			continue;

		port_statistics[rx_port].rx += nb_rx;

		/* Push the whole burst into input_ring at once. */
		unsigned enq = rte_ring_enqueue_burst(input_ring,
		                                     (void **)pkts_burst,
		                                     nb_rx, NULL);

		/* Any packets that didn't fit get dropped. */
		for (unsigned i = enq; i < nb_rx; i++) {
			rte_pktmbuf_free(pkts_burst[i]);
			port_statistics[rx_port].dropped++;
		}
	}
	return 0;
}

/* Worker thread: pop from input_ring, classify, apply drop/duplicate,
 * stamp release_time, push to queue_rings[q]. */
static int
worker_thread(void *arg)
{
	int worker_id = (int)(uintptr_t)arg;
	struct rte_mbuf *m;

	printf("Worker %d on lcore %u\n", worker_id, rte_lcore_id());
	RTE_LOG(INFO, NETEM, "entering worker loop on lcore %u\n", rte_lcore_id());

	while (!force_quit) {
		if (rte_ring_dequeue(input_ring, (void **)&m) != 0)
			continue;

		/* Classify packet */
		int queue_id = classify_packet(m);
		struct queue_rule *r = &queue_rules[queue_id];

		/* Atomic counter so multiple workers don't race when deciding
		 * drop/dup for the same queue. */
		uint64_t count = __atomic_add_fetch(&pkt_count[queue_id], 1,
		                                    __ATOMIC_RELAXED);

		/* Drop check */
		if (r->drop_every && (count % r->drop_every) == 0) {
			/* ToDo: correctly drop based on total RX packets, not
			 * while iterating the burst (e.g. 32 packets burst)
			 */
			rte_pktmbuf_free(m);
			port_statistics[rx_port].dropped++;
			continue;
		}

		/* Compute release_time = now + delay */
		uint64_t delay_cycles =
			(uint64_t)r->delay_us * rte_get_tsc_hz() / 1000000ULL;
		uint64_t release = rte_rdtsc() + delay_cycles;

		/* Duplicate check */
		if (r->duplicate_every && (count % r->duplicate_every) == 0) {
			struct rte_mbuf *clone =
				rte_pktmbuf_clone(m, netem_pktmbuf_pool);
			if (clone != NULL) {
				*mbuf_release_time(clone) = release;
				if (rte_ring_enqueue(queue_rings[queue_id], clone) < 0) {
					rte_pktmbuf_free(clone);
					port_statistics[rx_port].dropped++;
				}
			} else {
				port_statistics[rx_port].dropped++;
			}
		}

		/* Stamp the original and push */
		*mbuf_release_time(m) = release;
		if (rte_ring_enqueue(queue_rings[queue_id], m) < 0) {
			rte_pktmbuf_free(m);
			port_statistics[rx_port].dropped++;
		}
	}
	return 0;
}

/* TX thread: peek each queue_ring, pick the packet with the earliest
 * release_time that's already due, send it out. */
static int
tx_thread(__rte_unused void *arg)
{
	struct rte_eth_dev_tx_buffer *buffer;
	int sent;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
			BURST_TX_DRAIN_US;

	prev_tsc = 0;
	timer_tsc = 0;

	printf("TX thread on lcore %u, tx_port %u\n", rte_lcore_id(), tx_port);
	RTE_LOG(INFO, NETEM, "entering TX loop on lcore %u\n", rte_lcore_id());

	while (!force_quit) {
		cur_tsc = rte_rdtsc();

		/* Top up pending slot for each queue */
		for (int q = 0; q < NUM_PROFILE_QUEUES; q++) {
			if (pending[q] == NULL)
				rte_ring_dequeue(queue_rings[q], (void **)&pending[q]);
		}

		/* Find the queue whose pending packet has the smallest
		 * release_time AND is already due (release_time <= now). */
		int best_q = -1;
		uint64_t best_time = UINT64_MAX;
		for (int q = 0; q < NUM_PROFILE_QUEUES; q++) {
			if (pending[q] == NULL)
				continue;
			uint64_t release_time = *mbuf_release_time(pending[q]);
			if (release_time > cur_tsc)
				continue;
			if (release_time < best_time) {
				best_time = release_time;
				best_q = q;
			}
		}

		if (best_q >= 0) {
			buffer = tx_buffer[tx_port];
			rte_prefetch0(rte_pktmbuf_mtod(pending[best_q], void *));
			sent = rte_eth_tx_buffer(tx_port, 0, buffer, pending[best_q]);
			if (sent)
				port_statistics[tx_port].tx += sent;
			pending[best_q] = NULL;
		}

		/* Drains the TX queue after a certain time */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {
			buffer = tx_buffer[tx_port];

			sent = rte_eth_tx_buffer_flush(tx_port, 0, buffer);
			if (sent)
				port_statistics[tx_port].tx += sent;

			/* if timer is enabled */
			if (timer_period > 0) {

				/* advance the timer */
				timer_tsc += diff_tsc;

				/* if timer has reached its timeout */
				if (unlikely(timer_tsc >= timer_period)) {

					/* do this only on main core */
					if (rte_lcore_id() == rte_get_main_lcore()) {
						print_stats();
						/* reset the timer */
						timer_tsc = 0;
					}
				}
			}

			prev_tsc = cur_tsc;
		}
	}
	return 0;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

int
main(int argc, char **argv)
{
	int ret;
	uint16_t nb_ports;
	uint16_t nb_ports_available = 0;
	uint16_t portid;
	unsigned lcore_id;
	unsigned int nb_lcores = NUM_WORKERS + 2;  /* RX + workers + TX */
	unsigned int nb_mbufs;

	/* Init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	register_release_time_dynfield();

	/* Create the input ring: RX is the sole producer (SP),
	 * workers are multiple consumers (no SC flag). */
	input_ring = rte_ring_create("INPUT_RING", INPUT_RING_SIZE,
	                             rte_socket_id(), RING_F_SP_ENQ);
	if (input_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create input ring\n");

	/* Create the per-queue rings: workers are multiple producers
	 * (no SP flag), TX is the sole consumer (SC). */
	char queue_name[32];
	for (int i = 0; i < NUM_PROFILE_QUEUES; i++) {
		snprintf(queue_name, sizeof(queue_name),
				"PROFILE_QUEUE_%d", i);

		queue_rings[i] = rte_ring_create(
			queue_name,
			QUEUE_SIZE,
			rte_socket_id(),
			RING_F_SC_DEQ
		);

		if (queue_rings[i] == NULL) {
			rte_exit(EXIT_FAILURE,
					"Cannot create queue %d\n", i);
		}
	}

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* convert to number of cycles */
	timer_period *= rte_get_timer_hz();

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	nb_mbufs = RTE_MAX(nb_ports * (nb_rxd + nb_txd + MAX_PKT_BURST +
		nb_lcores * MEMPOOL_CACHE_SIZE), 8192U);

	/* Create the mbuf pool */
	netem_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
	if (netem_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	/* Initialize each port */
	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;

		nb_ports_available++;

		/* init port */
		printf("Initializing port %u... ", portid);
		fflush(stdout);

		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				portid, strerror(-ret));

		if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
				RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
		/* Configure the number of queues for a port. */
		ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
				  ret, portid);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
						       &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, port=%u\n",
				 ret, portid);

		ret = rte_eth_macaddr_get(portid,
					  &netem_ports_eth_addr[portid]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot get MAC address: err=%d, port=%u\n",
				 ret, portid);

		/* init one RX queue */
		fflush(stdout);
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		/* RX queue setup */
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
					     rte_eth_dev_socket_id(portid),
					     &rxq_conf,
					     netem_pktmbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
				  ret, portid);

		/* Init one TX queue on each port */
		fflush(stdout);
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
				rte_eth_dev_socket_id(portid),
				&txq_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n",
				ret, portid);

		/* Initialize TX buffers */
		tx_buffer[portid] = rte_zmalloc_socket("tx_buffer",
				RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
				rte_eth_dev_socket_id(portid));
		if (tx_buffer[portid] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
					portid);

		rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);

		ret = rte_eth_tx_buffer_set_err_callback(tx_buffer[portid],
				rte_eth_tx_buffer_count_callback,
				&port_statistics[portid].dropped);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
			"Cannot set error callback for tx buffer on port %u\n",
				 portid);

		ret = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL,
					     0);
		if (ret < 0)
			printf("Port %u, Failed to disable Ptype parsing\n",
					portid);
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
				  ret, portid);

		printf("Port %u, MAC address: " RTE_ETHER_ADDR_PRT_FMT "\n\n",
			portid,
			RTE_ETHER_ADDR_BYTES(&netem_ports_eth_addr[portid]));

		/* initialize port stats */
		memset(&port_statistics, 0, sizeof(port_statistics));
	}

	if (!nb_ports_available) {
		rte_exit(EXIT_FAILURE, "No ports available\n");
	}

	/* Lcore assignment:
	 *   main lcore   -> TX thread (runs inline)
	 *   first worker -> RX thread
	 *   rest         -> worker threads (NUM_WORKERS of them)
	 * Requires at least NUM_WORKERS + 2 lcores. Pass -l 0-3 (or wider). */
	unsigned int rx_lcore = 0;
	unsigned int worker_lcores[NUM_WORKERS];
	int wi = 0;
	int rx_assigned = 0;

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (!rx_assigned) {
			rx_lcore = lcore_id;
			rx_assigned = 1;
		} else if (wi < NUM_WORKERS) {
			worker_lcores[wi++] = lcore_id;
		}
	}

	if (!rx_assigned || wi < NUM_WORKERS) {
		rte_exit(EXIT_FAILURE,
			"Need at least %d lcores total. Use -l 0-%d on the command line.\n",
			NUM_WORKERS + 2, NUM_WORKERS + 1);
	}

	rte_eal_remote_launch(rx_thread, NULL, rx_lcore);
	for (int w = 0; w < NUM_WORKERS; w++) {
		rte_eal_remote_launch(worker_thread, (void *)(uintptr_t)w,
		                      worker_lcores[w]);
	}

	/* TX runs on the main lcore */
	ret = 0;
	tx_thread(NULL);

	/* Wait for everyone */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	RTE_ETH_FOREACH_DEV(portid) {
		printf("Closing port %d...", portid);
		ret = rte_eth_dev_stop(portid);
		if (ret != 0)
			printf("rte_eth_dev_stop: err=%d, port=%d\n",
			       ret, portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}

	/* clean up the EAL */
	rte_eal_cleanup();
	printf("Bye...\n");

	return ret;
}
