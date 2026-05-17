// Network Emulator 2026 - Andrei Georgescu & Mihail Bodnarciuc, ACS

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
#include <string.h>

#define DELAY_RING_SIZE 1024
#define DELAY_RING_MASK (DELAY_RING_SIZE - 1)
#define NO_PQUEUES 10
#define PATTERN_SIZE 12
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

/* Because all of these variables are 2D, and each lcore only has access to its own memory, race-conditions are prevented
	We have a completely LOCK-free design - no mutexes / semaphores
*/
static uint64_t pq_stats[RTE_MAX_LCORE][NO_PQUEUES + 1];
static uint64_t pq_pkt_count[RTE_MAX_LCORE][NO_PQUEUES + 1];
static uint64_t pq_dropped[RTE_MAX_LCORE][NO_PQUEUES + 1];
static uint64_t pq_duplicated[RTE_MAX_LCORE][NO_PQUEUES + 1];
static uint64_t pq_delayed[RTE_MAX_LCORE][NO_PQUEUES + 1];

// Latency variables
static uint64_t lat_min[RTE_MAX_LCORE][NO_PQUEUES + 1]; /* min cycles */
static uint64_t lat_max[RTE_MAX_LCORE][NO_PQUEUES + 1]; /* max cycles */
static uint64_t lat_sum[RTE_MAX_LCORE][NO_PQUEUES + 1];
static uint64_t lat_count[RTE_MAX_LCORE][NO_PQUEUES + 1];
static uint64_t lat_jitter_sum[RTE_MAX_LCORE][NO_PQUEUES + 1];
static uint64_t lat_last[RTE_MAX_LCORE][NO_PQUEUES + 1];

/* Dynamic mbuf field for RX timestamp */
static int netem_rx_tsc_dynfield_offset = -1;

#define RX_TSC(mbuf) \
	(*RTE_MBUF_DYNFIELD((mbuf), netem_rx_tsc_dynfield_offset, uint64_t *))

// Struct for delay ring_buffers - contains the packet and the moment it should be sent at
struct delayed_pkt
{
	struct rte_mbuf *m;
	uint64_t send_at_tsc;
};

static struct delayed_pkt delay_rings[RTE_MAX_LCORE][NO_PQUEUES + 1][DELAY_RING_SIZE];
static unsigned delay_head[RTE_MAX_LCORE][NO_PQUEUES + 1];
static unsigned delay_tail[RTE_MAX_LCORE][NO_PQUEUES + 1];

// Patern struct
struct pq_pattern
{
	uint8_t bytes[PATTERN_SIZE];
	const char *name;
};

// QUEUE behaviour - fields for drop, multiply and delay
struct pq_behavior
{
	uint32_t drop_every_n; /* drops 1 packet for every n packets */
	uint32_t dup_every_n;  /* duplicates 1 packet for every n packets  */
	uint32_t delay_us;	   /* delay in microseconds; 0 = no delay */
};

// NO_PQUEUES + 1 to include default as well
static const struct pq_behavior pq_behaviors[NO_PQUEUES + 1] = {
	/* PQ 0 */ {.drop_every_n = 10, .dup_every_n = 0, .delay_us = 0},
	/* PQ 1 */ {.drop_every_n = 5, .dup_every_n = 0, .delay_us = 0},
	/* PQ 2 */ {.drop_every_n = 0, .dup_every_n = 10, .delay_us = 0},
	/* PQ 3 */ {.drop_every_n = 0, .dup_every_n = 3, .delay_us = 0},
	/* PQ 4 */ {.drop_every_n = 0, .dup_every_n = 0, .delay_us = 100},
	/* PQ 5 */ {.drop_every_n = 0, .dup_every_n = 0, .delay_us = 1000},
	/* PQ 6 */ {.drop_every_n = 20, .dup_every_n = 10, .delay_us = 0},
	/* PQ 7 */ {.drop_every_n = 0, .dup_every_n = 5, .delay_us = 500},
	/* PQ 8 */ {.drop_every_n = 50, .dup_every_n = 0, .delay_us = 200},
	/* PQ 9 */ {.drop_every_n = 10, .dup_every_n = 10, .delay_us = 1000},
	/* default */ {.drop_every_n = 0, .dup_every_n = 0, .delay_us = 0},
};

// This can be changed, hardocded for the .pcap file
static const struct pq_pattern pq_patterns[NO_PQUEUES] = {

	/* PQ 0: tunel 30.0.0.8 -> 40.0.0.8 */
	{.bytes = {0x1E, 0x00, 0x00, 0x08, 0x28, 0x00, 0x00, 0x08, 0x00, 0x00, 0x08, 0x00},
	 .name = "Tunnel 30.0.0.8 -> 40.0.0.8"},

	/* PQ 1: tunel 40.0.0.8 -> 30.0.0.8 */
	{.bytes = {0x28, 0x00, 0x00, 0x08, 0x1E, 0x00, 0x00, 0x08, 0x00, 0x00, 0x08, 0x00},
	 .name = "Tunnel 40.0.0.8 -> 30.0.0.8"},

	/* PQ 2: tunel 30.0.0.22 -> 40.0.0.22 */
	{.bytes = {0x1E, 0x00, 0x00, 0x16, 0x28, 0x00, 0x00, 0x16, 0x00, 0x00, 0x08, 0x00},
	 .name = "Tunnel 30.0.0.22 -> 40.0.0.22"},

	/* PQ 3: tunel 40.0.0.22 -> 30.0.0.22 */
	{.bytes = {0x28, 0x00, 0x00, 0x16, 0x1E, 0x00, 0x00, 0x16, 0x00, 0x00, 0x08, 0x00},
	 .name = "Tunnel 40.0.0.22 -> 30.0.0.22"},

	/* PQ 4: tunel 30.0.0.38 -> 40.0.0.38 */
	{.bytes = {0x1E, 0x00, 0x00, 0x26, 0x28, 0x00, 0x00, 0x26, 0x00, 0x00, 0x08, 0x00},
	 .name = "Tunnel 30.0.0.38 -> 40.0.0.38"},

	/* PQ 5: tunel 40.0.0.38 -> 30.0.0.38 */
	{.bytes = {0x28, 0x00, 0x00, 0x26, 0x1E, 0x00, 0x00, 0x26, 0x00, 0x00, 0x08, 0x00},
	 .name = "Tunnel 40.0.0.38 -> 30.0.0.38"},

	/* PQ 6: tunel 30.0.0.54 -> 40.0.0.54 */
	{.bytes = {0x1E, 0x00, 0x00, 0x36, 0x28, 0x00, 0x00, 0x36, 0x00, 0x00, 0x08, 0x00},
	 .name = "Tunnel 30.0.0.54 -> 40.0.0.54"},

	/* PQ 7: tunel 30.0.0.62 -> 40.0.0.62 */
	{.bytes = {0x1E, 0x00, 0x00, 0x3E, 0x28, 0x00, 0x00, 0x3E, 0x00, 0x00, 0x08, 0x00},
	 .name = "Tunnel 30.0.0.62 -> 40.0.0.62"},

	/* PQ 8: tunel 30.0.0.83 -> 40.0.0.83 */
	{.bytes = {0x1E, 0x00, 0x00, 0x53, 0x28, 0x00, 0x00, 0x53, 0x00, 0x00, 0x08, 0x00},
	 .name = "Tunnel 30.0.0.83 -> 40.0.0.83"},

	/* PQ 9: tunel 30.0.0.99 -> 40.0.0.99 */
	{.bytes = {0x1E, 0x00, 0x00, 0x63, 0x28, 0x00, 0x00, 0x63, 0x00, 0x00, 0x08, 0x00},
	 .name = "Tunnel 30.0.0.99 -> 40.0.0.99"},
};

static volatile bool force_quit;

/* ethernet addresses of ports */
static struct rte_ether_addr netem_ports_eth_addr[NB_PORTS];

static struct rte_eth_dev_tx_buffer *tx_buffer[NB_PORTS];

static struct rte_eth_conf port_conf = {
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
};

struct rte_mempool *netem_pktmbuf_pool = NULL;

/* Per-port statistics struct */
struct __rte_cache_aligned netem_port_statistics
{
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
};
struct netem_port_statistics port_statistics[NB_PORTS];

/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 1; /* default period is 1 seconds */

static inline int delay_push(unsigned lcore_id, int pq_id, struct rte_mbuf *m, uint64_t delay_us)
{
	unsigned head = delay_head[lcore_id][pq_id];
	unsigned tail = delay_tail[lcore_id][pq_id];

	// HERE WE HAVE THE OVERFLOW PROTECTION - we return if the ringsize is full
	// if the ring is full, drop packet
	if (tail - head >= DELAY_RING_SIZE)
		return -1; /* full */

	uint64_t now = rte_rdtsc();
	uint64_t cycles_per_us = rte_get_tsc_hz() / 1000000ULL;
	uint64_t send_at = now + delay_us * cycles_per_us;

	delay_rings[lcore_id][pq_id][tail & DELAY_RING_MASK] =
		(struct delayed_pkt){.m = m, .send_at_tsc = send_at};
	delay_tail[lcore_id][pq_id] = tail + 1;
	pq_delayed[lcore_id][pq_id]++;

	return 0;
}

static inline void latency_record(unsigned lcore_id, int pq_id, uint64_t cycles)
{

	if (lat_count[lcore_id][pq_id] == 0 || cycles < lat_min[lcore_id][pq_id])
		lat_min[lcore_id][pq_id] = cycles;
	if (cycles > lat_max[lcore_id][pq_id])
		lat_max[lcore_id][pq_id] = cycles;
	lat_sum[lcore_id][pq_id] += cycles;

	if (lat_count[lcore_id][pq_id] > 0)
	{
		uint64_t prev = lat_last[lcore_id][pq_id];
		uint64_t jitter = (cycles > prev) ? (cycles - prev) : (prev - cycles);
		lat_jitter_sum[lcore_id][pq_id] += jitter;
	}
	lat_last[lcore_id][pq_id] = cycles;
	lat_count[lcore_id][pq_id]++;
}

static inline void send_packet_with_latency(unsigned lcore_id, int pq_id, uint16_t tx_port_id,
											struct rte_eth_dev_tx_buffer *buffer,
											struct rte_mbuf *m)
{
	uint64_t latency_cycles = rte_rdtsc() - RX_TSC(m);
	latency_record(lcore_id, pq_id, latency_cycles);

	int sent = rte_eth_tx_buffer(tx_port_id, 0, buffer, m);
	if (sent)
		port_statistics[tx_port_id].tx += sent;
}

// Function to send everything that is ready
static inline void delay_drain(unsigned lcore_id, uint16_t tx_port_id,
							   struct rte_eth_dev_tx_buffer *buffer)
{
	uint64_t now = rte_rdtsc();

	for (int pq = 0; pq <= NO_PQUEUES; pq++)
	{
		unsigned head = delay_head[lcore_id][pq];
		unsigned tail = delay_tail[lcore_id][pq];

		while (head != tail)
		{
			struct delayed_pkt *dp =
				&delay_rings[lcore_id][pq][head & DELAY_RING_MASK];

			// FIFO - if the first one isnt ready, the others definitely arent
			if (dp->send_at_tsc > now)
				break;

			send_packet_with_latency(lcore_id, pq, tx_port_id, buffer, dp->m);

			head++;
		}
		delay_head[lcore_id][pq] = head;
	}
}

// Returns the mathched queue ID
static int classify_packet(const uint8_t *pkt_data, uint16_t pkt_len)
{
	// We iterate through the queue list
	for (int i = 0; i < NO_PQUEUES; i++)
	{
		if (memmem(pkt_data, pkt_len,
				   pq_patterns[i].bytes, PATTERN_SIZE) != NULL)
		{
			return i;
		}
	}
	return NO_PQUEUES; /* default queue */
}

/* Print out statistics on packets dropped */
static void
print_stats(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	uint64_t total_pq_dropped, total_pq_duplicated;
	unsigned portid;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;
	total_pq_dropped = 0;
	total_pq_duplicated = 0;

	const char clr[] = {27, '[', '2', 'J', '\0'};
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};

	/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");
	for (portid = 0; portid < NB_PORTS; portid++)
	{
		printf("\nStatistics for port %u ------------------------------"
			   "\nPackets sent: %24" PRIu64
			   "\nPackets received: %20" PRIu64
			   "\nPackets dropped: %21" PRIu64,
			   portid,
			   port_statistics[portid].tx,
			   port_statistics[portid].rx,
			   port_statistics[portid].dropped);

		total_packets_dropped += port_statistics[portid].dropped;
		total_packets_tx += port_statistics[portid].tx;
		total_packets_rx += port_statistics[portid].rx;
	}

	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18" PRIu64
		   "\nTotal packets received: %14" PRIu64
		   "\nTotal packets dropped: %15" PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped);

	/* ============ Per-Queue detailed stats ============ */
	printf("\n\nProfile Queue Statistics ===========================");
	printf("\n%-32s %8s %8s %8s %8s %8s %8s",
		   "Queue", "Seen", "Drop", "Dup", "Delayed", "Drop1/N", "DelayUs");
	printf("\n----------------------------------------------------"
		   "-----------------------------------");

	uint64_t total_pq_delayed = 0;

	for (int i = 0; i < NO_PQUEUES; i++)
	{
		const struct pq_behavior *b = &pq_behaviors[i];

		uint64_t seen = 0, dropped = 0, duped = 0, delayed = 0;
		for (unsigned l = 0; l < RTE_MAX_LCORE; l++)
		{
			seen += pq_stats[l][i];
			dropped += pq_dropped[l][i];
			duped += pq_duplicated[l][i];
			delayed += pq_delayed[l][i];
		}

		printf("\n%-32s %8" PRIu64 " %8" PRIu64 " %8" PRIu64 " %8" PRIu64 " %8u %8u",
			   pq_patterns[i].name,
			   seen,
			   dropped,
			   duped,
			   delayed,
			   b->drop_every_n,
			   b->delay_us);

		total_pq_dropped += dropped;
		total_pq_duplicated += duped;
		total_pq_delayed += delayed;
	}

	/* default queue */
	{
		const struct pq_behavior *b = &pq_behaviors[NO_PQUEUES];

		uint64_t seen = 0, dropped = 0, duped = 0, delayed = 0;
		for (unsigned l = 0; l < RTE_MAX_LCORE; l++)
		{
			seen += pq_stats[l][NO_PQUEUES];
			dropped += pq_dropped[l][NO_PQUEUES];
			duped += pq_duplicated[l][NO_PQUEUES];
			delayed += pq_delayed[l][NO_PQUEUES];
		}

		printf("\n%-32s %8" PRIu64 " %8" PRIu64 " %8" PRIu64 " %8" PRIu64 " %8u %8u",
			   "[default queue]",
			   seen,
			   dropped,
			   duped,
			   delayed,
			   b->drop_every_n,
			   b->delay_us);

		total_pq_dropped += dropped;
		total_pq_duplicated += duped;
		total_pq_delayed += delayed;
	}

	printf("\n----------------------------------------------------"
		   "-----------------------------------");
	printf("\nTotal PQ-dropped packets: %12" PRIu64, total_pq_dropped);
	printf("\nTotal PQ-duplicated packets: %9" PRIu64, total_pq_duplicated);
	printf("\nTotal PQ-delayed packets: %12" PRIu64, total_pq_delayed);

	/* ============ Per-queue latency statistics ============ */
	printf("\n\nLatency per queue ==================================");
	printf("\n%-32s %10s %10s %10s %10s %10s",
		   "Queue", "Min(us)", "Avg(us)", "Max(us)", "Jit(us)", "Samples");
	printf("\n----------------------------------------------------"
		   "-----------------------------");

	double cyc_per_us = (double)rte_get_tsc_hz() / 1000000.0;

	for (int i = 0; i <= NO_PQUEUES; i++)
	{
		uint64_t qmin = UINT64_MAX, qmax = 0;
		uint64_t qsum = 0, qcnt = 0, qjit = 0;

		for (unsigned l = 0; l < RTE_MAX_LCORE; l++)
		{
			if (lat_count[l][i] == 0)
				continue;
			if (lat_min[l][i] < qmin)
				qmin = lat_min[l][i];
			if (lat_max[l][i] > qmax)
				qmax = lat_max[l][i];
			qsum += lat_sum[l][i];
			qcnt += lat_count[l][i];
			qjit += lat_jitter_sum[l][i];
		}

		if (qcnt == 0)
			continue; /* nu afișa cozi fără mostre */

		const char *name = (i == NO_PQUEUES) ? "[default queue]" : pq_patterns[i].name;
		double min_us = (double)qmin / cyc_per_us;
		double avg_us = ((double)qsum / qcnt) / cyc_per_us;
		double max_us = (double)qmax / cyc_per_us;
		double jit_us = (qcnt > 1) ? ((double)qjit / (qcnt - 1)) / cyc_per_us : 0.0;

		printf("\n%-32s %10.2f %10.2f %10.2f %10.2f %10" PRIu64,
			   name, min_us, avg_us, max_us, jit_us, qcnt);
	}

	printf("\n====================================================\n");
	fflush(stdout);
}

/* main processing loop */
static void
netem_main_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	int sent;
	unsigned lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	unsigned i, nb_rx;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
							   BURST_TX_DRAIN_US;
	struct rte_eth_dev_tx_buffer *buffer;

	prev_tsc = 0;
	timer_tsc = 0;

	lcore_id = rte_lcore_id();

	// Assign one port per lcore (PCAP PMD = 1 queue/port); extras go idle.
	uint16_t rx_port_id = 0xFFFF;
	uint16_t current_port = 0;
	unsigned lcore_iterator;

	RTE_LCORE_FOREACH(lcore_iterator)
	{
		if (current_port >= NB_PORTS)
			break;
		if (lcore_iterator == lcore_id)
		{
			rx_port_id = current_port;
			break;
		}
		current_port++;
	}

	if (rx_port_id >= NB_PORTS)
	{
		RTE_LOG(INFO, NETEM, "Lcore %u idle (no port assigned)\n", lcore_id);
		while (!force_quit)
		{
			rte_pause();
		}
		return;
	}

	uint16_t tx_port_id = rx_port_id ^ 1;

	printf("lcore_id %u, tx %u, rx %u\n", lcore_id, tx_port_id, rx_port_id);

	RTE_LOG(INFO, NETEM, "entering main loop on lcore %u\n", lcore_id);

	while (!force_quit)
	{
		/* Drains the TX queue after a certain time */
		cur_tsc = rte_rdtsc();

		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc))
		{
			buffer = tx_buffer[tx_port_id];

			sent = rte_eth_tx_buffer_flush(tx_port_id, 0, buffer);
			if (sent)
				port_statistics[tx_port_id].tx += sent;

			/* if timer is enabled */
			if (timer_period > 0)
			{

				/* advance the timer */
				timer_tsc += diff_tsc;

				/* if timer has reached its timeout */
				if (unlikely(timer_tsc >= timer_period))
				{

					/* do this only on main core */
					if (lcore_id == rte_get_main_lcore())
					{
						print_stats();
						/* reset the timer */
						timer_tsc = 0;
					}
				}
			}

			prev_tsc = cur_tsc;
		}

		// We want to verify delays at every iteration, not just at every 100us
		buffer = tx_buffer[tx_port_id];
		delay_drain(lcore_id, tx_port_id, buffer);

		/* Read packet from RX queue */
		nb_rx = rte_eth_rx_burst(rx_port_id, 0, pkts_burst, MAX_PKT_BURST);
		if (unlikely(nb_rx == 0))
			/*  Nothing received? Continue. */
			continue;

		// We add a timestamp here for latency info
		uint64_t rx_tsc = rte_rdtsc();
		for (unsigned k = 0; k < nb_rx; k++)
		{
			RX_TSC(pkts_burst[k]) = rx_tsc;
		}

		port_statistics[rx_port_id].rx += nb_rx;

		for (i = 0; i < nb_rx; i++)
		{
			m = pkts_burst[i];

			const uint8_t *pkt_data = rte_pktmbuf_mtod(m, const uint8_t *);
			uint16_t pkt_len = rte_pktmbuf_pkt_len(m);

			int pq_id = classify_packet(pkt_data, pkt_len);

			pq_stats[lcore_id][pq_id]++;

			// we want to be 1-indexed
			uint64_t n = ++pq_pkt_count[lcore_id][pq_id];

			const struct pq_behavior *behaviour = &pq_behaviors[pq_id];

			// If it is the nth packet, we drop
			if (behaviour->drop_every_n > 0 && (n % behaviour->drop_every_n) == 0)
			{
				rte_pktmbuf_free(m);
				port_statistics[rx_port_id].dropped++;
				pq_dropped[lcore_id][pq_id]++;
				continue;
			}

			rte_prefetch0(rte_pktmbuf_mtod(m, void *));

			buffer = tx_buffer[tx_port_id];

			// Here we dupe the required packets;
			if (behaviour->dup_every_n > 0 && (n % behaviour->dup_every_n) == 0)
			{
				struct rte_mbuf *clone = rte_pktmbuf_clone(m, netem_pktmbuf_pool);

				// If there is a clone, we send it
				if (clone)
				{
					if (behaviour->delay_us > 0)
					{
						// again, if the ring is full, we drop the clone
						if (delay_push(lcore_id, pq_id, clone, behaviour->delay_us) < 0)
						{
							rte_pktmbuf_free(clone);
						}
					}
					else
					{

						send_packet_with_latency(lcore_id, pq_id, tx_port_id, buffer, clone);
					}
					pq_duplicated[lcore_id][pq_id]++;
				}
			}

			if (behaviour->delay_us > 0)
			{
				// if the ring is full -> drop
				if (delay_push(lcore_id, pq_id, m, behaviour->delay_us) < 0)
				{
					rte_pktmbuf_free(m);
					pq_dropped[lcore_id][pq_id]++;
					port_statistics[rx_port_id].dropped++;
				}
			}
			else
			{
				// no delay - we send straight away
				send_packet_with_latency(lcore_id, pq_id, tx_port_id, buffer, m);
			}
		}
	}

	/* Final drain for graceful shutdown */
	buffer = tx_buffer[tx_port_id];
	for (int pq = 0; pq <= NO_PQUEUES; pq++)
	{
		unsigned head = delay_head[lcore_id][pq];
		unsigned tail = delay_tail[lcore_id][pq];
		while (head != tail)
		{
			struct delayed_pkt *dp = &delay_rings[lcore_id][pq][head & DELAY_RING_MASK];
			send_packet_with_latency(lcore_id, pq, tx_port_id, buffer, dp->m);
			head++;
		}
		delay_head[lcore_id][pq] = head;
	}

	/* Flush TX */
	sent = rte_eth_tx_buffer_flush(tx_port_id, 0, buffer);
	if (sent)
		port_statistics[tx_port_id].tx += sent;
}

static int
netem_launch_one_lcore(__rte_unused void *dummy)
{
	netem_main_loop();
	return 0;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM)
	{
		printf("\n\nSignal %d received, preparing to exit...\n",
			   signum);
		force_quit = true;
	}
}

int main(int argc, char **argv)
{
	int ret;
	uint16_t nb_ports;
	uint16_t nb_ports_available = 0;
	uint16_t portid;
	unsigned lcore_id;
	unsigned int nb_lcores = 2;
	unsigned int nb_mbufs;

	/* Init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* convert to number of cycles */
	timer_period *= rte_get_timer_hz();

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	nb_mbufs = RTE_MAX(nb_ports * (nb_rxd + nb_txd + MAX_PKT_BURST +
								   nb_lcores * MEMPOOL_CACHE_SIZE),
					   8192U);

	/* Create the mbuf pool */
	netem_pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
												 MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
												 rte_socket_id());
	if (netem_pktmbuf_pool == NULL)
	{
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
	}

	static const struct rte_mbuf_dynfield rx_tsc_desc = {
		.name = "netem_rx_tsc",
		.size = sizeof(uint64_t),
		.align = __alignof__(uint64_t),
	};

	netem_rx_tsc_dynfield_offset = rte_mbuf_dynfield_register(&rx_tsc_desc);
	if (netem_rx_tsc_dynfield_offset < 0)
	{
		rte_exit(EXIT_FAILURE, "Cannot register mbuf dynfield for latency\n");
	}

	/* Initialize each port */
	RTE_ETH_FOREACH_DEV(portid)
	{
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

	if (!nb_ports_available)
	{
		rte_exit(EXIT_FAILURE, "No ports available\n");
	}

	ret = 0;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(netem_launch_one_lcore, NULL, CALL_MAIN);
	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		if (rte_eal_wait_lcore(lcore_id) < 0)
		{
			ret = -1;
			break;
		}
	}

	RTE_ETH_FOREACH_DEV(portid)
	{
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
