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
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_ring.h>
#include "main.h"
#include "threads.h"
#include "list.h"

static volatile bool force_quit;

#define RTE_LOGTYPE_NETEM RTE_LOGTYPE_USER1

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256

/*
 * Configurable number of RX/TX ring descriptors
 */
// number of packets for receiving and sending
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

struct netem_port_statistics port_statistics[NB_PORTS];

/* A tsc-based timer responsible for triggering statistics printout */
static uint64_t timer_period = 1; /* default period is 1 seconds */

/* Returns current time in nanoseconds */
static inline uint64_t
get_time_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

/* Returns a random delay in nanoseconds between min_ms and max_ms */
static inline uint64_t
random_delay_ns(uint64_t min_ms, uint64_t max_ms)
{
    uint64_t min_ns = min_ms * 1000000ULL;
    uint64_t max_ns = max_ms * 1000000ULL;
    return min_ns + (rte_rand() % (max_ns - min_ns));
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

	printf("\n SALUT \n");

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

	/* On the RX path, the lcore reads the packets from it's port.
	 * For lcore_id 0, set the rx_port_id to 0.
	 * For lcore_id 1, set the rx_port_id to 1.
	 */
	uint16_t rx_port_id = lcore_id;

	/* On the TX path, the lcore will send the packets to the other port
	 * For lcore_id 0, set the tx_port_id to 1.
	 * For lcore_id 1, set the tx_port_id to 0.
	 */
	uint16_t tx_port_id = lcore_id ^ 1;

	printf("lcore_id %u, tx %u, rx %u\n", lcore_id, tx_port_id, rx_port_id);

	RTE_LOG(INFO, NETEM, "entering main loop on lcore %u\n", lcore_id);

	// spawn threads
	pthread_mutex_t *lock_TX = malloc(sizeof(pthread_mutex_t));
	pthread_mutex_init(lock_TX, NULL);  

	// in order to dinamically spawn new threads when a very large ammount of packets arrives
	// we will host a PQ_NR lists, each keeping track of how many worker threads
	// there are for each PQ
	// thus, if a PQ has like 10 packets, it will only have 1 worker
	// but if one PQ has 10 000 packets, it will have multiple workers
	struct double_list **thread_list = malloc((PQ_NR + 1) * sizeof(struct double_list*));

	for (int i = 1; i <= PQ_NR; i++)
		thread_list[i] = initList();

	for (int i = 1; i <= PQ_NR; i++) {
		struct thread *thread = malloc(sizeof(struct thread));

		char name_buffer_in[32];
    	char name_buffer_out[32];
		sprintf(name_buffer_in, "buffer_in%d%d", lcore_id, i);
		sprintf(name_buffer_out, "buffer_out%d%d", lcore_id, i);
	
		thread->buffer_in = rte_ring_create(name_buffer_in, RING_SIZE, rte_socket_id(), 0);
		thread->buffer_out = rte_ring_create(name_buffer_out, RING_SIZE, rte_socket_id(), 0);

		// internal buffer locks
		thread->cond_data_in = malloc(sizeof(pthread_cond_t));
		thread->lock_data_in = malloc(sizeof(pthread_mutex_t));

		// lock for managing sending out packets
		thread->lock_TX = lock_TX;

		// lock for managing each PQ's list
		thread->lock_list = malloc(sizeof(pthread_mutex_t));

		pthread_cond_init(thread->cond_data_in, NULL);
		pthread_mutex_init(thread->lock_data_in, NULL);  
		pthread_mutex_init(thread->lock_list, NULL);  

		// keep thread data in main array's storage
		thread_list[i] = insertRear(thread_list[i], thread);
		thread_list[i]->node_nr = 1;

		// alloc mem for input args for worker thread
		struct pq_thread_args *args = malloc(sizeof(struct pq_thread_args));
		if (args == NULL) {
			// Handle memory allocation failure
			fprintf(stderr, "Failed to allocate memory for thread args\n");
			return;
		}

		// populate input struc
		args->thread = thread;
		args->node = findNode(thread_list[i], thread);
		args->thread_list = thread_list[i];
		args->tx_port_id = tx_port_id;
		args->rx_port_id = rx_port_id;
		args->tx_buffer = tx_buffer;
		args->port_statistics = port_statistics;

		thread->flag = i;
		pthread_t tid;
		pthread_create(&tid, NULL, (void *) pq_thread, args);
	}

	while (!force_quit) {
		/* Drains the TX queue after a certain time */
		cur_tsc = rte_rdtsc();

		diff_tsc = cur_tsc - prev_tsc;
		// flush TX queue
		if (unlikely(diff_tsc > drain_tsc)) {
			buffer = tx_buffer[tx_port_id];

			sent = rte_eth_tx_buffer_flush(tx_port_id, 0, buffer);
			if (sent)
				port_statistics[tx_port_id].tx += sent;

			/* if timer is enabled */
			if (timer_period > 0) {

				/* advance the timer */
				timer_tsc += diff_tsc;

				/* if timer has reached its timeout */
				if (unlikely(timer_tsc >= timer_period)) {

					/* do this only on main core */
					if (lcore_id == rte_get_main_lcore()) {
						print_stats();
						/* reset the timer */
						timer_tsc = 0;
					}
				}
			}

			prev_tsc = cur_tsc;
		}

		/* Read packet from RX queue */
		nb_rx = rte_eth_rx_burst(rx_port_id, 0, pkts_burst, MAX_PKT_BURST);
		if (unlikely(nb_rx == 0))
			/*  Nothing received? Continue. */
			continue;

		port_statistics[rx_port_id].rx += nb_rx;

		// try to acquire all locks
		for (int i = 1; i <= PQ_NR; i++) {
			Node *node = thread_list[i]->head;
			while (node != NULL) {
				pthread_mutex_lock(node->current->lock_data_in);
				node = node->next;
			}
		}

		char buffer_changed[PQ_NR + 1] = {0};
		// put packet in one of the queues
		for (i = 0; i < nb_rx; i++) {
            m = pkts_burst[i];
            rte_prefetch0(rte_pktmbuf_mtod(m, void *));
			match_packet(m, buffer_changed, thread_list, &rx_port_id, 
				tx_port_id, lcore_id, tx_buffer, port_statistics);
		}

		// give all locks back
		for (int i = 1; i <= PQ_NR; i++) {
			Node *node = thread_list[i]->head;
			while (node != NULL) {
				pthread_mutex_unlock(node->current->lock_data_in);
				node = node->next;
			}
		}

		for (int i = 1; i <= PQ_NR; i++) {
		if (buffer_changed[i] == 1) {
			Node *node = thread_list[i]->head;
			while (node != NULL) {
				pthread_cond_signal(node->current->cond_data_in);
				node = node->next;
			}
		}
	}

			// /* Drop one in 10 packets, the 5th one. */
			// if (i % 10 == 5) {
			// 	/* ToDo: correctly drop based on total RX packets, not
			// 	 * while iterating the burst (e.g. 32 packets burst)
			// 	 */
			// 	rte_pktmbuf_free(m);
			// 	continue;
			// }

			// buffer = tx_buffer[tx_port_id];

			// sent = rte_eth_tx_buffer(tx_port_id, 0, buffer, m);
			// if (sent)
			// 	port_statistics[tx_port_id].tx += sent;
	}
}

// flag == 0, no modifications
// flag == 1, packet will suffer modification as agreed by conventions (check defines)
void match_packet(struct rte_mbuf *m, char *buffer_changed,
    struct double_list **thread_list, uint16_t *rx_port_id,
    uint16_t tx_port_id, unsigned lcore_id,
    struct rte_eth_dev_tx_buffer **tx_buffer,
    struct netem_port_statistics *port_statistics) {
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ip_hdr;

	// extract Ethernet header
	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	// app will only modify ipv4 packets
	if (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		// extract ip header
		ip_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);

		// pattern match for a queue
		// try to add packet to queue
		// if queue is full. drop packet

		if (ip_hdr->next_proto_id == UDP_PROTOCOL) {
			// put packet in buffer
			if (rte_ring_enqueue(thread_list[DUPLICATE_FLAG]->head->current->buffer_in, m) < 0) {
				handle_full_buffer(thread_list, DUPLICATE_FLAG, i, m, lcore_id,
                   tx_port_id, rx_port_id, tx_buffer, port_statistics);
			}

			buffer_changed[DUPLICATE_FLAG] = 1;
		} 
		else if (ip_hdr->next_proto_id == TCP_PROTOCOL) {
			if (rte_ring_enqueue(thread_list[DROP_FLAG]->head->current->buffer_in, m) < 0) {
				handle_full_buffer(thread_list, DROP_FLAG, i, m, lcore_id,
                   tx_port_id, rx_port_id, tx_buffer, port_statistics);
			}

			buffer_changed[DROP_FLAG] = 1;
		} 
		else if (ip_hdr->next_proto_id == IP_PROTOCOL_ICMP) {
			if (rte_ring_enqueue(thread_list[DELAY_FLAG]->head->current->buffer_in, m) < 0) {
				handle_full_buffer(thread_list, DELAY_FLAG, i, m, lcore_id,
                   tx_port_id, rx_port_id, tx_buffer, port_statistics);
			}

			buffer_changed[DELAY_FLAG] = 1;
		} 
		else {
			// add to default queue
			if (rte_ring_enqueue(thread_list[DUPLICATE_FLAG]->head->current->buffer_in, m) < 0) {
				handle_full_buffer(thread_list, DELAY_FLAG, i, m, lcore_id,
                   tx_port_id, rx_port_id, tx_buffer, port_statistics);
			}

			buffer_changed[PQ_NR] = 1;
		}
	} 
	else {
		// not ipv4 packet, just add to default queue
		if (rte_ring_enqueue(thread_list[DUPLICATE_FLAG]->head->current->buffer_in, m) < 0) {
			handle_full_buffer(thread_list, DELAY_FLAG, i, m, lcore_id,
				tx_port_id, rx_port_id, tx_buffer, port_statistics);
		}
	}
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

	// gets the number of available ports
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	// max between the 2 values
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

	ret = 0;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(netem_launch_one_lcore, NULL, CALL_MAIN);
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
