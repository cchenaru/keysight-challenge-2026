#ifndef __THREADS_H__
#define __THREADS_H__

#include <pthread.h>
#include <stdint.h>
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
#include "list.h"


struct thread {
	struct rte_ring *buffer_in;
	struct rte_ring *buffer_out;

	// mutex for waking up a thread when there is data for it to work with
	pthread_cond_t *cond_data_in;
	pthread_mutex_t *lock_data_in;

	// lock for TX so multiple threads don't try to forwards packets at the same time
	pthread_mutex_t *lock_TX;

	// lock for threads in the same PQ list
	// so that done worker threads can take themselves out of the list without issue
	pthread_mutex_t *lock_list;

	// flag that reflects if the buffer_in is full
	// (used for spawning more threads)
	unsigned int buffer_full;

	// flag for internal packet handling logic
	unsigned int flag;
};

struct pq_thread_args {
	struct double_list *thread_list;
	struct node *node;
	struct thread *thread;
	uint16_t tx_port_id;
	uint16_t rx_port_id;
	struct rte_eth_dev_tx_buffer **tx_buffer;
	struct netem_port_statistics *port_statistics;
};

void *pq_thread(void *arg);

void send_packets(struct thread *thread, uint16_t tx_port_id,
	struct rte_eth_dev_tx_buffer **tx_buffer,
	struct netem_port_statistics *port_statistics);

void apply_modifiers(struct thread *thread,
	struct netem_port_statistics *port_statistics,
	uint16_t rx_port_id);

void handle_full_buffer(List **thread_list, int flag,
	struct rte_mbuf *m, unsigned lcore_id, uint16_t tx_port_id, uint16_t rx_port_id,
	struct rte_eth_dev_tx_buffer **tx_buffer,
	struct netem_port_statistics *port_statistics);

#endif
