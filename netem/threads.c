#include "main.h"
#include "threads.h"
#include "list.h"

void *pq_thread(void *arg) {
	struct pq_thread_args *args = (struct pq_thread_args *)arg;
	
	struct thread *thread = args->thread;
	struct double_list *list = args->thread_list;
	struct node* node = args->node;
	uint16_t tx_port_id = args->tx_port_id;
	uint16_t rx_port_id = args->rx_port_id;
	struct rte_eth_dev_tx_buffer **tx_buffer = args->tx_buffer;
	struct netem_port_statistics *port_statistics = args->port_statistics;

	while (1) {
		// lock mutex
		pthread_mutex_lock(thread->lock_data_in);
		
		// protect against spurious wakeups by checking ring status
		while (rte_ring_empty(thread->buffer_in)) {
			pthread_cond_wait(thread->cond_data_in, thread->lock_data_in);
		}
		
		// unlock before calling modifier (so modifier can lock it)
		pthread_mutex_unlock(thread->lock_data_in);

		// apply maggic on packets
		apply_modifiers(thread, port_statistics, rx_port_id);

		// send packets to TX
		send_packets(thread, tx_port_id, tx_buffer, port_statistics);

		// reset buffer_full flag
		thread->buffer_full = 0;

		// if this worker thread is not the first worker thread kill it
		if (node->prev != NULL) {
			pthread_mutex_lock(thread->lock_list);
			deleteNode(list, node);
			pthread_mutex_unlock(thread->lock_list);

			// clean up thread resources
			pthread_cond_destroy(thread->cond_data_in);
			pthread_mutex_destroy(thread->lock_data_in);
			free(thread->cond_data_in);
			free(thread->lock_data_in);
			// free buffers
			rte_ring_free(thread->buffer_in);
			rte_ring_free(thread->buffer_out);
			free(thread);
			break;
		}
	}

	free(args);
	return NULL;
}

void send_packets(struct thread *thread, uint16_t tx_port_id, 
	struct rte_eth_dev_tx_buffer **tx_buffer, struct netem_port_statistics *port_statistics) {
	struct rte_mbuf *pkts[8];
	unsigned int nb_pkts;
	unsigned int i;
	int sent = 0;

	nb_pkts = rte_ring_dequeue_burst(thread->buffer_out, (void**)pkts, BURST_SIZE, NULL);
	if (nb_pkts == 0)
		return;

	pthread_mutex_lock(thread->lock_TX);

	for (i = 0; i < nb_pkts; i++) {
		sent += rte_eth_tx_buffer(tx_port_id, 0, tx_buffer[tx_port_id], pkts[i]);
	}
	sent += rte_eth_tx_buffer_flush(tx_port_id, 0, tx_buffer[tx_port_id]);
	port_statistics[tx_port_id].tx += sent;

	pthread_mutex_unlock(thread->lock_TX);
}

void apply_modifiers(struct thread *thread, struct netem_port_statistics *port_statistics,
	uint16_t rx_port_id) {
	struct rte_mbuf *pkts[BURST_SIZE];
	unsigned int nb_pkts;
	unsigned int i;
	int cnt = 0;

	pthread_mutex_lock(thread->lock_data_in);

	nb_pkts = rte_ring_dequeue_burst(thread->buffer_in, (void**)pkts, BURST_SIZE, NULL);

	pthread_mutex_unlock(thread->lock_data_in);

	for (i = 0; i < nb_pkts; i++) {
		struct rte_mbuf *m = pkts[i];
		cnt++;
		switch(thread->flag) {
			case DUPLICATE_FLAG: {
				rte_ring_enqueue(thread->buffer_out, m);
				struct rte_mbuf *copy = rte_pktmbuf_clone(m, m->pool);

				if (cnt % DUPLICATE_FLAG_WHEN == 0)
					rte_ring_enqueue(thread->buffer_out, copy);

				break;
			}
			
			case DROP_FLAG:
				if (cnt % DROP_FLAG_WHEN == 0) {
					rte_pktmbuf_free(m);
					port_statistics[rx_port_id].dropped++;
					continue;
				}

				rte_ring_enqueue(thread->buffer_out, m);
				
				break;

			case DELAY_FLAG:
				if (cnt % DELAY_FLAG_WHEN == 0) {
					usleep((DELAY_MIN_MS + rte_rand() % (DELAY_MAX_MS - DELAY_MIN_MS)) * 1000);
				}

				rte_ring_enqueue(thread->buffer_out, m);
				break;

			default:
				rte_ring_enqueue(thread->buffer_out, m);
				break;			
		}
	}
}

static void handle_full_buffer(List **thread_list, int flag, int i, 
	struct rte_mbuf *m, unsigned lcore_id, uint16_t tx_port_id, uint16_t rx_port_id,
	struct rte_eth_dev_tx_buffer **tx_buffer, struct netem_port_statistics *port_statistics) {
	thread_list[flag]->head->current->buffer_full = 1;

	// look through all threads for this PQ until you find one with space in buffer
	struct node *node = thread_list[flag]->head->next;
	while (node != NULL) {
		if (!node->current->buffer_full) {
			if (rte_ring_enqueue(node->current->buffer_in, m) < 0)
				node->current->buffer_full = 1;
			else
				return;
		}
		node = node->next;
	}

	// no space found — spawn a new thread
	struct thread *thread = malloc(sizeof(*thread));
	if (!thread) {
		fprintf(stderr, "Failed to allocate memory for thread\n");
		return;
	}

	thread_list[flag]->node_nr++;

	char name_buffer_in[32];
	char name_buffer_out[32];
	sprintf(name_buffer_in,  "buffer_in%d%d%d",  lcore_id, i, thread_list[flag]->node_nr);
	sprintf(name_buffer_out, "buffer_out%d%d%d", lcore_id, i, thread_list[flag]->node_nr);

	thread->buffer_in  = rte_ring_create(name_buffer_in,  RING_SIZE, rte_socket_id(), 0);
	thread->buffer_out = rte_ring_create(name_buffer_out, RING_SIZE, rte_socket_id(), 0);

	thread->cond_data_in = malloc(sizeof(pthread_cond_t));
	thread->lock_data_in = malloc(sizeof(pthread_mutex_t));
	thread->lock_TX      = thread_list[flag]->head->current->lock_TX;
	thread->lock_list    = thread_list[flag]->head->current->lock_list;

	pthread_cond_init(thread->cond_data_in, NULL);
	pthread_mutex_init(thread->lock_data_in, NULL);

	thread_list[flag] = insertRear(thread_list[flag], thread);
	thread->flag = flag;

	struct pq_thread_args *args = malloc(sizeof(*args));
	if (!args) {
		fprintf(stderr, "Failed to allocate memory for thread args\n");
		free(thread);
		return;
	}

	args->thread_list = thread_list[flag];
	args->node = findNode(thread_list[flag], thread);
	args->thread          = thread;
	args->tx_port_id      = tx_port_id;
	args->rx_port_id      = rx_port_id;
	args->tx_buffer       = tx_buffer;
	args->port_statistics = port_statistics;

	pthread_t tid;
	pthread_create(&tid, NULL, (void *)pq_thread, args);
}
