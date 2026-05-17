#ifndef main_h
#define main_h

#include <rte_mbuf.h> 
#include <stdint.h>

#define NUM_PROFILES 10
#define MAX_HEAP_SIZE 131072
#define NB_PORTS 2

// Structura pentru statistici cerută de tine
typedef struct {
	uint64_t total_received;
	uint64_t total_dropped;
	uint64_t total_sent;
	uint64_t total_duplicated;
} queue_stats_t;

// Structura profilului (curățată și actualizată)
typedef struct {
	int drop_rate; // 1 in drop_rate packets will be dropped
	int dup_rate;  // dup_rate packets out of 10 will be duplicated
	int min_delay; // minimum delay applied to packets in ms
	int max_delay; // maximum delay applied to packets in ms
	
	queue_stats_t stats; // Sub-structura de stats
	uint64_t pkt_count;  // Contor intern pentru logica de drop/dup
} profile_queue;

// Structura unui element din Min-Heap (sala de așteptare)
typedef struct {
	struct rte_mbuf *m;
	uint64_t send_tsc;   // Timpul exact (în cicli CPU) când pachetul trebuie trimis
	uint16_t tx_port_id;
} delayed_packet_t;

// Array-ul global de profile
extern profile_queue my_queues[NUM_PROFILES];

// Funcții queues.c
void init_queues(void);
int classify_packet(struct rte_mbuf *m);
void apply_changes(struct rte_mbuf *m, int queue_id, uint16_t tx_port_id);

// Interfața publică a Min-Heap-ului pentru main.c
int heap_get_size(uint16_t port_id);
uint64_t heap_peek_time(uint16_t port_id);
delayed_packet_t heap_pop(uint16_t port_id);

#endif
