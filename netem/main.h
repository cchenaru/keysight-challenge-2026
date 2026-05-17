#ifndef __MAIN_H__
#define __MAIN_H__

#include <stdint.h>
#include <rte_common.h>

// UDP PACKETS WILL BE DUPLICATED RANDOMLY
// TCP WILL BE DROPPED RANDOMLY
// ICMP WILL BE DELAYED RANDOMLY
// DEFINES FOR PACKET CLASIFICATION 
#define IP_BROADCAST		0xFFFFFFFF
#define UDP_PROTOCOL		17
#define TCP_PROTOCOL		6
#define IP_PROTOCOL_ICMP	1

// flags for modify function
#define DUPLICATE_FLAG          1
#define DUPLICATE_FLAG_WHEN     2
#define DROP_FLAG               2
#define DROP_FLAG_WHEN          2
#define DELAY_FLAG              3
#define DELAY_FLAG_WHEN         4

#define PQ_NR       4
#define BURST_SIZE  8

#define RING_SIZE 4096

#define DELAY_MIN_MS  50
#define DELAY_MAX_MS 150

/* Per-port statistics struct */
struct netem_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;


#endif
