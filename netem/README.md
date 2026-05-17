# Keysight Challenge 2026
 
 
## Main Implementation
 
The main thread is the entry for all incoming traffic. It runs on each lcore and listens on its assigned RX port. When packets arrive the main thread reads them in bursts(up to 32 at a time) and figures out which priority queue each packet belongs to.
 
Once a packet is classified it gets placed into the `buffer_in` ring of the appropriate worker thread. The main thread then signals the relevant worker threads (by using the condition variables) that new data is waiting and those threads wake up to process their packets.
 
## Packet Classification
 
When a packet arrives, the main thread first checks whether it's an IPv4 packet. If it's not, it goes straight to the default queue. For IPv4 packets, classification is done based on the transport layer protoco: UDP, TCP, ICMP, anything else goes to the default queue.
 
 
## Worker threads and Processing the packets
 
Each worker thread owns a pair of rings: `buffer_in` (where the main thread drops packets) and `buffer_out` (where processed packets wait to be sent). Worker threads sleep until the main thread wakes them up with a signal, then drain their input buffer and apply the specific network effect (UDP -> Duplicate, TCP-> Drop, ICMP -> Delay) before forwarding the packets to the TX port. All worker threads share a single TX mutex (`lock_TX` ) to avoid concurrent writes to the transmit buffer.
 
## Handling Full Buffers
 
Instead of a fixed ring buffer per thread, it uses a vector of double-linked lists. This way, if a thread's buffer fills up, a new thread can be spawned dinamically to handle the overflow and continue processing  without dropping the packets unnecessarily. The double linked-list is implemented manually. Each `Node` holds a `thread` pointer and the `list` has the functions `insertFront`, `insertRear`, `deleteNode` in order to be able to easily handle the problem of `full buffering`.
