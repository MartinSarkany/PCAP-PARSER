#ifndef IPV4_H
#define IPV4_H

#include "eth_frame.h"
#include <stdlib.h>


#define OK 1
#define NOK 0

// IPv4 packet (header + data + metadata)
typedef struct packet{
    time_t timestamp;
    int microsecs;
    unsigned char* src_IP;
    unsigned char* dst_IP;

    int data_size;
    unsigned char* data;

    struct packet* next;
} packet_t;

// returns version of IP protocol as integer
int extractVersion(unsigned char v);
// returns header length in bytes
int extractHeaderLength(unsigned char hl);
//returns length of whole packet (header + data)
int extractTotalLength(unsigned char* buff);
// true if packet is fragmented
int isFragmented(unsigned char b);
// true if first fragment of packet
int zeroOffset(unsigned char* buff);
// true if packet contains UDP datagram
int isUDP(unsigned char b);
// returns buffer with copied IP address
unsigned char* extractIPAddr(unsigned char* buffer);
// returns buffer with copied data
unsigned char* extractData(unsigned char* buffer);
// returns initialized packet structure
packet_t* createPacket(time_t timestamp, int microsecs, unsigned char* src_IP, unsigned char* dst_IP,
                       unsigned char* data, int data_size);
// adds packet to list (used with in parser)
packet_t* addPacket(packet_t** packet_list_p, packet_t* new_packet);
// extracts packets from list of ethernet frames
int process_frames(frame_t* frame_list, packet_t** packet_list_p);



#endif // IPV4_H
