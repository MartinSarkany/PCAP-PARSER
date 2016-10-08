#ifndef IPV4_H
#define IPV4_H

#include "eth_frame.h"
#include <stdlib.h>


#define OK 1
#define NOK 0

typedef struct packet{
    time_t timestamp;
    int microsecs;
    unsigned char* src_IP;
    unsigned char* dst_IP;

    int data_size;
    unsigned char* data;

    struct packet* next;
} packet_t;


int extractVersion(unsigned char v);
int extractHeaderLength(unsigned char hl);
int extractTotalLength(unsigned char* buff);
int isFragmented(unsigned char b);
int zeroOffset(unsigned char* buff);
int isUDP(unsigned char b);
unsigned char* extractIPAddr(unsigned char* buffer);
unsigned char* extractData(unsigned char* buffer);
packet_t* createPacket(time_t timestamp, int microsecs, unsigned char* src_IP, unsigned char* dst_IP,
                       unsigned char* data, int data_size);
packet_t* addPacket(packet_t** packet_list_p, packet_t* new_packet);
int process_frames(frame_t* frame_list, packet_t** packet_list_p);



#endif // IPV4_H
