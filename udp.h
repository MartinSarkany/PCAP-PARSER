#ifndef UDP_H
#define UDP_H

#include "ipv4.h"

/* UDP Header*/
typedef struct UDP_Header{
    unsigned char sport;          // Source port number
    unsigned char dport;          // Destination port #
    unsigned char len;            // Datagram length
    unsigned char crc;            // Checksum
}UDP_Header;

typedef unsigned char Byte;

void Read_UDP_Header(Byte *data, int UDP_Length);

unsigned short CheckSum(unsigned short *buffer, int length);

typedef struct datagram{
    unsigned int src_port;
    unsigned int dst_port;
    int data_size;

    packet_t* packet;

    struct datagram* next;
} datagram_t;

datagram_t* createDatagram(int src_port, int dst_port, int data_size, packet_t* packet);
datagram_t* addDatagram(datagram_t** datagram_list_p, datagram_t* new_datagram);
int extractPort(unsigned char* buff);
int process_datagrams(packet_t* packet_list, datagram_t** datagram_list_p);

#endif // UDP_H
