#ifndef PARSER_H
#define PARSER_H

#include "stdio.h"
#include <time.h>

#define OK 1
#define NOK 0

typedef struct packet{
    //content of the packet
    time_t timestamp;
    int microsecs;
    int captured_len;
    int real_len;

    unsigned char* src_addr;
    unsigned char* dst_addr;
    int type;
    unsigned char* data;

    struct packet* next;
}packet_t;

typedef struct{
    int size;
    packet_t *packet_list;
} parser_t;


packet_t* createPacket(time_t timestamp, int microsecs, int cap_len, int real_len,
                       unsigned char* src_addr, unsigned char* dst_addr, int type,
                       unsigned char* data);
packet_t* addPacket(parser_t* parser, packet_t* new_packet);

void initParser(parser_t* parser);
int checkMagicNumber(unsigned char* mag_num);
void printVersionNumber(unsigned char* ver_num);
void printTimeStuff(unsigned char* time);
int maxPacketLength(unsigned char* packet_len);
int linkLayerHeaderType(unsigned char* llht);
long long readStuff(FILE* file, size_t size);
long long readTimeStamp(FILE* file);
long long readMicrosecs(FILE* file);
long long readPacketSize(FILE* file);
unsigned char* readBytes(FILE* file, size_t size);
unsigned char* readMACAddress(FILE* file);
int readType(FILE* file);
unsigned char* readData(FILE* file, size_t size);
int skipCRC(FILE* file);
void printFrame(packet_t* frame);
void print2ndLayer(parser_t* parser);
int parse(parser_t* parser, char* filename);  //filename must be correct C string





#endif // PARSER_H
