#ifndef PARSER_H
#define PARSER_H

#include "stdio.h"

#define OK 1
#define NOK 0

typedef struct packet{
    //content of the packet
    struct packet* next;
}packet_t;

typedef struct{
    int size;
    packet_t *packet_list;
} parser_t;


packet_t* createPacket();
packet_t* addPacket(parser_t* parser, packet_t* new_packet);

void initParser(parser_t* parser);
int checkMagicNumber(unsigned char* mag_num);
void printVersionNumber(unsigned char* ver_num);
void printTimeStuff(unsigned char* time);
int maxPacketLength(unsigned char* packet_len);
int parse(parser_t* parser, char* filename);  //filename must be correct C string





#endif // PARSER_H
