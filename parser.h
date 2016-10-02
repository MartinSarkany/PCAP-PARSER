#ifndef PARSER_H
#define PARSER_H

#include "stdio.h"

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

int parse(parser_t* parser, char* filename);  //filename must be correct C string





#endif // PARSER_H
