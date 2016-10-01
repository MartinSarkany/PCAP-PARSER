#include "parser.h"


void initParser(parser_t *parser){
    parser->packet_list = NULL;
    parser->size = 0;
}

//Add packet to list
packet_t* addPacket(parser_t* parser, packet_t* new_packet){
    //if empty list, initialize
    if(!parser->packet_list){
        parser->packet_list = new_packet;
        return new_packet;
    }

    //if not empty, find the last packet and add the new one
    packet_t* current_packet = parser->packet_list;
    while(current_packet->next != NULL){
        current_packet = current_packet->next;
    }
    current_packet->next = new_packet;

    return new_packet;
}


int parse(parser_t *parser, char *filename){
    FILE* file = fopen(filename, "rb");
    if(!file){
        printf("File could not be loaded\n");
        return 0;
    }

    //read & add packets

    return 1;   // remove/replace
}
