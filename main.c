#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "parser.h"

int main(int argc, char *argv[])
{
    if(argc < 2){
        printf("No filename specified\n");
        return 1;
    }

    char* filename = argv[1];   //just to make it more readable
    parser_t parser;
    initParser(&parser);

    if(parse(&parser, filename) == NOK){
        printf("\n\n PARSING FAILED\n\n");
        exit(1);
    }

    process_frames(parser.frame_list, &parser.packet_list);
    process_packets(parser.packet_list, &parser.datagram_list);
    clearFrames(&parser.frame_list);
    printf("Total number of datagrams: %I64d\n\n", numDatagrams(&parser));
    print4thLayer(&parser);
    clearPackets(&parser.packet_list);

    return 0;
}
