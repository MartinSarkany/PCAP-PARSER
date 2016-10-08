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

    //print2ndLayer(&parser);
    process_frames(parser.frame_list, &parser.packet_list);
    print3rdLayer(&parser);

    return 0;
}
