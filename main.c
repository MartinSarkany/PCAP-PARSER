#include <stdio.h>
#include <string.h>
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

    parse(&parser, filename);

    return 0;
}
