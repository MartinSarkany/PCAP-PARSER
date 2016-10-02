#include "parser.h"

#define OK 1
#define NOK 0


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

int checkMagicNumber(unsigned char* mag_num){
    if(mag_num[0] != 0xd4 || mag_num[1] != 0xc3 ||
       mag_num[2] != 0xb2 || mag_num[3] != 0xa1){
        printf("Magic number checking failed\n");
        return NOK;
    }
    return OK;
}

void printVersionNumber(unsigned char* ver_num){
    int majVer = ver_num[1] * 255 + ver_num[0];
    int minVer = ver_num[3] * 255 + ver_num[2];
    printf("Version: %d.%d\n", majVer, minVer);
}

int parse(parser_t *parser, char *filename){
    FILE* file = fopen(filename, "rb");
    if(!file){
        printf("%s:\n", filename);
        printf("File could not be loaded\n");
        return NOK;
    }

    //read first 4 bytes - "Magic number" d4 c3 b2 a1
    unsigned char magic_num[4];
    rewind(file);
    int read_bytes_num = fread(magic_num, sizeof(unsigned char), 4, file);
    if(read_bytes_num != 4){
        printf("Could not read magic number: File corrupted/too small\n");
        return NOK;
    }
    if(!checkMagicNumber(magic_num)){
        printf("Magic number incorrect\n");
        return NOK;
    }

    //read version number
    unsigned char version_num[4];
    read_bytes_num = fread(version_num, sizeof(unsigned char), 4, file);
    if(read_bytes_num != 4){
        printf("Could not read version number: File corrupted/too small\n");
        return NOK;
    }
    printVersionNumber(version_num);

    //read & add packets

    return OK;   // remove/replace
}
