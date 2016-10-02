#include "parser.h"
#include "utils.h"

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
    unsigned int majVer = ver_num[1] * 255 + ver_num[0];
    unsigned int minVer = ver_num[3] * 255 + ver_num[2];
    printf("Version: %d.%d\n", majVer, minVer);
}

void printTimeStuff(unsigned char* time){
    unsigned int time_stuff = arrayToUInt(time, 4);
    printf("GMT timezone offset minus the timezone used in the headers in seconds: %d\n", time_stuff);

    unsigned int accuracy = arrayToUInt(time+4, 4);
    printf("Accuracy of the timestamps: %d\n", accuracy);
}

int maxPacketLength(unsigned char* packet_len){
    return arrayToUInt(packet_len, 4);
}

int linkLayerHeaderType(unsigned char* llht){
    unsigned int type = arrayToUInt(llht, 4);
    char* header_type_name = headerTypeName(type);
    printf("Link-Layer Header Type: %s\n", header_type_name);
    free(header_type_name);
    return type;
}

int parse(parser_t *parser, char *filename){
    size_t uchar_size = sizeof(unsigned char);
    FILE* file = fopen(filename, "rb");
    if(!file){
        printf("%s:\n", filename);
        printf("File could not be loaded\n");
        return NOK;
    }

    //read first 4 bytes - "Magic number" d4 c3 b2 a1
    unsigned char magic_num[4];
    rewind(file);
    int read_bytes_num = fread(magic_num, uchar_size, 4, file);
    if(read_bytes_num != 4){
        printf("Could not read magic number: File corrupted/too small\n");
        return NOK;
    }
    if(!checkMagicNumber(magic_num)){
        printf("Magic number incorrect\n");
        return NOK;
    }

    //read and print version number
    unsigned char version_num[4];
    read_bytes_num = fread(version_num, uchar_size, 4, file);
    if(read_bytes_num != 4){
        printf("Could not read version number: File corrupted/too small\n");
        return NOK;
    }
    printVersionNumber(version_num);

    //read and print some time stuff
    unsigned char time[8];
    read_bytes_num = fread(time, uchar_size, 8, file);
    if(read_bytes_num != 8){
        printf("Could not read time stuff: File corrupted/too small\n");
        return NOK;
    }
    printTimeStuff(time);

    //read maximum packet length (Snapshot Length)
    unsigned char max_packet_len[4];
    unsigned int snapshot_length = 0;   //max. packet length
    read_bytes_num = fread(max_packet_len, uchar_size, 4, file);
    if(read_bytes_num != 4){
        printf("Could not read Snapshot Length: File corrupted/too small\n");
        return NOK;
    }
    snapshot_length = maxPacketLength(max_packet_len);
    printf("Snapshot length: %d bytes\n", snapshot_length);

    //read Link-Layer Header Type
    unsigned char link_layer_header_type[4];
    read_bytes_num = fread(link_layer_header_type, uchar_size, 4, file);
    if(read_bytes_num != 4){
        printf("Could not read Link-Layer Header Type: File corrupted/too small\n");
        return NOK;
    }
    int llht = linkLayerHeaderType(link_layer_header_type); //also print


    //read & add packets

    return OK;   // remove/replace
}
