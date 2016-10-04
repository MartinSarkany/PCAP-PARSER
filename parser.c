#include "parser.h"
#include "utils.h"

void initParser(parser_t *parser){
    parser->packet_list = NULL;
    parser->size = 0;
}

packet_t* createPacket(time_t timestamp, int microsecs, int cap_len, int real_len,
                       unsigned char* src_addr, unsigned char* dst_addr, int type,
                       unsigned char* data){
    packet_t* packet = malloc(sizeof(packet_t));
    packet->timestamp = timestamp;
    packet->microsecs = microsecs;
    packet->captured_len = cap_len;
    packet->real_len = real_len;

    packet->src_addr = src_addr;
    packet->dst_addr = dst_addr;
    packet->type = type;
    packet->data = data;

    packet->next = NULL;

    return packet;
}

//Add packet to list
packet_t* addPacket(parser_t* parser, packet_t* new_packet){
    //if empty list, initialize
    if(!parser->packet_list){
        parser->size++;
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
    if(!header_type_name){
        header_type_name = malloc(16 * sizeof(char));
        memset(header_type_name, sizeof(char), 16);
        strcpy(header_type_name, "File not found\n");
    }
    printf("Link-Layer Header Type: %s\n", header_type_name);
    free(header_type_name);
    return type;
}

long long readStuff(FILE* file, size_t size){   //I didn't want to have FILE here but wanted to make parse() shorter
    if(size > 7){
        printf("Overflow could happen, returning -1\n");
        return -1;
    }
    unsigned char stuff_buff[4];
    if(fread(stuff_buff, sizeof(unsigned char), size, file) != size){
        return -1;
    }

    return arrayToUInt(stuff_buff, size);
}

long long readTimeStamp(FILE* file){
    return readStuff(file, 4);
}

long long readMicrosecs(FILE* file){
    return readStuff(file, 4);
}

long long readPacketSize(FILE* file){
    return readStuff(file, 4);
}

unsigned char* readBytes(FILE* file, size_t size){
    unsigned char* buff = malloc(size);
    if(fread(buff, sizeof(unsigned char), size, file) != size){
        return NULL;
    }

    return buff;
}

unsigned char* readMACAddress(FILE* file){
    return readBytes(file, 6);
}

int readType(FILE* file){
    unsigned char* type = readBytes(file, 2);
    if(type[0] == 0x08){
        if(type[1] == 0x00){
            return IPV4;
        }
        if(type[1] == 0x06){
            return ARP;
        }
    }
    if(type[0] == 0x86 && type[1] == 0xdd){
        return IPV6;
    }

    return UNKNOWN;
}

unsigned char* readData(FILE* file, size_t size){
    return readBytes(file, size);
}

int skipCRC(FILE* file){
    unsigned char* res = readBytes(file, 4);
    if(res == NULL){
        return NOK;
    }
    free(res);
    return OK;
}

void printFrame(packet_t* frame){
    printTime(frame->timestamp);
    printf("+%d microsecs\nSource MAC address: ", frame->microsecs);
    printMACAddress(frame->src_addr);
    printf("Destination MAC address: ");
    printMACAddress(frame->dst_addr);
    printf("Size: %d (%d)\n",frame->captured_len, frame->real_len);
    printf("\n\n");
}

void print2ndLayer(parser_t* parser){
    packet_t* frame = parser->packet_list;
    while(frame){
        printFrame(frame);
        frame = frame->next;
    }
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
    if(llht != 1){
        printf("Sorry, we are not parsing this.\n");
        return NOK;
    }

    //read & add packets
    do{
        time_t timestamp;
        if((timestamp = readTimeStamp(file)) == -1){
            printf("Could not read timestamp\n");
            return NOK;    //continue to next packet instead
        }
        int microsecs;
        if((microsecs = readMicrosecs(file)) == -1){
            printf("Could not read microseconds part of timestamp\n");
            return NOK;    //continue to next packet instead
        }
        long long capt_data_len;
        if((capt_data_len = readPacketSize(file)) == -1){
            printf("Could not read captured packet size\n");    //restricted to max Snapshot Length
            return NOK;    //continue to next packet instead
        }
        long long real_data_len;
        if((real_data_len = readPacketSize(file)) == -1){
            printf("Could not read real packet size\n");
            return NOK;    //continue to next packet instead
        }

        //printTime(timestamp);
        //printf("+ %d microseconds\ncaptured packet size: %lld\nreal packet size: %lld\n", microsecs, capt_data_len, real_data_len);

        unsigned char* dst_addr = readMACAddress(file);
        if(dst_addr == NULL){
            printf("Could not read destination MAC address\n");
            return NOK;
        }

        unsigned char* src_addr = readMACAddress(file);
        if(dst_addr == NULL){
            printf("Could not read source MAC address\n");
            return NOK;
        }

        //printf("Source:");
        //printMACAddress(dst_addr);
        //printf("Destination:");
        //printMACAddress(src_addr);

        int type = readType(file);
        //printProtocol(type);

        unsigned char* data = readData(file, capt_data_len - 18);
        if(skipCRC(file) == NOK){
            return NOK;
        }

        //printf("\n\n");

        if(type == IPV4){
            addPacket(parser, createPacket(timestamp, microsecs, capt_data_len, real_data_len, src_addr, dst_addr, type, data));
        }

        //determine if it's end of file
        fpos_t position;
        fgetpos(file, &position);
        if(fgetc(file) == EOF){
            break;
        }
        fsetpos(file, &position);

    }while(1);

    fclose(file);
    file = NULL;
    return OK;   // remove/replace
}
