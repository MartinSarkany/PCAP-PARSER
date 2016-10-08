#include "parser.h"

void initParser(parser_t *parser){
    parser->frame_list = NULL;
    parser->packet_list = NULL;
    //parser->frames_num = 0;
    //parser->packets_num = 0;
}

frame_t* createFrame(time_t timestamp, int microsecs, int cap_len, int real_len,
                       unsigned char* src_addr, unsigned char* dst_addr, int type,
                       unsigned char* data, int data_size){
    frame_t* frame = malloc(sizeof(frame_t));
    frame->timestamp = timestamp;
    frame->microsecs = microsecs;
    frame->captured_len = cap_len;
    frame->real_len = real_len;

    frame->src_addr = src_addr;
    frame->dst_addr = dst_addr;
    frame->type = type;
    frame->data = data;
    frame->data_size = data_size;

    frame->next = NULL;

    return frame;
}


//Add frame to list
frame_t* addFrame(parser_t* parser, frame_t* new_frame){
    //if empty list, initialize
    if(!parser->frame_list){
        parser->frame_list = new_frame;
        return new_frame;
    }

    //if not empty, find the last frame and add the new one
    frame_t* current_frame = parser->frame_list;
    while(current_frame->next != NULL){
        current_frame = current_frame->next;
    }
    current_frame->next = new_frame;
    //parser->frames_num++;

    return new_frame;
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

int maxFrameLength(unsigned char* frame_len){
    return arrayToUInt(frame_len, 4);
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

long long readFrameSize(FILE* file){
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

void printFrame(frame_t* frame){
    printTime(frame->timestamp);
    printf("+%d microsecs\nSource MAC address: ", frame->microsecs);
    printMACAddress(frame->src_addr);
    printf("Destination MAC address: ");
    printMACAddress(frame->dst_addr);
    printf("Size: %d (%d)\n",frame->captured_len, frame->real_len);
    printf("\n\n");
}

void print2ndLayer(parser_t* parser){
    frame_t* frame = parser->frame_list;
    while(frame){
        printFrame(frame);
        frame = frame->next;
    }
}

void printPacket(packet_t* packet){
    printTime(packet->timestamp);
    printf("+%d microsecs\nSource ", packet->microsecs);
    printIPAddress(packet->src_IP);
    printf("Destination ");
    printIPAddress(packet->dst_IP);
    printf("Size: %d\n",packet->data_size);
    printf("\n\n");
}

void print3rdLayer(parser_t* parser){
    packet_t* packet = parser->packet_list;
    while(packet){
        printPacket(packet);
        packet = packet->next;
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

    //read maximum frame length (Snapshot Length)
    unsigned char max_frame_len[4];
    unsigned int snapshot_length = 0;   //max. frame length
    read_bytes_num = fread(max_frame_len, uchar_size, 4, file);
    if(read_bytes_num != 4){
        printf("Could not read Snapshot Length: File corrupted/too small\n");
        return NOK;
    }
    snapshot_length = maxFrameLength(max_frame_len);
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

    //read & add frames
    do{
        time_t timestamp;
        if((timestamp = readTimeStamp(file)) == -1){
            printf("Could not read timestamp\n");
            return NOK;    //continue to next frame instead
        }
        int microsecs;
        if((microsecs = readMicrosecs(file)) == -1){
            printf("Could not read microseconds part of timestamp\n");
            return NOK;    //continue to next frame instead
        }
        long long capt_data_len;
        if((capt_data_len = readFrameSize(file)) == -1){
            printf("Could not read captured frame size\n");    //restricted to max Snapshot Length
            return NOK;    //continue to next frame instead
        }
        long long real_data_len;
        if((real_data_len = readFrameSize(file)) == -1){
            printf("Could not read real frame size\n");
            return NOK;    //continue to next frame instead
        }

        //printTime(timestamp);
        //printf("+ %d microseconds\ncaptured frame size: %lld\nreal frame size: %lld\n", microsecs, capt_data_len, real_data_len);

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
            addFrame(parser, createFrame(timestamp, microsecs, capt_data_len, real_data_len, src_addr, dst_addr, type, data, capt_data_len - 18 /*actual data size*/));
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
