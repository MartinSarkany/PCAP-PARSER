#include "parser.h"

void initParser(parser_t *parser){
    parser->frame_list = NULL;
    parser->packet_list = NULL;
    parser->datagram_list = NULL;
}

long long readStuff(FILE* file, size_t size){   //reading up to 7 bytes of data
    if(size > 7){
        printf("Overflow could happen, returning -1\n");
        return -1;
    }
    unsigned char stuff_buff[4];
    if(fread(stuff_buff, sizeof(unsigned char), size, file) != size){
        return -1;
    }

    // if successfully read, return as number - returns long long so -1 can be returned
    return arrayToUInt(stuff_buff, size);
}

unsigned char* readBytes(FILE* file, size_t size){  // read data from file and return them as new allocated buffer
    unsigned char* buff = malloc(size);
    if(fread(buff, sizeof(unsigned char), size, file) != size){
        free(buff);
        buff = NULL;
        return NULL;    // return NULL if unsuccessful
    }

    return buff;
}

int checkMagicNumber(FILE* file){
    unsigned char* mag_num;
    if((mag_num = readBytes(file, 4)) == NULL){
        printf("Unable to read Magic Number\n");
        return NOK;
    }
    if(mag_num[0] == 0xd4 && mag_num[1] == 0xc3 &&
       mag_num[2] == 0xb2 && mag_num[3] == 0xa1){
        free(mag_num);
        mag_num = NULL; // Fixes #6 Issue : Memory Safety Violation
        return LITTLE_ENDIAN_;
    } else if(mag_num[0] == 0xa1 && mag_num[1] == 0xb2 &&
              mag_num[2] == 0xc3 && mag_num[3] == 0xd4){
        free(mag_num);
        mag_num = NULL;
        return BIG_ENDIAN_;
    }
    free(mag_num);
    mag_num = NULL; // Fixes #6 Issue : Memory Safety Violation 
    return NOK;
}

int printTimeStuff(FILE* file){
    unsigned char* time = readBytes(file, 8);
    if(!time){
        return NOK;
    }

    unsigned int time_stuff = arrayToUInt(time, 4);
    printf("GMT timezone offset minus the timezone used in the headers in seconds: %u\n", time_stuff);// changed to correct format specifier

    unsigned int accuracy = arrayToUInt(time+4, 4);
    printf("Accuracy of the timestamps: %u\n", accuracy); // Fixes #11  Incorrect use of Specifier

    free(time);
    time = NULL;

    return OK;
}

int linkLayerHeaderType(FILE* file){
    // read from file
    unsigned char* llht = readBytes(file, 4);
    if(!llht){
        return NOK;
    }
    // convert to uint
    unsigned int type = arrayToUInt(llht, 4);
    free(llht);
    llht = NULL;

    char* header_type_name;
    if(type != 1){
        // not ethernet, we're not parsing this
        header_type_name = "UNKNOWN";

    } else {    // we already know what the 1 is so no need to read the file at all
        header_type_name = "ETH10MB";
    }
    //print the label
    printf("Link-Layer Header Type: %s\n", header_type_name);

    return type;
}

int maxFrameLength(FILE* file){
    return readStuff(file, 4);
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

unsigned char* readMACAddress(FILE* file){
    return readBytes(file, 6);
}

int readType(FILE* file){
    unsigned char* type = readBytes(file, 2);
    if(type == NULL){
        return NOK;
    }

    if(type[0] == 0x08){
        if(type[1] == 0x00){
            free(type);
            type = NULL;

            return IPV4;
        }
        if(type[1] == 0x06){
            free(type);
            type = NULL;

            return ARP;
        }
    }
    if(type[0] == 0x86 && type[1] == 0xdd){
        free(type);
        type = NULL;

        return IPV6;
    }

    free(type);
    type = NULL;

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
    res = NULL; // Fixes #6 Issue : Memory Safety Violation
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

void printDatagram(datagram_t* datagram){
    packet_t* packet = datagram->packet;
    printf("\n+++++++++++++++++++++ Datagram +++++++++++++++++++++++\n");
    printTime(packet->timestamp);
    printf("                  + %d microseconds\nSource IP:        ", packet->microsecs);
    printIPAddress(packet->src_IP);
    printf("Destination IP:   ");
    printIPAddress(packet->dst_IP);
    printf("Source port:      %d\nDestination port: %d\n", datagram->src_port, datagram->dst_port);
    printf("Data size:        %d", datagram->data_size);
    printf("\n\n");
    //printf("\n+++++++++++++++++++++ Datagram +++++++++++++++++++++++\n");
}

void print4thLayer(parser_t* parser){
    datagram_t* datagram = parser->datagram_list;
    while(datagram){
        printDatagram(datagram);
        datagram = datagram->next;
    }
}

long long numDatagrams(parser_t* parser){
    long long nd = 0;
    datagram_t* dg = parser->datagram_list;
    while(dg){
        nd++;
        dg = dg->next;
    }

    return nd;
}

int parseGlobalHeader(FILE* file){
    int mag_num = checkMagicNumber(file);
    if(mag_num != LITTLE_ENDIAN_){
        if(mag_num == BIG_ENDIAN_){
            printf("Big endian - sorry, we're not parsing this.");
        } else {
            printf("Magic number incorrect\n");
        }
        return NOK;
    }

    //read and print version number
    unsigned char* version_num = readBytes(file, 4);
    if(version_num == NULL){
        printf("Could not read version number: File corrupted/too small\n");
        return NOK;
    }
    printVersionNumber(version_num);
    free(version_num);
    version_num = NULL; // Fixes #6 Issue : Memory Safety Violation

    //read and print some time stuff

    if(printTimeStuff(file) == NOK){
        printf("Could not read time stuff: File corrupted/too small\n");
        return NOK;
    }

    //read maximum frame length (Snapshot Length)
    //Fixes #10 Issue : Integer Overflow
    unsigned long long snapshot_length;   //max. frame length
    if((snapshot_length = maxFrameLength(file)) == -1){
        printf("Could not read Snapshot Length: File corrupted/too small\n");
        return NOK;
    }
    printf("Snapshot length: %d bytes\n", (unsigned int)snapshot_length);

    //read Link-Layer Header Type
    int llht = linkLayerHeaderType(file); //also print
    if(llht == NOK){
        printf("Could not read Link-Layer Header Type: File corrupted/too small\n");
        return NOK;
    }

    if(llht != 1) {
        printf("Sorry, we are not parsing this.\n");
        return NOK;
    }

    return OK;
}

int parse(parser_t *parser, char *filename){
    FILE* file = fopen(filename, "rb");
    if(!file){
        printf("%s:\n", filename);
        printf("File could not be loaded\n");
        return NOK;
    }

    rewind(file);

    if(parseGlobalHeader(file) == NOK){
        return NOK;
    }

    //read & add frames
    do{
        time_t timestamp;
        if((timestamp = readTimeStamp(file)) == -1){
            printf("Could not read timestamp\n");
            return NOK;
        }
        int microsecs;
        if((microsecs = readMicrosecs(file)) == -1){
            printf("Could not read microseconds part of timestamp\n");
            return NOK;
        }
        long long capt_data_len;
        if((capt_data_len = readFrameSize(file)) == -1){
            printf("Could not read captured frame size\n");    //restricted to max Snapshot Length
            return NOK;
        }
        long long real_data_len;                        //we don't really need this in this project but anyway..
        if((real_data_len = readFrameSize(file)) == -1){
            printf("Could not read real frame size\n");
            return NOK;
        }
        unsigned char* dst_addr = readMACAddress(file); //we don't really need this in this project but anyway..
        if(dst_addr == NULL){
            printf("Could not read destination MAC address\n");
            return NOK;
        }
        unsigned char* src_addr = readMACAddress(file); //we don't really need this in this project but anyway..
        if(dst_addr == NULL){
            free(dst_addr);
            dst_addr = NULL;
            printf("Could not read source MAC address\n");
            return NOK;
        }

        int type = readType(file);
        if(type == NOK){
            printf("Error reading protocol\n");

            free(dst_addr);
            dst_addr = NULL;
            free(src_addr);
            src_addr = NULL;

            return NOK;
        }

        unsigned char* data = readData(file, capt_data_len - 18);
        if(data == NULL){
            printf("Error reading data from file\n");

            free(dst_addr);
            dst_addr = NULL;
            free(src_addr);
            src_addr = NULL;

            return NOK;
        }

        if(skipCRC(file) == NOK){
            return NOK;
        }

        if(type == IPV4){
            addFrame(&parser->frame_list, createFrame(timestamp, microsecs, capt_data_len, real_data_len, src_addr, dst_addr, type, data, capt_data_len - 18 /*actual data size*/));
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
    return OK;
}
