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

    unsigned char stuff_buff[size];
    if(fread(stuff_buff, sizeof(unsigned char), size, file) != size){
        return -1;
    }

    // if successfully read, return as number - returns long long so -1 can be returned
    return arrayToUInt(stuff_buff, size);
}

unsigned char* readBytes(FILE* file, size_t size){  // read data from file and return them as new allocated buffer
    unsigned char* buff = malloc(size);
    if(fread(buff, sizeof(unsigned char), size, file) != size){
        freePtr((void**)&buff);

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
        freePtr((void**)&mag_num);

        return LITTLE_ENDIAN_;
    } else if(mag_num[0] == 0xa1 && mag_num[1] == 0xb2 &&
              mag_num[2] == 0xc3 && mag_num[3] == 0xd4){
        freePtr((void**)&mag_num);

        return BIG_ENDIAN_;
    }
    freePtr((void**)&mag_num);

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

long long maxFrameLength(FILE* file){
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
            freePtr((void**)&type);
            return IPV4;
        }
        if(type[1] == 0x06){
            freePtr((void**)&type);
            return ARP;
        }
    }

    if(type[0] == 0x86 && type[1] == 0xdd){
        freePtr((void**)&type);
        return IPV6;
    }

    freePtr((void**)&type);

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
    freePtr((void**)&res);

    return OK;
}

void printFrame(frame_t* frame){
    printTime(frame->timestamp);
    printf("+%d microsecs\nSource MAC address: ", frame->microsecs);
    printMACAddress(frame->src_addr);
    printf("Destination MAC address: ");
    printMACAddress(frame->dst_addr);
    printf("Size: %d (%d)\n\n",frame->captured_len, frame->real_len);
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
    printf("Size: %d\n\n",packet->data_size);
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
    printf("Source port:      %u\nDestination port: %u\n", datagram->src_port, datagram->dst_port);
    printf("Data size:        %d\n\n", datagram->data_size);
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

int processVersionNumber(FILE* file){
    unsigned char* version_num = readBytes(file, 4);
    if(version_num == NULL){
        printf("Could not read version number: File corrupted/too small\n");
        return NOK;
    }

    printVersionNumber(version_num);

    freePtr((void**)&version_num);

    return OK;
}

int processSnapshotLength(FILE* file){
    long long snapshot_length;   //max. frame length
    if((snapshot_length = maxFrameLength(file)) == -1){
        printf("Could not read Snapshot Length: File corrupted/too small\n");
        return NOK;
    }

    printf("Snapshot length: ");
    printLongLong(snapshot_length);
    printf(" bytes\n");

    return OK;
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
    if(processVersionNumber(file) != OK){
        return NOK;
    }

    //read and print some time stuff
    if(printTimeStuff(file) == NOK){
        printf("Could not read time stuff: File corrupted/too small\n");
        return NOK;
    }

    //read maximum frame length (Snapshot Length)
    if(processSnapshotLength(file) != OK){
        printf("Error processing snapshot length\n");
        return NOK;
    }

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

frame_t* readTime(FILE* file, frame_t* frame){
    if(file == NULL || frame == NULL){
        printf("Incorrect argument(s)\n");
        return NULL;
    }

    time_t timestamp;
    if((timestamp = readTimeStamp(file)) == -1){
        printf("Could not read timestamp\n");
        return NULL;
    }

    int microsecs;
    if((microsecs = readMicrosecs(file)) == -1){
        printf("Could not read microseconds part of timestamp\n");
        return NULL;
    }

    frame->timestamp = timestamp;
    frame->microsecs = microsecs;

    return frame;
}

frame_t* readLengths(FILE* file, frame_t* frame, /*out*/ int* capt_data_len){
    if(file == NULL || frame == NULL){
        printf("Incorrect argument(s)\n");
        return NULL;
    }

    if((*capt_data_len = readFrameSize(file)) == -1){
        printf("Could not read captured frame size\n");    //restricted to max Snapshot Length
        return NULL;
    }

    long long real_data_len;                        //we don't really need this in this project but anyway..
    if((real_data_len = readFrameSize(file)) == -1){
        printf("Could not read real frame size\n");
        return NULL;
    }

    frame->captured_len = *capt_data_len;
    frame->real_len = real_data_len;

    return frame;
}

frame_t* readMACs(FILE* file, frame_t* frame){
    if(file == NULL || frame == NULL){
        printf("Incorrect argument(s)\n");
        return NULL;
    }

    unsigned char* dst_addr = readMACAddress(file); //we don't really need this in this project but anyway..
    if(dst_addr == NULL){
        printf("Could not read destination MAC address\n");
        return NULL;
    }
    unsigned char* src_addr = readMACAddress(file); //we don't really need this in this project but anyway..
    if(dst_addr == NULL){
        freePtr((void**)&dst_addr);
        printf("Could not read source MAC address\n");
        return NULL;
    }

    frame->dst_addr = dst_addr;
    frame->src_addr = src_addr;

    return frame;

}

frame_t* readTypeAndData(FILE* file, frame_t* frame, /*in*/ int data_len /*without header*/){
    if(file == NULL || frame == NULL){
        printf("Incorrect argument(s)\n");
        return NULL;
    }

    int type = readType(file);
    if(type == NOK){
        printf("Error reading protocol\n");
        return NULL;
    }

    unsigned char* data = readData(file, data_len);
    if(data == NULL){
        printf("Error reading data from file\n");
        return NULL;
    }

    frame->type = type;
    frame->data = data;
    frame->data_size = data_len;

    return frame;
}

frame_t* readFrame(FILE* file){
    frame_t* new_frame = malloc(sizeof(frame_t));
    if(new_frame == NULL){
        printf("Memory allocation failed.");
        return NULL;
    }

    new_frame->next = NULL;

    if(readTime(file, new_frame) == NULL){
        return NULL;    // error message already printed
    }

    int capt_data_len;
    if(readLengths(file, new_frame, &capt_data_len) == NULL){
        return NULL;    // errot message already printed
    }

    if(readMACs(file, new_frame) == NULL){
        clearFrame(new_frame);
        return NULL;
    }

    if(readTypeAndData(file, new_frame, capt_data_len - 18) == NULL){
        clearFrame(new_frame);
        return NULL;
    }

    if(skipCRC(file) == NOK){
        clearFrame(new_frame);
        return NULL;
    }

    if(new_frame->type != IPV4){
        clearFrame(new_frame);
        return NULL;
    }

    return new_frame;
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
        frame_t* new_frame = readFrame(file);

        if(new_frame != NULL){
            addFrame(&parser->frame_list, new_frame);
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
