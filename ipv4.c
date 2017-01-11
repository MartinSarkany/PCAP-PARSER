#include "ipv4.h"
#include <stdio.h>  //remove with all printf() functions

int extractVersion(unsigned char v){
    return v >> 4;
}

int extractHeaderLength(unsigned char hl){
    return 4 * (hl & 0x0F);
}

int extractTotalLength(unsigned char* buff){
    return arrayToUIntBE(buff, 2);
}

int isFragmented(unsigned char b){
    int tmp = b >> 5;
    if(tmp & 0x01){
        return 1;
    }
    return 0;
}

int zeroOffset(unsigned char* buff){
    if(buff[1]){
        return 0;
    }
    unsigned char tmp = buff[0] & 0x1F;
    return !tmp;
}

int isUDP(unsigned char b){
    if(b == 0x11){
        return 1;
    }
    return 0;
}

unsigned char* extractIPAddr(unsigned char* buffer){
    unsigned char* addr = malloc(4);
    memcpy(addr, buffer, 4);
    return addr;
}

packet_t* createPacket(time_t timestamp, int microsecs, unsigned char* src_IP, unsigned char* dst_IP,
                       unsigned char* data, int data_size){
    packet_t* packet = malloc(sizeof(packet_t));
    packet->next = NULL;

    packet->timestamp = timestamp;
    packet->microsecs = microsecs;
    packet->data_size = data_size;
    packet->data = data;
    packet->src_IP = src_IP;
    packet->dst_IP = dst_IP;

    return packet;
}

packet_t* addPacket(packet_t** packet_list_p, packet_t* new_packet){
    if(!(*packet_list_p)){
        *packet_list_p = new_packet;
        return new_packet;
    }

    //if not empty, find the last packet and add the new one
    packet_t* current_packet = *packet_list_p;
    while(current_packet->next != NULL){
        current_packet = current_packet->next;
    }
    current_packet->next = new_packet;

    return new_packet;
}

void clearPacket(packet_t* packet){
    free(packet->src_IP);
    packet->src_IP = NULL; // Fixes #6 Issue : Memory Safety Violation
    free(packet->dst_IP);
    packet->dst_IP = NULL; // Fixes #6 Issue : Memory Safety Violation
    free(packet->data);
    packet->data = NULL; // Fixes #6 Issue : Memory Safety Violation
}

void clearPackets(packet_t** packet_list_p){
    packet_t* cur_packet = (*packet_list_p);
    while(cur_packet){
        clearPacket(cur_packet);
        packet_t* prev_packet = cur_packet;
        cur_packet = cur_packet->next;
        free(prev_packet);
        prev_packet = NULL; // Fixes #6 Issue : Memory Safety Violation
    }
    *packet_list_p = NULL;
}

int process_frames(frame_t* frame_list, packet_t** packet_list_p){
    // return NOK if nothing to process
    if(!frame_list){
        return NOK;
    }

    frame_t* cur_frame = frame_list;
    //process frames in loop
    do{
        if(cur_frame->data_size < 16){
            printf("Corrupted packet");
            cur_frame = cur_frame->next;
            continue;
        }
        unsigned char* data = cur_frame->data; //just to shorten name
        int version = extractVersion(data[0]);
        if(version != 4){
            printf("Wrong version, shouldn't happen\n");
            cur_frame = cur_frame->next;
            continue;
        }
        int header_len = extractHeaderLength(data[0]);
        if(cur_frame->data_size < header_len){
            printf("Corupted packet\n");
            cur_frame = cur_frame->next;
            continue;
        }
        /*int total_len = */extractTotalLength(data + 2);
        //int data_len = total_len - header_len;
        // for some reason, packet size stated in file is always 4 bytes more than actual data size
        // and we don't care about data at all so will just ignore it
        int data_len = cur_frame->data_size - header_len;

        int fragmented = isFragmented(data[6]);
        if(fragmented && !zeroOffset(data+6)){
            cur_frame = cur_frame->next;
            continue; //not the first fragment (we don't care about data, just the header)
        }
        int is_udp = isUDP(data[9]);
        if(!is_udp){
            cur_frame = cur_frame->next;
            continue;
        }
        unsigned char* src_IP = extractIPAddr(data + 12);
        unsigned char* dst_IP = extractIPAddr(data + 16);

        // copy packet data from frame data (frame data will be freed later in main())
        unsigned char* packet_data = malloc(data_len);
        memcpy(packet_data, data + header_len, data_len);

        addPacket(packet_list_p, createPacket(cur_frame->timestamp, cur_frame->microsecs, src_IP, dst_IP, packet_data, data_len));

        cur_frame = cur_frame->next;
    }while(cur_frame != NULL);



    return OK;
}
