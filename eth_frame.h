#ifndef ETH_FRAME_H
#define ETH_FRAME_H

#include <time.h>
#include "utils.h"

// ethernet frame (header + data + metadata)
typedef struct frame{
    time_t timestamp;
    int microsecs;
    int captured_len;
    int real_len;

    unsigned char* src_addr;
    unsigned char* dst_addr;
    int type;
    unsigned char* data;
    int data_size;

    struct frame* next;
}frame_t;

// returns initialized frame
frame_t* createFrame(time_t timestamp, int microsecs, int cap_len, int real_len,
                       unsigned char* src_addr, unsigned char* dst_addr, int type,
                       unsigned char* data, int data_size);
// adds frame to a list (in parser structure)
frame_t* addFrame(frame_t** frame_list_p, frame_t* new_frame);
// clears the list
void clearFrames(frame_t** frame_list_p);

#endif // ETH_FRAME_H
