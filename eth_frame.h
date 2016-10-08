#ifndef ETH_FRAME_H
#define ETH_FRAME_H

#include <time.h>
#include "utils.h"

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


#endif // ETH_FRAME_H
