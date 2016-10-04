#ifndef PARSER_H
#define PARSER_H

#include "stdio.h"
#include <time.h>

#define OK 1
#define NOK 0

typedef struct frame{
    //content of the frame
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

typedef struct{
    int size;
    frame_t *frame_list;
} parser_t;


frame_t* createFrame(time_t timestamp, int microsecs, int cap_len, int real_len,
                       unsigned char* src_addr, unsigned char* dst_addr, int type,
                       unsigned char* data, int data_size);
frame_t* addFrame(parser_t* parser, frame_t* new_frame);

void initParser(parser_t* parser);
int checkMagicNumber(unsigned char* mag_num);
void printVersionNumber(unsigned char* ver_num);
void printTimeStuff(unsigned char* time);
int maxFrameLength(unsigned char* frame_len);
int linkLayerHeaderType(unsigned char* llht);
long long readStuff(FILE* file, size_t size);
long long readTimeStamp(FILE* file);
long long readMicrosecs(FILE* file);
long long readFrameSize(FILE* file);
unsigned char* readBytes(FILE* file, size_t size);
unsigned char* readMACAddress(FILE* file);
int readType(FILE* file);
unsigned char* readData(FILE* file, size_t size);
int skipCRC(FILE* file);
void printFrame(frame_t* frame);
void print2ndLayer(parser_t* parser);
int parse(parser_t* parser, char* filename);  //filename must be correct C string





#endif // PARSER_H
