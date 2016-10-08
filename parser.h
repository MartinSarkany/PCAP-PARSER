#ifndef PARSER_H
#define PARSER_H

#include <stdio.h>
#include "eth_frame.h"
#include "ipv4.h"
#include "udp.h"

#define OK 1
#define NOK 0

// parser structure, lists of frames, packets and datagrams
typedef struct{
    // only frames containing IPv4 traffic are added
    frame_t* frame_list;
    // only packets containing UDP datagrams are added
    packet_t* packet_list;
    datagram_t* datagram_list;
} parser_t;

// sets lists to NULL
void initParser(parser_t* parser);
// reads *size* of bytes and converts them to long long int or returns -1 if impossible.
// max length is 7 bytes (because of -1 error)
long long readStuff(FILE* file, size_t size);
// reads *size* of bytes and returns buffer with read bytes or NULL if unable to read
unsigned char* readBytes(FILE* file, size_t size);
// read first 4 bytes - "Magic number" d4 c3 b2 a1
int checkMagicNumber(FILE* file);
// prints time when the packet was captured
int printTimeStuff(FILE* file);
// extracts type of layer 2 protocol - we only parse ethernet (inlucing IEEE 802.11
// stored as ethernet)
int linkLayerHeaderType(FILE* file);
// maximum length of captured packets (larger packets are cut)
int maxFrameLength(FILE* file);
// reads time stamp
long long readTimeStamp(FILE* file);
// reads microseconds part of time stamp
long long readMicrosecs(FILE* file);
// reads size of the frame
long long readFrameSize(FILE* file);
// reads MAC address
unsigned char* readMACAddress(FILE* file);
// reads type of the layer 3 protocol
int readType(FILE* file);
// reads comtent of the frame
unsigned char* readData(FILE* file, size_t size);
// reads and discards CRC (not checking, 0 *argh* are given)
int skipCRC(FILE* file);
// prints frame details (debugging only)
void printFrame(frame_t* frame);
// prints details of all frames (debugging only)
void print2ndLayer(parser_t* parser);
// prints packet details (debugging only)
void printPacket(packet_t* packet);
// prints details of all packets (debugging only)
void print3rdLayer(parser_t* parser);
// prints datagram details
void printDatagram(datagram_t* datagram);
// prints details of all datagrams
void print4thLayer(parser_t* parser);
// returns number of datagrams in list
long long numDatagrams(parser_t* parser);
// parses whole file, prints file (global) header and stores frames in list
int parse(parser_t* parser, char* filename);  //filename must be correct C string





#endif // PARSER_H
