#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define IPV4 1
#define ARP 2
#define IPV6 3
#define UNKNOWN -1

#ifdef _WIN32
size_t getline(char **lineptr, size_t *n, FILE *stream);
#endif

//little endian
unsigned int arrayToUInt(unsigned char* buffer, int size);
//big endian
unsigned int arrayToUIntBE(unsigned char* buffer, int size);
char* headerTypeName(int header_type_num);
void printTime(time_t time);
void printMACAddress(unsigned char* addr);
void printProtocol(int protocol);

void printIPAddress(unsigned char* addr);

#endif // UTILS_H
