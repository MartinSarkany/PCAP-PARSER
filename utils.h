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

unsigned int arrayToUInt(unsigned char* buffer, int size);
char* headerTypeName(int header_type_num);
void printTime(time_t time);
void printMACAddress(unsigned char* addr);
void printProtocol(int protocol);

#endif // UTILS_H
