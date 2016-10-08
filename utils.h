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
//stolen from stackoverflow.com, not defined on Windows
size_t getline(char **lineptr, size_t *n, FILE *stream);
#endif

// converts array of bytes to unsigned integer - little endian
unsigned int arrayToUInt(unsigned char* buffer, int size);
// converts array of bytes to unsigned integer - big endian
unsigned int arrayToUIntBE(unsigned char* buffer, int size);
// returns name for the given number of protocol
char* headerTypeName(int header_type_num);
// prints version number
void printVersionNumber(unsigned char* ver_num);
// prints time in human readable form
void printTime(time_t time);
// prints MAC address in hex form
void printMACAddress(unsigned char* addr);
// prints protocol name
void printProtocol(int protocol);
// prints IP address in IP notation
void printIPAddress(unsigned char* addr);

#endif // UTILS_H
