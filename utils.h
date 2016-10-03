#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

unsigned int arrayToUInt(unsigned char* buffer, int size);
char* headerTypeName(int header_type_num);
size_t getline(char **lineptr, size_t *n, FILE *stream);
void printTime(time_t time);

#endif // UTILS_H
