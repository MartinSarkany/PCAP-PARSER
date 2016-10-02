#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned int arrayToUInt(unsigned char* buffer, int size);
char* headerTypeName(int header_type_num);

#endif // UTILS_H
