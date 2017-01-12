#include "utils.h"

#ifdef WIN32
void printLongLong(long long n){
    printf("%I64d", n);
}
#else
void printLongLong(long long n){
    printf("%lld", n);
}
#endif

unsigned int arrayToUInt(unsigned char* buffer, int size){
    unsigned int value = 0;
    for(int i = size - 1;i>=0;i--){
        value = value << 8;
        value += buffer[i];
    }

    return value;
}

unsigned int arrayToUIntBE(unsigned char* buffer, int size){
    unsigned int value = 0;
    for(int i = 0;i<size;i++){
        value = value << 8;
        value += buffer[i];
    }

    return value;
}

void printVersionNumber(unsigned char* ver_num){
    unsigned int majVer = ver_num[1] * 255 + ver_num[0];
    unsigned int minVer = ver_num[3] * 255 + ver_num[2];
    printf("Version: %u.%u\n", majVer, minVer);
}

void printTime(time_t time){
    printf("Capture time:     %s", ctime(&time));
}

void printMACAddress(unsigned char* addr){
    printf("%02x", addr[0]);
    for(int i=1;i<6;i++){
        printf(":%02x", addr[i]);
    }
    printf("\n");
}

void printProtocol(int protocol){
    printf("Protocol: ");
    switch(protocol){
    case IPV4: printf("IPv4\n"); break;
    case ARP: printf("ARP\n"); break;
    case IPV6: printf("IPv6"); break;
    default: printf("unknown"); break;
    }
}

void printIPAddress(unsigned char* addr){
    printf("%u.%u.%u.%u\n", addr[0], addr[1], addr[2], addr[3]);
}


