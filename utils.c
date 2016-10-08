#include "utils.h"

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

#ifdef _WIN32
size_t getline(char **lineptr, size_t *n, FILE *stream) {   //stolen from stackoverflow.com
    char *bufptr = NULL;
    char *p = bufptr;
    size_t size;
    int c;

    if (lineptr == NULL) {
        return -1;
    }
    if (stream == NULL) {
        return -1;
    }
    if (n == NULL) {
        return -1;
    }
    bufptr = *lineptr;
    size = *n;

    c = fgetc(stream);
    if (c == EOF) {
        return -1;
    }
    if (bufptr == NULL) {
        bufptr = malloc(128);
        if (bufptr == NULL) {
            return -1;
        }
        size = 128;
    }
    p = bufptr;
    while(c != EOF) {
        int s = size;
        if ((p - bufptr) > (s - 1)) {
            size = size + 128;
            bufptr = realloc(bufptr, size);
            if (bufptr == NULL) {
                return -1;
            }
        }
        *p++ = c;
        if (c == '\n') {
            break;
        }
        c = fgetc(stream);
    }

    *p++ = '\0';
    *lineptr = bufptr;
    *n = size;

    return p - bufptr - 1;
}
#endif


char* headerTypeName(int header_type_num){ //header_types.txt is shipped together with program so it must be correct
    FILE* types_file = fopen("../PCAP-PARSER/header_types.txt", "rt");
    if(!types_file){
        return NULL;
    }
    char* line = NULL;
    char* header_type_name;
    size_t len = 0;
    int header_num;
    do{
        len = getline(&line, &len, types_file);
        if(len == 0 || len == 1){
            return NULL;
        }
        int space_pos = strchr(line, ' ') - line;
        char h_num[space_pos+1];
        for(int i=0;i<space_pos;i++){
            h_num[i] = line[i];
        }
        h_num[space_pos] = 0;
        header_num = atoi(h_num);
        if(header_num != header_type_num){
            continue;
        }
        int name_len = strlen(line + space_pos) + 1;
        header_type_name = malloc((name_len + 1) * sizeof(char));
        strcpy(header_type_name, line + space_pos + 1);
        free(line);
    }while(header_num != header_type_num);

    fclose(types_file);

    return header_type_name;
}

void printTime(time_t time){
    printf("Capture time: %s", ctime(&time));
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
    printf("IP: %u.%u.%u.%u\n", addr[0], addr[1], addr[2], addr[3]);
}


