#ifndef UDP_H
#define UDP_H



/* UDP Header*/
typedef struct UDP_Header{
    unsigned char sport;          // Source port number
    unsigned char dport;          // Destination port #
    unsigned char len;            // Datagram length
    unsigned char crc;            // Checksum
}UDP_Header;

void Read_UDP_Header(Byte *data, int UDP_Length);

unsigned short CheckSum(unsigned short *buffer, int length);


#endif // UDP_H
