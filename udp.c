#include <netinet/in.h>
#include <arpa/inet.h>

#include "parser.h"
#include "udp.h"

/*This file has routines to process UDP Packets*/

typedef unsigned char BOOL;
typedef unsigned short u16;
typedef unsigned int u32; //as int is 32 bits on this platform

/*for the statistics of UDP datagrams*/
struct udp_stats {
  int totalDatagrams;
  int minDataSize;
  int maxDataSize;
  int corruptDatagrams;
};

struct udp_stats udp_stats;

/*Calculates UDP Checksum and returns the sum*/
u16 UDP_Checksum(u16 len_udp, u16 src_addr[],u16 dest_addr[], BOOL padding, u16 buff[])
{
  u16 prot_udp=17;
  u16 padd=0;
  u16 word16;
  u32 sum=0;
  int i;

  /* Find out if the length of data is even or odd n
   * umber. If odd, add a padding byte = 0 at the end of packet*/

  if ( (padding & 1 ) == 1 ) {

    padd=1;
    buff[len_udp]=0;

  }

  /* make 16 bit words out of every two adjacent 8 bit words and
   calculate the sum of all 16 vit words */

  for (i=0; i<len_udp+padd ;i=i+2){

    word16 = ((buff[i]<<8)&0xFF00) + (buff[i+1]&0xFF);
    sum = sum + (unsigned long)word16;

  }

  // add the UDP pseudo header which contains the IP source and destinationn addresses
  for (i=0;i<4;i=i+2){

    word16 =((src_addr[i]<<8)&0xFF00)+(src_addr[i+1]&0xFF);
    sum=sum+word16;

  }

  for (i=0;i<4;i=i+2){

    word16 =((dest_addr[i]<<8)&0xFF00)+(dest_addr[i+1]&0xFF);
    sum=sum+word16;

  }
  // the protocol number and the length of the UDP packet
  sum = sum + prot_udp + len_udp;

  // keep only the last 16 bits of the 32 bit calculated sum and add the carries
  while (sum>>16)
    sum = (sum & 0xFFFF)+(sum >> 16);

  // Take the one's complement of sum
  sum = ~sum;

  return ((u16) sum);
}

datagram_t* createDatagram(int src_port, int dst_port, int data_size, packet_t* packet){
    datagram_t* datagram = malloc(sizeof(datagram_t));
    datagram->next = NULL;

    datagram->data_size = data_size;
    datagram->src_port = src_port;
    datagram->dst_port = dst_port;
    datagram->packet = packet;

    return datagram;
}

datagram_t* addDatagram(datagram_t** datagram_list_p, datagram_t* new_datagram){
    if(!(*datagram_list_p)){
        *datagram_list_p = new_datagram;
        return new_datagram;
    }

    datagram_t* current_datagram = *datagram_list_p;
    while(current_datagram->next != NULL){
        current_datagram = current_datagram->next;
    }
    current_datagram->next = new_datagram;

    return new_datagram;
}

int extractPort(unsigned char* buff){
    return arrayToUIntBE(buff, 2);
}

int extractChecksum(unsigned char* buff){
    return arrayToUIntBE(buff, 2);
}


void initUDPStats() {
  udp_stats.totalDatagrams = 0;
  udp_stats.maxDataSize = 0;
  udp_stats.minDataSize = 0;
  udp_stats.corruptDatagrams = 0;
}

void updateMinMaxStats(int data_len) {
  if(data_len > udp_stats.maxDataSize) {
    udp_stats.maxDataSize = data_len;
  }
  if(data_len < udp_stats.minDataSize) {
    udp_stats.minDataSize = data_len;
  }
}

void printUDPStats() {
  printf("\n------------------UDP Stats----------------------\n");
  printf("Total number of UDP datagrams: %d\n", udp_stats.totalDatagrams);
  printf("Total number of corrupt UDP datagrams: %d\n", udp_stats.corruptDatagrams);
  printf("Minimum data size of UDP datagrams: %d\n", udp_stats.minDataSize);
  printf("Maximum data size of UDP datagrams: %d\n", udp_stats.maxDataSize);
  printf("\n------------------UDP Stats----------------------\n");
}

int process_packets(packet_t* packet_list, datagram_t** datagram_list_p){
    if(!packet_list){
        return NOK;
    }

    initUDPStats();
    packet_t* cur_packet = packet_list;

    do{
        // Collect stats for total number of datagram parsed
        udp_stats.totalDatagrams++;
        if(cur_packet->data_size < 8){
            printf("Corrupted datagram");
            cur_packet = cur_packet->next;
            // Collect stats for corrupt datagrams
            udp_stats.corruptDatagrams++;
            continue;
        }

        unsigned char* data = cur_packet->data; //just to shorten name

        int src_port = extractPort(data);
        int dst_port = extractPort(data + 2);

        int total_len = extractTotalLength(data + 4);
        int data_len = total_len - 8;
        /* Cross checking of the UDP checksum*/
        unsigned char EvenorOdd = data_len % 2;  //Even = 0  , Odd = 1  for padding
        u16 checked_sum;
        u16 checksum_datagram = extractTotalLength(data + 5);       // getting stored checksum

        checked_sum = UDP_Checksum((u16)total_len, (u16 *) data,(u16*) (data+2), EvenorOdd, (u16 *) (data+5));
        if(checked_sum != checksum_datagram)
        {
                udp_stats.corruptDatagrams++;
        }


        // Collect stats on min and max datagram size
        updateMinMaxStats(data_len);

        addDatagram(datagram_list_p, createDatagram(src_port, dst_port, data_len, cur_packet));

        cur_packet = cur_packet->next;
    }while(cur_packet != NULL);

    return OK;
}
