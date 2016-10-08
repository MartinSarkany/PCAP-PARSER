/*This file has routines to process UDP Packets*/

typedef unsigned char BOOL;
typedef unsigned short u16;
typedef unsigned int u32; //as int is 32 bits on this platform

/*Calculates UDP Checksum and returns the sum*/
u16 UDP_Checksum(u16 len_udp, u16 src_addr[],u16 dest_addr[], BOOL padding, u16 buff[])
{
  u16 prot_udp=17;
  u16 padd=0;
  u16 word16;
  u32 sum;
  int i;

  /* Find out if the length of data is even or odd n
   * umber. If odd,
   add a padding byte = 0 at the end of packet*/

  if ( (padding & 1 ) == 1 ) {

    padd=1;
    buff[len_udp]=0;

  }

  //initialize sum to zero
  sum=0;

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


// ////////////////////////////////////////////////////////


