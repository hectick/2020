#ifndef PACKET_STRUCTURE_H
#define PACKET_STRUCTURE_H

#endif // PACKET_STRUCTURE_H

#include <stdint.h>

#pragma pack(push, 1)
typedef struct ethernet
{
    uint8_t dmac[6];            //destination MAC(6bytes)
    uint8_t smac[6];            //Source MAC(6bytes)
    uint16_t ethertype;         //Type(2bytes)
}Ethernet;

typedef struct ip
{
    uint8_t ver:4, hlen:4;                //version(4bits)
                                          //Header Length(4bits)

    uint8_t type_SF;            //Type of Service Flags(1byte)
    uint16_t total_length;            //Total Packet Length(2bytes)
    uint16_t Frag_id;            //Fragment identifier(2bytes)

    uint16_t Frag_flags:3, Frag_Offset:13;            //Fragmentation Flags(3bits)
                                                      //Fragmentation Offset(13bits)

    uint8_t TTL;            //Time to live(1byte)
    uint8_t protocol;           //Protocol(1byte)
    uint16_t header_checksum;            //Header Checksum(2bytes)
    uint8_t sip[4];           //Source IP Address(4bytes)
    uint8_t dip[4];           //Destination IP Address(4bytes)
}IP;

typedef struct tcp
{
    uint16_t sport;             //Source Port(2bytes)
    uint16_t dport;             //Destination Port(2bytes)
    uint32_t seq_num;            //Sequence Number(4bytes)
    uint32_t ack_num;            //Acknowledgement Number(4bytes)

    uint16_t header_len:4, reserved:6, control_flags:6;           //Header Length(4bits)
                                                                 //Reserved(6bits)
                                                                //Control Flags(6bits)

    uint16_t windowsize;            //Window Size(2bytes)
    uint16_t checksum;            //Checksum(2bytes)
    uint16_t urg_pointer;            //Urgent Pointer(2bytes)
}TCP;
#pragma pack(pop)

