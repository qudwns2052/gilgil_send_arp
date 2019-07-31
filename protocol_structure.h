#ifndef PROTOCAL_STRUCTURE_H
#define PROTOCAL_STRUCTURE_H

#endif // PROTOCAL_STRUCTURE_H

#include <stdint.h>

/* ETHERNET header */
typedef struct eth_header
{
    uint8_t  dmac[6];
    uint8_t  smac[6];
    uint16_t type;
}ETH_header;

/* ARP header */
typedef struct arp_header
{
    uint16_t htype;          /* Hardware Type           */
    uint16_t ptype;         /* Protocol Type           */
    uint8_t hlen;           /* Hardware Address Length */
    uint8_t plen;           /* Protocol Address Length */
    uint16_t oper;          /* Operation Code          */
    uint8_t smac[6];        /* Sender hardware address */
    uint8_t sip[4];         /* Sender IP address       */
    uint8_t dmac[6];        /* Target hardware address */
    uint8_t dip[4];         /* Target IP address       */
}ARP_header;
