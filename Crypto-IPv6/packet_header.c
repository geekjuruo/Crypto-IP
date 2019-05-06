#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include "packet_header.h"

#define MAXBYTE2CAPTURE 2048

int isprint(char c)
{
    return 0;
}

void print_buf(u_char* pBuf, u_int32 len)
{
    if (!pBuf)
    {
        return;
    }

    for(int i=0; i<len; i++)
    {
        printf("%02x ",  (u_char*)pBuf[i]);

        if ((i%16 == 0 && i!=0) || i == len-1)
        {
            printf("\r\n");
        }
    }
}

void parse_ethII(u_char* pData, u_int32 len)
{
    if (!pData || len <14)
    {
        return;
    }

    printf("eth II frame: \r\n");
    print_buf(pData, 14);

    /* parse src mac and dst mac */
    EthHeader_t* pEth = (EthHeader_t*)pData;
    printf("destination: %02x:%02x:%02x:%02x:%02x:%02x ",
        pEth->dest_hwaddr[0],
        pEth->dest_hwaddr[1],
        pEth->dest_hwaddr[2],
        pEth->dest_hwaddr[3],
        pEth->dest_hwaddr[4],
        pEth->dest_hwaddr[5]);

    printf("source : %02x:%02x:%02x:%02x:%02x:%02x",
        pEth->source_hwaddr[0],
        pEth->source_hwaddr[1],
        pEth->source_hwaddr[2],
        pEth->source_hwaddr[3],
        pEth->source_hwaddr[4],
        pEth->source_hwaddr[5]);

    /* parse frame type */
    printf("\r\nframe type: 0x%x\r\n", ntohs(pEth->frame_type));
}


void parse_ipheader(u_char* pData, u_int32 len)
{
    if (!pData || len <14)
    {
        return;
    }

    printf("ip header: \r\n");
    print_buf(pData, 20);

    /* parse ip header */
    IPHeader_t* pIpHeader = (IPHeader_t*)pData;
    printf("\tversion     : %02x\r\n"
           "\ttos         : %02x\r\n"
           "\ttotal length: %d(0x%02x)\r\n"
           "\tid          : %d(0x%02x)\r\n"
           "\tsegment flag: %d(0x%02x)\r\n"
           "\tttl         : %02x\r\n"
           "\tprotocol    : %02x\r\n"
           "\tchecksum    : %d(0x%02x)\r\n"
           "\tsrc ip      : %d.%d.%d.%d\r\n"
           "\tdst ip      : %d.%d.%d.%d\r\n",
        pIpHeader->Ver_HLen,
        pIpHeader->TOS,
        ntohs(pIpHeader->TotalLen), ntohs(pIpHeader->TotalLen),
        ntohs(pIpHeader->ID), ntohs(pIpHeader->ID),
        ntohs(pIpHeader->Flag_Segment), ntohs(pIpHeader->Flag_Segment),
        pIpHeader->TTL,
        pIpHeader->Protocol,
        ntohs(pIpHeader->Checksum), ntohs(pIpHeader->Checksum),
        pIpHeader->SrcIP[0],pIpHeader->SrcIP[1],pIpHeader->SrcIP[2],pIpHeader->SrcIP[3],
        pIpHeader->DstIP[0],pIpHeader->DstIP[1],pIpHeader->DstIP[2],pIpHeader->DstIP[3]);
}

void parse_ip6header(u_char* pData, u_int32 len)
{
    if (!pData || len <14)
    {
        return;
    }

    printf("ipv6 header: \r\n");
    print_buf(pData, 40);

    /* parse ipv6 header */
    IPv6Header_t* pIpv6Header = (IPv6Header_t*)pData;
    printf("\tversion           : %x\r\n"
           "\ttraffic class     : %x\r\n"
           "\tflow label        : %x\r\n"
           "\tpayload length    : %x\r\n"
           "\tnext header       : %x\r\n"
           "\thop limit         : %x\r\n"
           "\tsource            : %x\r\n"
           "\tdestination       : %x\r\n",
           pIpv6Header->ip6_ctlun.ip6_un2_vfc,
           pIpv6Header->ip6_ctlun.ip6_unl.ip6_unl_flow,
           pIpv6Header->ip6_ctlun.ip6_unl.ip6_unl_flow,
           pIpv6Header->ip6_ctlun.ip6_unl.ip6_unl_plen,
           pIpv6Header->ip6_ctlun.ip6_unl.ip6_unl_nxt,
           pIpv6Header->ip6_ctlun.ip6_unl.ip6_unl_hlim,
           pIpv6Header->ip6_src,
           pIpv6Header->ip6_dst);
}


void parse_packet(const u_char* packet, u_int32 len)
{
    u_short ftype = 0;

    if (!packet)
    {
        return ;
    }

    u_char* pMbuf = (u_char*)packet;
    parse_ethII(pMbuf, len);

    ftype = ntohs(((EthHeader_t*)pMbuf)->frame_type);
    switch(ftype)
    {
        case 0x0800:  /* ipv4 */
            pMbuf = (u_char*)packet + 14;
            parse_ipheader(pMbuf, len-14);
            break;
        case 0x86dd: /* ipv6 */
            pMbuf = (u_char*)packet + 14;
            parse_ip6header(pMbuf, len-14);
            break;
        default:
            printf("frame type : 0x%x\r\n", ftype);
            break;
    }

    printf("\r\n");
}

void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    int i = 0, *counter = (int *)arg;

    printf("--------------------------------------------\r\n");
    printf("Packet Count: %d\n", ++(*counter));
    printf("Received Packet Size: %d\n", pkthdr->len);
    printf("Payload:\n");

#if 1
    for (i = 0; i < pkthdr->len; i++)
    {
        if (isprint(packet[i]))
        {
            printf("%02d ", packet[i]);
        }
        else
        {
            printf("%02x ", packet[i]);
        }

        if ((i % 16 == 0 && i != 0) || i == pkthdr->len-1)
        {
            printf("\n");
        }

    }
#endif

    parse_packet(packet, pkthdr->len);

    return;
}

int main()
{

    int i = 0, count = 0;
    pcap_t *descr = NULL;
    char errbuf[PCAP_ERRBUF_SIZE], *device = NULL;
    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    /* Get the name of the first device suitable for capture */
    device = pcap_lookupdev(errbuf);
    if (!device)
    {
        printf("Open device failed.");
        return -1;
    }

    printf("Opening device %s\n", device);

    /* Open device in promiscuous mode */
    descr = pcap_open_live(device, MAXBYTE2CAPTURE, 1, 512, errbuf);

    
    /* Loop forever & call processPacket() for every received packet */
    pcap_loop(descr, -1, processPacket, (u_char *)&count);

    return 0;
}