/**
 * @file pcap-test.cpp
 * @author pingu52 (gudrbs9852@gmail.com)
 * @brief 
 * @version 0.1
 * @date 2023-04-27
 * 
 * @copyright Copyright (c) 2023
 * 
 */

#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

void usage(){
    printf("syntex: pcap-test <interface>\n");
    printf("sample: pcap-test en0\n");
}

// typedef struct {
// 	char* dev_;
// } Param;

/**
 * @brief 
 * libnet-headers.h 안에 있는 본 과제와 직접적으로 관련된 구조체들 :
 * struct libnet_ethernet_hdr (479 line)
 * struct libnet_ipv4_hdr (647 line)
 * struct libnet_tcp_hdr (1519 line)
 * 
 */


/*
 *  Ethernet II header
 *  Static header size: 14 bytes
 */
typedef struct libnet_gre_hdr{
    u_int8_t  ether_dhost[6];/* destination ethernet address */
    u_int8_t  ether_shost[6];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
} EthHeader;
/*
 *  IPv4 header
 *  Internet Protocol, version 4
 *  Static header size: 20 bytes
 */
typedef struct libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    u_int8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
#endif
    u_int8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
}IPHeader;
/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
typedef struct libnet_tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
#if (LIBNET_LIL_ENDIAN)
    u_int8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */
#endif
#if (LIBNET_BIG_ENDIAN)
    u_int8_t th_off:4,        /* data offset */
           th_x2:4;         /* (unused) */
#endif
    u_int8_t  th_flags;       /* control flags */
#ifndef TH_FIN
#define TH_FIN    0x01      /* finished send data */
#endif
#ifndef TH_SYN
#define TH_SYN    0x02      /* synchronize sequence numbers */
#endif
#ifndef TH_RST
#define TH_RST    0x04      /* reset the connection */
#endif
#ifndef TH_PUSH
#define TH_PUSH   0x08      /* push data to the app layer */
#endif
#ifndef TH_ACK
#define TH_ACK    0x10      /* acknowledge */
#endif
#ifndef TH_URG
#define TH_URG    0x20      /* urgent! */
#endif
#ifndef TH_ECE
#define TH_ECE    0x40
#endif
#ifndef TH_CWR   
#define TH_CWR    0x80
#endif
    u_int16_t th_win;         /* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
}TCPHeader;
typedef struct Data{
    u_int8_t Data[10]; 
}Data;


int main(int argc, char* argv[]){
    if(argc != 2){
        usage();
        return -1;
    }
    
    char* dev = argv[1];
    struct pcap_pkthdr* header;
    const u_char* packet;
    char errbuf[PCAP_ERRBUF_SIZE];
    IPHeader *tlen; 
    u_int length;
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s \n",dev, errbuf);
        return -1;
    }
    


    while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
        EthHeader *ethHeader;
        IPHeader *ipHeader;
        TCPHeader *tcpHeader;
        Data *data;

        ethHeader = (EthHeader *)packet;

        const u_char* ippacket = 14 + packet;
        ipHeader = (IPHeader *)ippacket;
        
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        if(ipHeader->ip_p == 0x06){
            puts("===========================================");
            puts("Destination MAC");
            for(int i=0; i<6; i++){
                printf("%02x ",ethHeader->ether_dhost[i]);
            }
            puts("\nSource MAC");
            for(int i=0; i<6; i++){
                printf("%02x ",ethHeader->ether_shost[i]);
            }
            puts("");
            printf("Source IP: %s\n",inet_ntoa(ipHeader->ip_src));
            printf("Destination IP: %s\n",inet_ntoa(ipHeader->ip_dst));
            ippacket = 16+ packet;
            ipHeader = (IPHeader *)ippacket;

        }
        
	}
    
	pcap_close(pcap);


    
}