#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include "libnet.h"

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {

    //오류 산출하는 함수
    if (argc != 2) {
        usage();
        return -1;
    }

    char* interface = argv[1]; //1번째 인덱스를 interface에 넣고

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    if (pcap == NULL) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;

        struct libnet_ethernet_hdr *ethernet;
        struct libnet_ipv4_hdr *ipv4;
        struct libnet_tcp_hdr *tcp;
        struct gardata *Data;
        const u_char* packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }
        
        printf("%u bytes captured\n", header->caplen);

        ethernet =(struct libnet_ethernet_hdr *)packet;
        ipv4 = (struct libnet_ipv4_hdr *)(packet+sizeof(struct libnet_ethernet_hdr));
        tcp = (struct libnet_tcp_hdr *)(packet+sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_ipv4_hdr));
        Data = (struct gardata *)(packet+sizeof(struct libnet_ethernet_hdr)+sizeof(struct libnet_ipv4_hdr)+4);

        //ethernet
        puts("\t>ethernet");
        printf("\t\tsource address : ");
        for (int i = 0; i < ETHER_ADDR_LEN; i++)
        {
            if(i!=0) printf(":");
            printf("%02X", ethernet->ether_shost[i]);
        }

        printf("\tdestination address : ");
        for (int i = 0; i < ETHER_ADDR_LEN; i++)
        {
            if(i!=0) printf(":");
            printf("%02X", ethernet->ether_dhost[i]);\
        }
        puts("");

        //ipv4
        puts("\t>ipv4");
        printf("\t\tsource ip: ");
        u_int32_t sip = ntohl(ipv4->ip_src);
        printf("%d.", (sip &0xff000000)>>24);
        printf("%d.", (sip &0xff0000)>>16);
        printf("%d.", (sip &0xff00)>>8);
        printf("%d", sip &0xff);

        printf("\t\tdestination ip : ");
        u_int32_t dip = ntohl(ipv4->ip_dst);
        printf("%d.", (dip &0xff000000)>>24);
        printf("%d.", (dip &0xff0000)>>16);
        printf("%d.", (dip &0xff00)>>8);
        printf("%d", dip &0xff);
        puts("");

        //tcp
        puts("\t>tcp");
        printf("\t\tsouce port : %d",ntohs(tcp->th_sport));
        printf("\t\t\tdestination port : %d\n",ntohs(tcp->th_dport));

        //data
        puts("\t>data");
        printf("\t\tdata :");
        for(int i=0;i<8;i++){
            if(i!=0) printf(" ");
            printf("%02X",Data->wow[i]);
        }
        puts("");
    }
    pcap_close(pcap);

}
