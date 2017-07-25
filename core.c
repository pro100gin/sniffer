#include "../include/core.h"

void list_net_devs() {
	int rtn = 0;
	pcap_if_t *net_devs_list = NULL, *cur_dev = NULL;
	pcap_addr_t* dev_addr = NULL;
	char err_buf[PCAP_ERRBUF_SIZE];

	rtn = pcap_findalldevs(&net_devs_list, err_buf);
	if (rtn == -1) {
		printf(stderr, "pcap_findalldevs failed: couldn't get all network devices: %s\n", err_buf);
		exit(EXIT_FAILURE);
	}

	printf("\nAvailable network devices list:\n");
	printf("+----------+--------------------------------------------------+------------------+\n");
	printf("| %-8s | %-48s | %-16s |\n", "Name", "Description", "Network address");
	printf("+----------+--------------------------------------------------+------------------+\n");

	cur_dev = net_devs_list;
	while(cur_dev) {
		printf("| %-8s | %-48s |", cur_dev->name, cur_dev->description ? cur_dev->description : "(no description)");

		dev_addr = cur_dev->addresses;
		while(dev_addr) {
			switch(dev_addr->addr->sa_family) {
				case AF_INET:
					printf(" %-16s |", inet_ntoa(((struct sockaddr_in*)dev_addr->addr)->sin_addr));
					break;

				case AF_INET6:
					break;

				default:
					break;
			}

			dev_addr = dev_addr->next;
		}

		printf("\n+----------+--------------------------------------------------+------------------+\n");
		cur_dev = cur_dev->next;
	}

	if (net_devs_list)
		pcap_freealldevs(net_devs_list);
}

void pckt_hndl(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
	int size = 0, tcp = 0, udp = 0, icmp = 0, others = 0, igmp = 0, total = 0;
	struct iphdr *iph = NULL;

	size = header->len;
	iph = (struct iphdr*)(packet + sizeof(struct ethhdr));

	++total;

	switch(iph->protocol) {
		/* ICMP Protocol */
		case 1:
			++icmp;
			print_icmp_packet(packet, size);
			break;

		/* IGMP Protocol */
		case 2:
			++igmp;
			break;

		/* TCP Protocol */
		case 6:
			++tcp;
			print_tcp_packet(packet, size);
			break;

		/* UDP Protocol */
		case 17:
			++udp;
			print_udp_packet(packet, size);
			break;

		/* Some Other Protocol like ARP etc. */
		default:
			++others;
			break;
	}

	printf("\nStatistics: TCP: %d UDP: %d ICMP: %d IGMP: %d Others: %d Total: %d\n", tcp, udp, icmp, igmp, others, total);
}

void print_ethernet_header(const u_char* frame, int size) {
	struct ethhdr *eth = NULL;
	eth = (struct ethhdr *)frame;

	printf("\n");
	printf("Ethernet Header\n");
	printf("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	printf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	printf("   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

void print_ip_header(const u_char* packet, int size) {
	unsigned short iphdrlen = 0;
	struct iphdr *iph = NULL;
	struct sockaddr_in source, dest;

	iph = (struct iphdr *)(packet + sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;

	print_ethernet_header(packet, size);

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	printf("\n");
	printf("IP Header\n");
	printf("   |-IP Version        : %d\n", (unsigned int)iph->version);
	printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n", (unsigned int)iph->ihl, ((unsigned int)(iph->ihl)) * 4);
	printf("   |-Type Of Service   : %d\n", (unsigned int)iph->tos);
	printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n", ntohs(iph->tot_len));
	printf("   |-Identification    : %d\n", ntohs(iph->id));
	/*printf("   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);*/
	/*printf("   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);*/
	/*printf("   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);*/
	printf("   |-TTL               : %d\n", (unsigned int)iph->ttl);
	printf("   |-Protocol          : %d\n", (unsigned int)iph->protocol);
	printf("   |-Checksum          : %d\n", ntohs(iph->check));
	printf("   |-Source IP         : %s\n", inet_ntoa(source.sin_addr));
	printf("   |-Destination IP    : %s\n", inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(const u_char* packet, int size) {
	unsigned short iphdrlen = 0;
	struct iphdr *iph = NULL;
	struct tcphdr *tcph = NULL;
	int header_size = 0;

	iph = (struct iphdr *)( packet  + sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	tcph =  (struct tcphdr*)(packet + iphdrlen + sizeof(struct ethhdr));
	header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

	printf("\n\n***********************TCP Packet*************************\n");

	print_ip_header(packet, size);

	printf("\n");
	printf("TCP Header\n");
	printf("   |-Source Port          : %u\n", ntohs(tcph->source));
	printf("   |-Destination Port     : %u\n", ntohs(tcph->dest));
	printf("   |-Sequence Number      : %u\n", ntohl(tcph->seq));
	printf("   |-Acknowledge Number   : %u\n", ntohl(tcph->ack_seq));
	printf("   |-Header Length        : %d DWORDS or %d BYTES\n", (unsigned int)tcph->doff, (unsigned int)tcph->doff*4);
	/*printf("   |-CWR Flag : %d\n", (unsigned int)tcph->cwr);*/
	/*printf("   |-ECN Flag : %d\n", (unsigned int)tcph->ece);*/
	printf("   |-Urgent Flag          : %d\n", (unsigned int)tcph->urg);
	printf("   |-Acknowledgement Flag : %d\n", (unsigned int)tcph->ack);
	printf("   |-Push Flag            : %d\n", (unsigned int)tcph->psh);
	printf("   |-Reset Flag           : %d\n", (unsigned int)tcph->rst);
	printf("   |-Synchronise Flag     : %d\n", (unsigned int)tcph->syn);
	printf("   |-Finish Flag          : %d\n", (unsigned int)tcph->fin);
	printf("   |-Window               : %d\n", ntohs(tcph->window));
	printf("   |-Checksum             : %d\n", ntohs(tcph->check));
	printf("   |-Urgent Pointer       : %d\n", tcph->urg_ptr);
	printf("\n");
	printf("                        DATA Dump                         ");
	printf("\n");

	printf("IP Header\n");
	print_data(packet, iphdrlen);

	printf("TCP Header\n");
	print_data(packet+iphdrlen, tcph->doff*4);

	printf("Data Payload\n");
	print_data(packet + header_size , size - header_size);

	printf("\n###########################################################");
}

void print_udp_packet(const u_char* packet, int size) {
	unsigned short iphdrlen = 0;
	struct iphdr *iph = NULL;
	struct udphdr *udph = NULL;
	int header_size = 0;

	iph = (struct iphdr *)(packet +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;

	udph = (struct udphdr*)(packet + iphdrlen + sizeof(struct ethhdr));

	header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udph;

	printf("\n\n***********************UDP Packet*************************\n");

	print_ip_header(packet, size);

	printf("\nUDP Header\n");
	printf("   |-Source Port      : %d\n", ntohs(udph->source));
	printf("   |-Destination Port : %d\n", ntohs(udph->dest));
	printf("   |-UDP Length       : %d\n", ntohs(udph->len));
	printf("   |-UDP Checksum     : %d\n", ntohs(udph->check));

	printf("\n");
	printf("IP Header\n");
	print_data(packet, iphdrlen);

	printf("UDP Header\n");
	print_data(packet+iphdrlen, sizeof udph);

	printf("Data Payload\n");

	print_data(packet + header_size, size - header_size);

	printf("\n###########################################################");
}

void print_icmp_packet(const u_char* packet, int size) {
	unsigned short iphdrlen;
	struct iphdr *iph = NULL;
	struct icmphdr *icmph = NULL;
	int header_size = 0;

	iph = (struct iphdr *)(packet  + sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;

	icmph = (struct icmphdr *)(packet + iphdrlen + sizeof(struct ethhdr));

	header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

	printf("\n\n***********************ICMP Packet*************************\n");

	print_ip_header(packet, size);

	printf("\n");

	printf("ICMP Header\n");
	printf("   |-Type : %d", (unsigned int)(icmph->type));

	if((unsigned int)(icmph->type) == 11) {
		printf("  (TTL Expired)\n");
	}
	else
		if((unsigned int)(icmph->type) == ICMP_ECHOREPLY) {
			printf("  (ICMP Echo Reply)\n");
		}

	printf("   |-Code : %d\n", (unsigned int)(icmph->code));
	printf("   |-Checksum : %d\n", ntohs(icmph->checksum));
	/*printf("   |-ID       : %d\n",ntohs(icmph->id));*/
	/*printf("   |-Sequence : %d\n",ntohs(icmph->sequence));*/
	printf("\n");

	printf("IP Header\n");
	print_data(packet, iphdrlen);

	printf("UDP Header\n");
	print_data(packet + iphdrlen, sizeof icmph);

	printf("Data Payload\n");

	print_data(packet + header_size, size - header_size);

	printf("\n###########################################################");
}

void print_data(const u_char* data, int size) {
	int i = 0, j = 0;

	for(i = 0; i < size; i++) {
		if(i != 0 && i%16 == 0) {
			printf("         ");

			for(j=i-16 ; j<i ; j++) {
				if(data[j]>=32 && data[j]<=128)
					printf("%c", (unsigned char)data[j]);
				else
					printf(".");
			}

			printf("\n");
		}

		if(i%16 == 0)
			printf("   ");

		printf(" %02X",(unsigned int)data[i]);

		if(i == size-1) {
			for(j = 0; j < 15 - i%16; j++) {
				printf("   ");
			}

			printf("         ");

			for(j = i - i%16; j <= i ; j++) {
				if(data[j]>=32 && data[j]<=128) {
					printf("%c",(unsigned char)data[j]);
				}
				else {
					printf(".");
				}
			}

			printf( "\n" );
		}
	}
}
