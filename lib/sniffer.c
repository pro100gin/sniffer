#include "../include/snif.h"

struct pseudo_header{
   unsigned int src, dest;
   unsigned char reserved;
   unsigned char protocol;
   unsigned short size;
}__attribute__((packed));

unsigned short compute_checksum(unsigned short *addr, unsigned int count) {
	unsigned long sum = 0;

	while (count > 1) {
		sum += *addr++;
		count -= 2;
	}

	if(count > 0) {
		sum += ((*addr)&htons(0xFF00));
	}

	while (sum>>16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	sum = ~sum;
	return ((unsigned short)sum);
}

void process_packet(unsigned char *args, const struct pcap_pkthdr *header,
						 const unsigned char *buffer){
	int size = header->len;

	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	switch (iph->protocol){
		case 1:  /*ICMP Protocol*/
			print_icmp_packet(buffer, size);
			break;

		case 6:  /*TCP Protocol*/
			print_tcp_packet(buffer, size);
			break;

		case 17: /*UDP Protocol*/
			print_udp_packet(buffer, size);
			break;

		default: /*Some Other Protocol like ARP etc.*/
			break;
	}
}
void print_ethernet_header(const unsigned char *Buffer, int Size){
	struct ethhdr *eth = (struct ethhdr *)Buffer;

	printf("\n");
	printf("Ethernet Header\n");
	printf("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
		 eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
		 eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	printf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",
		 eth->h_source[0], eth->h_source[1], eth->h_source[2],
		 eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	printf("   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

void print_ip_header(const unsigned char * Buffer, int Size){
	struct sockaddr_in source, dest;

	unsigned short iphdrlen = 0, tmp_checksum = 0;

	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));

	print_ethernet_header(Buffer, Size);

	iphdrlen = iph->ihl*4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	tmp_checksum = ntohs(iph->check);
	iph->check = 0;
	iph->check = compute_checksum((unsigned short*)iph, iph->ihl<<2);

	printf("\nOld IP checksum : %d, my IP checksum : %d\n", tmp_checksum,
							ntohs(iph->check));
	printf("\n");
	printf("IP Header\n");
	printf("   |-IP Version        : %d\n",(unsigned int)iph->version);
	printf("   |-IP Header Length  : %d DWORDS or %d Bytes\n",
			(unsigned int)iph->ihl,((unsigned int)iphdrlen));
	printf("   |-IP Total Length   : %d  Bytes(Size of Packet)\n",
							ntohs(iph->tot_len));
	printf("   |-TTL               : %d\n",(unsigned int)iph->ttl);
	printf("   |-Protocol          : %d\n",(unsigned int)iph->protocol);
	printf("   |-Checksum          : %d\n", ntohs(iph->check));
	printf("   |-Source IP         : %s\n", inet_ntoa(source.sin_addr));
	printf("   |-Destination IP    : %s\n", inet_ntoa(dest.sin_addr));
}

void print_data (const unsigned char * data , int Size){
	int i = 0, j = 0;
	for(i = 0 ; i < Size ; i++){
		if(i!=0 && i%16==0){
			printf("         ");
			for(j=i-16 ; j<i ; j++){
				if(data[j]>=32 && data[j]<=128){
					printf("%c",(unsigned char)data[j]);
				}
				else{
					printf(".");
				}
			}
			printf("\n");
		}

		if(i%16 == 0){
			 printf("   ");
		}
		printf(" %02X",(unsigned int)data[i]);

		if(i == Size - 1){
			for(j = 0; j < 15 - i%16; j++){
				printf("   ");
			}

			printf("         ");

			for(j=i-i%16 ; j<=i ; j++){
				if(data[j]>=32 && data[j]<=128){
					printf("%c",
						(unsigned char)data[j]);
				}
				else{
					printf(".");
				}
			}

			printf("\n" );
		}
	}
}


void print_tcp_packet(const u_char* packet, int size) {
	unsigned short iphdrlen = 0;
	struct iphdr *iph = NULL;
	struct pseudo_header *pseudo;
	struct tcphdr *tcph = NULL;
	int header_size = 0, tmp_checksum = 0, new_checksum = 0, tcp_packet_len= 0;
	unsigned char *tcp_packet;

	iph = (struct iphdr *)( packet  + sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;
	tcph =  (struct tcphdr*)(packet + iphdrlen + sizeof(struct ethhdr));
	header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
	pseudo  = malloc(sizeof (struct pseudo_header));
	tcp_packet_len = 12 + tcph->doff*4 + size - header_size;
	tcp_packet = malloc(tcp_packet_len);

	printf("\n\n***********************TCP Packet*************************\n");

	print_ip_header(packet, size);

	pseudo->src = iph->saddr;
	pseudo->dest = iph->daddr;
	pseudo->reserved = 0;
	pseudo->protocol = iph->protocol;
	pseudo->size = htons(ntohs(iph->tot_len) - iphdrlen);/* ???  */

	printf("Pseudo header size = %d\n", (int) sizeof(*pseudo));

	tmp_checksum = ntohs(tcph->check);
	tcph->check = 0;


	memcpy(tcp_packet, pseudo, 12);
	memcpy(tcp_packet + 12, tcph, tcph->doff*4);
	memcpy(tcp_packet + 12 + tcph->doff*4, packet + header_size,
							size - header_size);
	new_checksum = compute_checksum((unsigned short*)tcp_packet,
							    tcp_packet_len);

	printf("Old TCP checksum = %d, new TCP checksum = %d\n",
	tmp_checksum, ntohs(new_checksum));

	tcph->check = htons(tmp_checksum);

	printf("\n");
	printf("TCP Header\n");
	printf("   |-Source Port          : %u\n", ntohs(tcph->source));
	printf("   |-Destination Port     : %u\n", ntohs(tcph->dest));
	printf("   |-Sequence Number      : %u\n", ntohl(tcph->seq));
	printf("   |-Acknowledge Number   : %u\n", ntohl(tcph->ack_seq));
	printf("   |-Header Length        : %d DWORDS or %d BYTES\n",
		 (unsigned int)tcph->doff, (unsigned int)tcph->doff*4);
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

	printf("\n####################END_OF_PACKET##########################\n\n");
}

void print_udp_packet(const u_char* packet, int size) {
	unsigned short iphdrlen = 0;
	struct iphdr *iph = NULL;
	struct udphdr *udph = NULL;
	int header_size = 0, tmp_checksum = 0, new_checksum = 0, udp_packet_len= 0;
	struct pseudo_header *pseudo;
	unsigned char *udp_packet;

	iph = (struct iphdr *)(packet +  sizeof(struct ethhdr));
	iphdrlen = iph->ihl*4;

	udph = (struct udphdr*)(packet + iphdrlen + sizeof(struct ethhdr));

	header_size = sizeof(struct ethhdr) + iphdrlen + sizeof(udph);

	pseudo  = malloc(sizeof (struct pseudo_header));
	udp_packet_len = 12 + ntohs(udph->len);
	if(udp_packet_len & 1){
		printf("----------%d----------\n", udp_packet_len);
		udp_packet = malloc(udp_packet_len+1);
		udp_packet[udp_packet_len] = 0;
		udp_packet_len++;
	}
	else{
		udp_packet = malloc(udp_packet_len);
	}
	printf("\n\n***********************UDP Packet*************************\n");

	print_ip_header(packet, size);

	pseudo->src = iph->saddr;
	pseudo->dest = iph->daddr;
	pseudo->reserved = 0;
	pseudo->protocol = iph->protocol;
	pseudo->size = udph->len; /* ???  */

	printf("Pseudo header size = %d, len = %d\n", (int) sizeof(*pseudo),
						udp_packet_len );

	tmp_checksum = ntohs(udph->check);
	udph->check = 0;

	memcpy(udp_packet, pseudo, 12);
	memcpy(udp_packet + 12, udph, ntohs(udph->len));
	new_checksum = compute_checksum((unsigned short*)udp_packet,
							    udp_packet_len);

	printf("Old UDP checksum = %d, new UDP checksum = %d\n",
				tmp_checksum, ntohs(new_checksum));

	udph->check = htons(tmp_checksum);


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
	printf("\n####################END_OF_PACKET##########################\n\n");

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
	printf("\n");

	printf("IP Header\n");
	print_data(packet, iphdrlen);

	printf("UDP Header\n");
	print_data(packet + iphdrlen, sizeof icmph);

	printf("Data Payload\n");

	print_data(packet + header_size, size - header_size);
	printf("\n####################END_OF_PACKET##########################\n\n");

}

