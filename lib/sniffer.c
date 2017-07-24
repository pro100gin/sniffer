#include "../include/snif.h"


/* set ip checksum of a given ip header*/
void compute_ip_checksum(struct iphdr* iphdrp){
	iphdrp->check = 0;
	iphdrp->check =  compute_checksum((unsigned short*)iphdrp, iphdrp->ihl<<2);
}

unsigned short compute_checksum(unsigned short *addr, unsigned int count) {
	register unsigned long sum = 0;
	while (count > 1) {
		sum += *addr++;
		count -= 2;
	}
	/*if any bytes left, pad the bytes and add*/
	if(count > 0) {
		sum += ((*addr)&htons(0xFF00));
	}
	/*Fold sum to 16 bits: add carrier to result*/
	while (sum>>16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}
	/*one's complement*/
	sum = ~sum;
	return ((unsigned short)sum);
}

void process_packet(unsigned char *args, const struct pcap_pkthdr *header,
						 const unsigned char *buffer){
	int size = header->len;

	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	switch (iph->protocol){
		case 1:  /*ICMP Protocol*/
			/*print_icmp_packet(buffer, size);*/
			break;

		case 6:  /*TCP Protocol*/
			/*print_tcp_packet(buffer, size);*/
			break;

		case 17: /*UDP Protocol*/
			/*print_udp_packet(buffer, size);*/
			break;

		default: /*Some Other Protocol like ARP etc.*/
			break;
	}
	print_ip_header(buffer, size);
	print_data(buffer, size);
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

	unsigned short iphdrlen, tmp_checksum = 0;

	struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));

	iphdrlen = iph->ihl*4;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	print_ethernet_header(Buffer, Size);

	tmp_checksum = ntohs(iph->check);
	iph->check = 0;
	compute_ip_checksum(iph);

	printf("\nOld checksum : %d, my checksum : %d\n", tmp_checksum,
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
	printf("   |-Checksum          : %d\n",ntohs(iph->check));
	printf("   |-Source IP         : %s\n", inet_ntoa(source.sin_addr));
	printf("   |-Destination IP    : %s\n", inet_ntoa(dest.sin_addr));
}

void print_data (const unsigned char * data , int Size){
	int i, j;
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
