#include "../include/snif.h"

int main(){
	pcap_if_t *alldevsp, *device;
	pcap_t *handle;

	char errbuf[100], devs[100][100];
	int count = 1;

	printf("Finding available devices ... \n");
	if(pcap_findalldevs(&alldevsp, errbuf) ){
		perror("pcap_findalldevs");
		exit(1);
	}
	printf("Done");

	printf("\nAvailable Devices are :\n");

	for(device = alldevsp; device != NULL; device = device->next){
		printf("%d. %s - %s\n", count, device->name,
						 device->description);
		if(device->name != NULL){
			strcpy(devs[count], device->name);
		}
		count++;
	}

	handle = pcap_open_live("eth0", 65536, 1, 0, errbuf);

	if (handle == NULL){
		perror("pcap_open_live error");
		exit(-1);
	}
	printf("Done\n");

	pcap_loop(handle , -1 , process_packet , NULL);

	return 0;
}
