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

#define MAX_NUMBER_OF_HOSTS 200

typedef struct QUESTION QUESTION;
typedef struct DNS_HEADER DNS_HEADER;
typedef struct RES_RECORD RES_RECORD;

char *url;
char *host_names[MAX_NUMBER_OF_HOSTS];
char *resp_ips[MAX_NUMBER_OF_HOSTS];
int txid[MAX_NUMBER_OF_HOSTS];
int current_pairs;

char *get_resp_ip_str(int size, struct DNS_HEADER *dns_header, int i, const u_char *packet_buffer) {
	RES_RECORD answers[20];
	int stop, j;
	char *ret;
	struct sockaddr_in source;

	stop = 0;
	size += sizeof(DNS_HEADER) + i + 1 + sizeof(QUESTION);
	const u_char *pck_new = packet_buffer + size;
	ret = (char *) calloc(200 * sizeof(char), 1);
	strcpy(ret, " ");
	/* Store the all response IPs! */
	for (j=0; j < ntohs(dns_header->ans_count); j++) {
        	pck_new = pck_new + 2;
		memcpy(&(answers[j].type), pck_new, 2);
		memcpy(&(answers[j].data_len), pck_new + 8, 2);
		pck_new = pck_new + 10;
		char *ip = (char *) malloc(4 * sizeof(char));
        	if (ntohs(answers[j].type) == 1) {
			memcpy(&(answers[j].rdata), pck_new, 4);
			memset(&source, 0, sizeof(source));
			source.sin_addr.s_addr = answers[j].rdata;
            		inet_ntop(AF_INET, &(source.sin_addr), ip, 16);
			strcat(ret, ip);
			strcat(ret, " ");
			pck_new = pck_new + 4;
		} else {
			/* Skip CNAME address */
			pck_new = pck_new + ntohs(answers[j].data_len);
		}
	}
	return ret;
}

void check_dns_packet(const u_char *packet_buffer, int packet_size, struct timeval ts) {
	int i, j, k, length, p;
	bool dns_attack_detected = false;
	struct iphdr *ip_header = (struct iphdr *)(packet_buffer +  sizeof(struct ethhdr));
    	length = ip_header->ihl*4;
    	struct udphdr *udp_header = (struct udphdr*)(packet_buffer + length  + sizeof(struct ethhdr));
    	int size =  sizeof(struct ethhdr) + length + sizeof (udp_header);
	DNS_HEADER *dns_header = (DNS_HEADER *)(packet_buffer + size);

	char *ans_ip;
	if(ntohs(udp_header->source) == 53) {
		/* Check if this is response of type 'A' */
		int name_len = (int)strlen((const char*)(packet_buffer+size+sizeof(DNS_HEADER)));
		QUESTION *question = (QUESTION *)(packet_buffer+ size + sizeof(DNS_HEADER)+ name_len + 1);
		if(ntohs(question->qtype) != 1) {
			return;
		}

		/* Get URL of DNS response */		
		url = (char *) calloc(name_len, sizeof(char));
		for(i=0; i < name_len; i++) {
	        	p=(packet_buffer+size+sizeof(DNS_HEADER))[i];
	        	for(j=0; j<p; j++) {
	            		url[i]=(packet_buffer+size+sizeof(DNS_HEADER))[i+1];
	            		i=i+1;
	        	}
	        	url[i]='.';
	    	}
	    	url[i-1]='\0';

		/* Check if we have recevied any response for this before */
		for (j = 0; j < current_pairs; j++) {
			if(strcmp(url, host_names[j]) == 0 && txid[j] == ntohs(dns_header->id)) {
				dns_attack_detected = true;
				/* Print about dns detection here */
				printf("###########################################################################\n");
				printf("ALERT! DNS ATTACK DETECTED!\n");
				printf("Time: %sTransaction ID: 0x%x \nRequest: %s\n", ctime(&(ts.tv_sec)), txid[j], url);
				ans_ip = strdup(get_resp_ip_str(size, dns_header, i, packet_buffer));
				printf("Answer 1: %s\n", resp_ips[j]);
				printf("Answer 2: %s\n", ans_ip);
				printf("###########################################################################\n");
				break;
			}
		}
		/* This seems new entry. Add its detail in array. */
		if (dns_attack_detected == false) {
			host_names[current_pairs] = (char *)malloc(strlen(url));
			strcpy(host_names[current_pairs], url);
			txid[current_pairs] = ntohs(dns_header->id);
			ans_ip = strdup(get_resp_ip_str(size, dns_header, i, packet_buffer));
			resp_ips[current_pairs] = (char *) malloc(strlen(ans_ip));
			strcpy(resp_ips[current_pairs++], ans_ip);
		}
	}
}

void process_packet(struct pcap_pkthdr *header, const u_char *buffer, struct timeval ts) {
   	int size = header->len;
    	struct ethhdr *ethernet_header = (struct ethhdr *)buffer;
	struct iphdr *ip_header = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    	switch (ntohs(ethernet_header->h_proto)) {
    	case ETHERTYPE_IP:
		if (ip_header->protocol == 17) {
			check_dns_packet(buffer, size, ts);
    		}
		break;							
	default:
		break;		
    	}
}

void detection_callback(u_char *temp, const struct pcap_pkthdr* pkthdr,const u_char* packet) {
	process_packet((struct pcap_pkthdr *)pkthdr, packet, pkthdr->ts);
}

/*Sniif packets for detection */
void sniff_packets_for_detection(char *interface, char *filterExpression) {
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
    	pcap_t* descr;
    	struct bpf_program fp;
    	bpf_u_int32 pMask;
    	bpf_u_int32 pNet;
   	pcap_if_t *alldevs, *d;
    	char dev_buff[64] = {0};
    	int i =0;

    	if (strcmp(interface, " ") == 0) {
    		interface = pcap_lookupdev(errbuf);
		if (interface == NULL) {
			printf("couldn't find default device: %s\n", errbuf);
			return;
		}
    	}
	dev = strdup(interface);
	pcap_lookupnet(dev, &pNet, &pMask, errbuf);
    	descr = pcap_open_live(dev, BUFSIZ, 1,-1, errbuf);
    	if (descr == NULL) {
        	printf("pcap_open_live() failed due to [%s]\n", errbuf);
        	return;
    	}
    	if (pcap_compile(descr, &fp, filterExpression, 0, pNet) == -1) {
        	printf("\npcap_compile() failed. Check for filter expression validity.\n");
        	return;
    	}
    	if (pcap_setfilter(descr, &fp) == -1) {
        	printf("\nUnable to set filter. pcap_setfilter() failed\n");
        	exit(1);
    	}
    	pcap_loop(descr, -1, detection_callback, NULL);
    	return;
}

/* Function to read pcap file and dump its data based on the expression */
void read_pcap_file(char *fileName, char *filterExpression) {
	pcap_t *pcap;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	struct bpf_program fp;        

	pcap = pcap_open_offline(fileName, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "Error in reading pcap file: %s\n", errbuf);
		exit(1);
	}
	if (pcap_compile(pcap, &fp, filterExpression, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        	printf("\npcap_compile() failed. Check for filter expression validity.\n");
        	return;
    	}
   	if (pcap_setfilter(pcap, &fp) == -1) {
       		printf("\nUnable to set filter. pcap_setfilter() failed.\n");
        	exit(1);
    	}
	while ((packet = pcap_next(pcap, &header)) != NULL) {
		process_packet(&header, packet, header.ts);
	}
	return;
}
