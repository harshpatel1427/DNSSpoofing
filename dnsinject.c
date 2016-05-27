#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <pcap.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <netdb.h>

#define _GNU_SOURCE
#define MAX_NUMBER_OF_HOSTS 20

extern void sniff_packets_for_injection(char *, char *);

char *read_hostname_file(char *);
char *host_names[MAX_NUMBER_OF_HOSTS];
char *host_ip[MAX_NUMBER_OF_HOSTS];
int total_pairs;
char *ip_spoof;

bool get_interface_ip (char *dev) {
	struct ifaddrs *if_addr, *ifa;
	int family, s;
	char hostnames[NI_MAXHOST];
	if (getifaddrs(&if_addr) == -1) {
		perror("getifaddrs error:");
		return false;
	}
	for (ifa = if_addr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;  
		s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), hostnames, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		if((strcmp(ifa->ifa_name, dev) == 0) && (ifa->ifa_addr->sa_family == AF_INET)) {
			if (s != 0) {
				printf("getnameinfo() failed due to: %s\n", gai_strerror(s));
				return false;
			}
			ip_spoof = (char *) calloc(strlen(hostnames), 1);
			strcpy(ip_spoof, hostnames);
		}
	}
	freeifaddrs(if_addr);
	return true;
}

int main(int argc, char *argv[]) {

	unsigned int iflag = 0, fflag = 0, hflag = 0, option;
	char usage[] = "Usage: dnsinject [-i interface] [-f hostnames] expression \n";
	char optstring[] = "hi:f:";
	char *token, *expression = NULL;
	int count = 0;
	total_pairs = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* Intializing arguments to their default value */
	char *hostnamefile = (char *) malloc(sizeof (char *));	
	strcpy(hostnamefile, " ");
	char *interface = (char *) malloc(sizeof (char *));	
	strcpy(interface, " ");

	while((option = getopt(argc, argv, optstring)) != (-1)) {
		switch(option) {
			
			case 'i':
				iflag++;
				interface = optarg;
				break;
			
			case 'f':
				fflag++;
				hostnamefile = optarg;
				break;
			case 'h':
				hflag++;
				printf("%s", usage);
				break;
			case '?':
				exit(-1);
				break;
		}
	}
	if (hflag == 1) {
		/* Usage is already printed. Exit now. */
		exit(-1);
	}

	if (iflag > 1 || fflag > 1 || hflag > 1) {
		printf("Invalid Option in argument. Use -h for more help of command usage.\n");
		exit(-1);
	}

	if (optind < argc) {
		expression = (char *) malloc(strlen(argv[optind])+1);
		strcpy(expression, argv[optind++]);  
		strcat(expression, " ");
	}	
	while (optind < argc) {
		expression = (char *) realloc(expression, strlen(expression)+strlen(argv[optind])+1);
		strcat(expression, argv[optind++]);
		strcat(expression, " ");
	}

	/* Get hostnames and IP address */
	if(fflag != 0) {
		char *host_details = read_hostname_file(hostnamefile);
		if(host_details == NULL)
			exit(-1);
		char *data = strdup(host_details);
		while((token = strsep(&data, "\n"))) {
			char *str;
			if(strcmp(token,"") == 0)
				break;
			if(total_pairs >= 20)
				break;
			while((str = strsep(&token, " "))) {
				if (count % 2 == 0) {
					if(token == NULL) {
						printf("IP and host should be separated by space in hostfile\n");
						exit(-1);
					}
					host_ip[total_pairs] = (char *)malloc(strlen(str));
					strcpy(host_ip[total_pairs], str);
				} else {
					host_names[total_pairs] = (char *)malloc(strlen(str));
					strcpy(host_names[total_pairs], str);
				}
				count++;
			}
			total_pairs++;
			if(data == NULL)
				break;
		}
	}
	if (strcmp(interface, " ") == 0) {
    		interface = pcap_lookupdev(errbuf);
		if (interface == NULL) {
			fprintf(stderr, "couldn't find default device: %s\n", errbuf);
			return;
		}
    	}
	if (total_pairs == 0) {
		if(!get_interface_ip(interface)) {
			fprintf(stderr, "couldn't find associated ip for interface\n");
		}
	}

	/* Sniff DNS packets */
	sniff_packets_for_injection(interface, expression);
	return 0;
}

char *read_hostname_file(char *filename) {
	char *keybuf;
	long length;
	FILE *fp = fopen(filename, "r");
	if (fp) {
		fseek(fp, 0, SEEK_END);
		length = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		keybuf = (char *)malloc(length);
		if (keybuf)
			fread(keybuf, 1, length, fp);
		fclose(fp);
	} else {
		printf("Unable to open file for reading host details. Check for filename or its permission.\n");
		return NULL;
	}
	return keybuf;
}
