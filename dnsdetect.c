#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

extern void sniff_packets_for_detection(char *, char *);
extern void read_pcap_file(char *, char *);

int main(int argc, char *argv[]) {

	unsigned int iflag = 0, rflag = 0, hflag = 0, option;
	char usage[] = "Usage: dnsdetect [-i interface] [-r tracefile] expression \n";
	char optstring[] = "hi:r:";
	char *token, *expression = NULL;
	int count = 0;

	/* Intializing arguments to their default value */
	char *tracefile = (char *) calloc(sizeof (char *), sizeof(char));	
	strcpy(tracefile, " ");
	char *interface = (char *) calloc(sizeof (char *), sizeof(char));
	strcpy(interface, " ");

	while((option = getopt(argc, argv, optstring)) != (-1)) {
		switch(option) {	
			case 'i':
				iflag++;
				interface = optarg;
				break;
			case 'r':
				rflag++;
				tracefile = optarg;
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
	if ((iflag != 0 && rflag != 0) || (iflag == 1 && rflag == 1)) {
		printf("Invalid options. Provide interface or trace file name. Use -h for more help.\n");
		exit(-1);
	}
	if (iflag > 1 || rflag > 1 || hflag > 1) {
		printf("Invalid Option in argument. Use -h for more help of command usage.\n");
		exit(-1);
	}

	if (optind < argc) {
		expression = (char *) calloc(strlen(argv[optind])+1, sizeof(char));
		strcpy(expression, argv[optind++]);  
		strcat(expression, " ");
	}	
	while (optind < argc) {
		expression = (char *) realloc(expression, strlen(expression)+strlen(argv[optind])+1);
		strcat(expression, argv[optind++]);
		strcat(expression, " ");
	}

	/* Sniff DNS packets if interface is provided*/
	if (iflag == 1)
		sniff_packets_for_detection(interface, expression);
	else if (rflag == 1)
		read_pcap_file(tracefile, expression);
	return 0;
}
