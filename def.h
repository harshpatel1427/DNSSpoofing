#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<unistd.h>

struct DNS_HEADER {
    	unsigned short id;
	unsigned short flags;
    	unsigned short q_count;
    	unsigned short ans_count;
    	unsigned short ns_count;
    	unsigned short add_count;
}__attribute__((packed));

struct QUESTION {
	unsigned short qtype;
    	unsigned short qclass;
}__attribute__((packed));

struct RES_RECORD {
    	unsigned short name;
	unsigned short type;
   	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
	unsigned int rdata;
}__attribute__((packed));

