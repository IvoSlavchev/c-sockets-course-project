#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <errno.h>

#define SOCKET_ERROR ((int)-1)
#define SIZEBUF 1000000
#define MAXSIZE 1000000

FILE* logfile;
struct sockaddr_in source;

void printData(unsigned char* data, int size) {
	int i, j;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0) {
            fprintf(logfile,"         ");
            for (j = i - 16; j < i; j++) {
                if (data[j] >= 32 && data[j] <= 128) {
                    fprintf(logfile, "%c", (unsigned char) data[j]);               
                } else {
                    fprintf(logfile, ".");
                }
            }
            fprintf(logfile, "\n");
        } 
         
        if (i % 16 == 0) {
            fprintf(logfile,"   ");
        }
        fprintf(logfile, " %02X", (unsigned int) data[i]);
                 
        if (i == size-1) {
            for (j = 0; j < 15 - i % 16; j++) {
                fprintf(logfile,"   ");
            }
            fprintf(logfile,"         ");
            for (j = i - i % 16; j <= i; j++) {
                if (data[j] >= 32 && data[j] <= 128) {
                    fprintf(logfile, "%c", (unsigned char) data[j]);
                } else {
                    fprintf(logfile, ".");
                }
            }
            fprintf(logfile, "\n");
        }
    }
}

void printIPHeader(unsigned char* buffer, int size) {
	struct sockaddr_in dest;  
    struct iphdr *iph = (struct iphdr*) buffer; 
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;   
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    fprintf(logfile,"\n");
    fprintf(logfile,"IP Header\n");
    fprintf(logfile,"   |-IP Version        : %d\n", (unsigned int) iph->version);
    fprintf(logfile,"   |-IP Header Length  : %d DWORDS or %d Bytes\n",
        (unsigned int) iph->ihl, ((unsigned int) (iph->ihl))*4);
    fprintf(logfile,"   |-Type Of Service   : %d\n", (unsigned int) iph->tos);
    fprintf(logfile,"   |-IP Total Length   : %d  Bytes(Size of Packet)\n", ntohs(iph->tot_len));
    fprintf(logfile,"   |-Identification    : %d\n", ntohs(iph->id));
    fprintf(logfile,"   |-TTL      : %d\n", (unsigned int) iph->ttl);
    fprintf(logfile,"   |-Protocol : %d\n", (unsigned int) iph->protocol);
    fprintf(logfile,"   |-Checksum : %d\n", ntohs(iph->check));
    fprintf(logfile,"   |-Source IP        : %s\n", inet_ntoa(source.sin_addr));
    fprintf(logfile,"   |-Destination IP   : %s\n", inet_ntoa(dest.sin_addr));
}

void printTCPPacket(unsigned char* buffer, int size) {
    unsigned short iphdrlen;
    struct iphdr *iph = (struct iphdr *) buffer;
    iphdrlen = iph->ihl * 4;
    struct tcphdr *tcph = (struct tcphdr*) (buffer + iphdrlen);
             
    fprintf(logfile,"\n\n***********************TCP Packet*************************\n");    
     
    printIPHeader(buffer, size);
    
    fprintf(logfile,"\n");     
    fprintf(logfile,"                        DATA Dump                         ");
    fprintf(logfile,"\n");
         
    fprintf(logfile,"IP Header\n");
    printData(buffer, iphdrlen);   
    fprintf(logfile,"TCP Header\n");
    printData(buffer + iphdrlen, tcph->doff * 4); 
    fprintf(logfile,"Data Payload\n");  
    printData(buffer + iphdrlen + tcph->doff * 4, (size - tcph->doff * 4 - iph->ihl * 4));              
    fprintf(logfile,"\n###########################################################");
}

void sendPacket() {
	struct sockaddr_in Local, Serv;
	char string_remote_ip_address[100];
	short int remote_port_number;
	int socketfd, OptVal, ris;
	int n, nwrite, len;
	char msg[MAXSIZE];

    strcpy(msg, "Sample message");
    msg[MAXSIZE-1]='\0';

	strncpy(string_remote_ip_address, "127.0.0.1", 99);
	remote_port_number = atoi("3000");

	printf("Initializing socket...\n");
	socketfd = socket(AF_INET, SOCK_STREAM, 0);
	if (socketfd == SOCKET_ERROR) {
		printf("socket() failed, Err: %d \"%s\"\n", errno,strerror(errno));
		exit(1);
	}

	OptVal = 1;
	printf ("Setting socket options...\n");
	ris = setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, (char *)&OptVal, sizeof(OptVal));
	if (ris == SOCKET_ERROR)  {
		printf ("setsockopt() SO_REUSEADDR failed, Err: %d \"%s\"\n", errno,strerror(errno));
		exit(1);
	}

	memset ( &Local, 0, sizeof(Local) );
	Local.sin_family = AF_INET;
	Local.sin_addr.s_addr = htonl(INADDR_ANY);
	Local.sin_port = htons(0);
	printf ("Binding...\n");
	ris = bind(socketfd, (struct sockaddr*) &Local, sizeof(Local));
	if (ris == SOCKET_ERROR)  {
		printf ("Binding failed, Err: %d \"%s\"\n",errno,strerror(errno));
		exit(1);
	}

	memset ( &Serv, 0, sizeof(Serv) );
	Serv.sin_family = AF_INET;
	Serv.sin_addr.s_addr = inet_addr(string_remote_ip_address);
	Serv.sin_port = htons(remote_port_number);

	printf ("Connecting...\n");
	ris = connect(socketfd, (struct sockaddr*) &Serv, sizeof(Serv));
	if (ris == SOCKET_ERROR)  {
		printf ("Connecting failed, Err: %d \"%s\"\n",errno,strerror(errno));
		exit(1);
	}

	len = strlen(msg)+1;
	nwrite = 0;
	printf ("Sending...\n");
	fflush(stdout);
	while ((n=write(socketfd, &(msg[nwrite]), len-nwrite)) > 0) {
		nwrite+=n;
	}
	if (n < 0) {
		char msgerror[1024];
		sprintf(msgerror,"Sending failed [err %d] ",errno);
		perror(msgerror);
		fflush(stdout);
		exit(1);
	}
	close(socketfd);
}

void receivePackets(int sock_raw, char* targetIp) {
    unsigned int saddr_size , data_size;
    struct sockaddr saddr;   
    unsigned char* buffer = (unsigned char*) malloc(65536);   
    saddr_size = sizeof(saddr);
    data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, &saddr_size);
    if (data_size <0 ) {
        printf("Recvfrom error , failed to get packets\n");
        exit(1);
    }
    struct iphdr *iph = (struct iphdr*) buffer;
    if (iph->protocol == 6) {
        printf("TCP packet received: Source IP: %s\n", inet_ntoa(source.sin_addr));
        if (strcmp(inet_ntoa(source.sin_addr), targetIp) == 0) {
            sendPacket();
        }
        printTCPPacket(buffer, data_size);
    }
}

int main(int argc, char** argv) {
	int sock_raw;
    logfile = fopen("packets.txt", "w");
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock_raw < 0) {
        printf("Socket Error\n");
        exit(1);
    }
    while (1) {
        receivePackets(sock_raw, argv[1]);
    }
    close(sock_raw);
    return 0;
}