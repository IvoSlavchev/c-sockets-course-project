#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
 
int sock_raw;
FILE* logfile;
int i, j;
struct sockaddr_in source, dest;

void printData(unsigned char* data , int size) {
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

int main() {
    unsigned int saddr_size , data_size;
    struct sockaddr saddr;   
    unsigned char* buffer = (unsigned char*) malloc(65536);   
    logfile = fopen("packets.txt", "w");
    sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    while (1) {
        saddr_size = sizeof(saddr);
        data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, &saddr_size);
        struct iphdr *iph = (struct iphdr*) buffer;
        if (iph->protocol == 6) {
            printf("TCP packet received: Source IP: %s\n", inet_ntoa(source.sin_addr));
            printTCPPacket(buffer, data_size);
        }
    }
    close(sock_raw);
    return 0;
}