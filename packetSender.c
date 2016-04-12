#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define SOCKET_ERROR ((int)-1)
#define SIZEBUF 1000000
#define MAXSIZE 1000000

int main(int argc, char *argv[])
{
	struct sockaddr_in Local, Serv;
	char string_remote_ip_address[100];
	short int remote_port_number;
	int socketfd, OptVal, ris;
	int n, i, nwrite, len;
	char msg[MAXSIZE];
	
	for(i=0;i<MAXSIZE;i++) {
		msg[i]='a';
	}
	
	msg[MAXSIZE-1]='\0';
	
	if(argc!=3) {
		printf ("2 parameters are needed\n");
		exit(1);
	} else {
		strncpy(string_remote_ip_address, argv[1], 99);
		remote_port_number = atoi(argv[2]);
	}

	/* get a datagram socket */
	printf("Initializing socket...\n");
	socketfd = socket(AF_INET, SOCK_STREAM, 0);
	if (socketfd == SOCKET_ERROR) {
		printf("socket() failed, Err: %d \"%s\"\n", errno,strerror(errno));
		exit(1);
	}

	/* avoid EADDRINUSE error on bind() */
	OptVal = 1;
	printf ("Setting socket options...\n");
	ris = setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, (char *)&OptVal, sizeof(OptVal));
	if (ris == SOCKET_ERROR)  {
		printf ("setsockopt() SO_REUSEADDR failed, Err: %d \"%s\"\n", errno,strerror(errno));
		exit(1);
	}

	/* name the socket */
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

	/* assign our destination address */
	memset ( &Serv, 0, sizeof(Serv) );
	Serv.sin_family     =    AF_INET;
	Serv.sin_addr.s_addr  =    inet_addr(string_remote_ip_address);
	Serv.sin_port         =    htons(remote_port_number);

	/* connection request */
	printf ("Connecting...\n");
	ris = connect(socketfd, (struct sockaddr*) &Serv, sizeof(Serv));
	if (ris == SOCKET_ERROR)  {
		printf ("Connecting failed, Err: %d \"%s\"\n",errno,strerror(errno));
		exit(1);
	}

	/*send data out*/
	len = strlen(msg)+1;
	nwrite=0;
	printf ("Sending...\n");
	fflush(stdout);
	while((n=write(socketfd, &(msg[nwrite]), len-nwrite)) > 0) {
		nwrite+=n;
	}
	if(n<0) {
		char msgerror[1024];
		sprintf(msgerror,"Sending failed [err %d] ",errno);
		perror(msgerror);
		fflush(stdout);
		return(1);
	}
	close(socketfd);
	return(0);
}