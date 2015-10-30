#include "shellconfig.h"

#ifndef SERVER_IP
#error "Please define SERVER_IP in config. Should be a hex IPv4 value."
#endif

#ifndef SERVER_PORT
#error "Please define SERVER_PORT in config. Should be a host byte order integer value."
#endif

#include "shellcode.h"
#include "xnu10.10/syscalls.h"
#include <unistd.h>
#include <netinet/in.h>

int main() {
	int sockfd;
	struct sockaddr_in serv_addr;

	sockfd = scc_socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
        scc_exit(43);
	}

	bzero((struct sockaddr *)&serv_addr,sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = SERVER_IP;
	serv_addr.sin_port = htons(SERVER_PORT);

	if(scc_connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) {
        scc_exit(44);
	}

	if(scc_write(sockfd, MESSAGE, MESSAGE_LEN) <= 0) {
		scc_exit(45);
	}

	scc_close(sockfd);

	// end the process
	scc_exit(42);
}

#include "syscalls.c"
#include "xnu10.10/syscalls.c"

