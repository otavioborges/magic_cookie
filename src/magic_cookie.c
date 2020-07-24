#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <arpa/inet.h>

#include "socket.h"
#include "dhcp.h"
#include "database.h"

static int keepRunning = 1;

void signalHandler(int signo){
	int ret = 0;

	if(signo == SIGINT){
		printf("Received termination signal, closing socket...\n");
		ret = socket_closeServer();
		if(ret){
			fprintf(stderr, "Error closing socket, code: %d\n", ret);
		}
	}

	keepRunning = 0;
}

int main(int argc, char **argv){
	int ret = 0;

	// attaching Ctrl+C signal
	if(signal(SIGINT, signalHandler) == SIG_ERR){
		fprintf(stderr, "Error attaching interrupt signal, exiting...\n");
		return ret;
	}

	ret = socket_openServer(67);
	if(ret){
		fprintf(stderr, "Error opening socketoso. Code: %d\n", ret);
		return ret;
	}

	dhcp_init();
	socket_defineCallback(dhcp_socketCallback);

	while(keepRunning){
		sleep(100);
	}

	dhcp_end();
	return 0;
}
