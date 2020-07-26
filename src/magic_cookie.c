#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <arpa/inet.h>

#include "config.h"
#include "socket.h"
#include "dhcp.h"
#include "database.h"

static int keepRunning = 1;

void signalHandler(int signo){
	int ret = 0;

	if(signo == SIGINT){
		config_log(CONFIG_LOG_NORMAL, "Received SIGINT, closing server...");
		ret = socket_closeServer();
		if(ret){
			config_log(CONFIG_LOG_WARNING, "Error closing socket, code: %d", ret);
		}
	}

	keepRunning = 0;
}

int main(int argc, char **argv){
	int ret, count;
	struct dhcp_lease *list;
	struct timeval leaseTime;
	gettimeofday(&leaseTime, NULL);

	if(argc > 1){
		if(strcmp(argv[1], "--list-leases") == 0){
			list = db_getLeases(&count);
			if(list){
				printf("\tIP Address\tMAC Address\t\tHostname\tValid for\n-------------------------------------------------------------\n");
				for(ret = 0; ret < count; ret++){
					printf("\t%s\t%s\t%s\t%ds\n", inet_ntoa(list[ret].ipAddr),
						dhcp_htoa(list[ret].hwAddr), list[ret].hostname, (leaseTime.tv_sec - list[ret].leaseTimestamp));
				}
			}

			return 0;
		}else if((strcmp(argv[1], "-h") == 0) || (strcmp(argv[1], "--help") == 0)){
			printf("\tUsage: magic-cookie {--list-leases}\n\t\t--list-leases: list current leases\n");
			return 0;
		}
	}

	config_defineLogLevel(CONFIG_LOG_DEBUG);

	// attaching Ctrl+C signal
	if(signal(SIGINT, signalHandler) == SIG_ERR){
		config_log(CONFIG_LOG_ERROR, "Error attaching interrupt signal, exiting...");
		return ret;
	}

	config_log(CONFIG_LOG_NORMAL, "Initiating listening socket...");
	ret = socket_openServer(67);
	if(ret){
		config_log(CONFIG_LOG_ERROR, "Error opening socket. Code: %d", ret);
		return ret;
	}

	config_log(CONFIG_LOG_NORMAL, "Initiating DHCP server...");
	dhcp_init(NULL);
	socket_defineCallback(dhcp_socketCallback);

	while(keepRunning){
		sleep(1);
	}

	config_log(CONFIG_LOG_NORMAL, "Killing server...");
	dhcp_end();
	return 0;
}
