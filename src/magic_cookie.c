#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include <arpa/inet.h>

#include "socket.h"
#include "dhcp.h"
#include "database.h"

void signalHandler(int signo){
	int ret = 0;

	if(signo == SIGINT){
		printf("Received termination signal, closing socket...\n");
		ret = socket_closeServer();
		if(ret){
			fprintf(stderr, "Error closing socket, code: %d\n", ret);
		}
	}
}

struct dhcp_lease model[] = {
	{{0x0a000a0a}, {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa}, "teste1", 0},
	{{0x0b000a0a}, {0xfe, 0xee, 0xdd, 0xcc, 0xbb, 0xaa}, "teste2", 0},
	{{0x0c000a0a}, {0xfd, 0xee, 0xdd, 0xcc, 0xbb, 0xaa}, "teste3", 0},
	{{0x0d000a0a}, {0xfc, 0xee, 0xdd, 0xcc, 0xbb, 0xaa}, "teste4", 0},
};

int main(int argc, char **argv){
	int ret = 0;

	struct dhcp_lease *leases = NULL;
	int count = 0;
	int idx;
	struct in_addr addr;

	ret = db_addLease(model[0]);
	if(ret != DB_RESULTS_ADDED)
		printf("Error adding lease, code: %i\n", ret);
	ret = db_addLease(model[1]);
	if(ret != DB_RESULTS_ADDED)
		printf("Error adding lease, code: %i\n", ret);

	ret = db_addStaticLease(model[2]);
	if(ret != DB_RESULTS_ADDED)
		printf("Error adding lease, code: %i\n", ret);
	ret = db_addStaticLease(model[3]);
	if(ret != DB_RESULTS_ADDED)
		printf("Error adding lease, code: %i\n", ret);

	int lCount = 0;
	struct dhcp_lease *results;
	results = db_getLeases(&lCount);
	if(results == NULL){
		printf("Error getting leases, code %i\n", ret);
	}else{
		printf("Got %d leases\n", lCount);
		for(idx = 0; idx < lCount; idx++)
			printf("Lease: %d, %02X:%02X:%02X:%02X:%02X:%02X. Name: %s\n", inet_ntoa(results[idx].ipAddr), results[idx].hwAddr[0], results[idx].hwAddr[1], results[idx].hwAddr[2], results[idx].hwAddr[3], results[idx].hwAddr[4], results[idx].hwAddr[5], results[idx].hostname);

		free(results);
	}
	results = db_getStaticLeases(&lCount);
	if(results == NULL){
		printf("Error getting leases, code %i\n", ret);
	}else{
		printf("Got %d leases\n", lCount);
		for(idx = 0; idx < lCount; idx++)
			printf("Lease: %d, %02X:%02X:%02X:%02X:%02X:%02X. Name: %s\n", inet_ntoa(results[idx].ipAddr), results[idx].hwAddr[0], results[idx].hwAddr[1], results[idx].hwAddr[2], results[idx].hwAddr[3], results[idx].hwAddr[4], results[idx].hwAddr[5], results[idx].hostname);

		free(results);
	}

	results = (struct dhcp_lease *)malloc(sizeof(struct dhcp_lease));
	ret = db_searchLease(results, model[0].hwAddr);
	if(ret != DB_RESULTS_FOUND)
		printf("Error searching from a lease\n");
	else
		printf("Found with IP: %s\n", inet_ntoa(results->ipAddr));

	ret = db_searchLease(results, model[2].hwAddr);
	if(ret != DB_RESULTS_NONE)
		printf("Error searching from a NOT lease\n");
	else
		printf("Not found good!\n");

	ret = db_searchStaticLease(results, model[3].hwAddr);
	if(ret != DB_RESULTS_FOUND)
		printf("Error searching from a lease\n");
	else
		printf("Found with IP: %s\n", inet_ntoa(results->ipAddr));

	ret = db_searchStaticLease(results, model[1].hwAddr);
	if(ret != DB_RESULTS_NONE)
		printf("Error searching from a NOT lease\n");
	else
		printf("Not found good!\n");
	free(results);

	ret = db_removeLease(model[0].hwAddr);
	if(ret != DB_RESULTS_REMOVED)
		printf("Error removing model, code: %d\n", ret);

	ret = db_removeLease(model[1].hwAddr);
	if(ret != DB_RESULTS_REMOVED)
		printf("Error removing model, code: %d\n", ret);

	ret = db_removeStaticLease(model[2].hwAddr);
	if(ret != DB_RESULTS_REMOVED)
		printf("Error removing model, code: %d\n", ret);

	ret = db_removeStaticLease(model[3].hwAddr);
	if(ret != DB_RESULTS_REMOVED)
		printf("Error removing model, code: %d\n", ret);

	return 0;

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

	sleep(1001); // wait 10 seconds and fuck off!
	ret = socket_closeServer();
	if(ret){
		fprintf(stderr, "Error closing socketoso. Code: %d\n", ret);
		return ret;
	}

	return 0;
}
