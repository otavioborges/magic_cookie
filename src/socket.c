#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>

#include "socket.h"
#include "config.h"

static int m_socket = -1;
static struct sockaddr_in m_serverAddr;
static uint8_t payload[SOCKET_MAX_PAYLOAD];

static socket_callback m_callback = NULL;
static pthread_t m_socketThread = 0;
static uint8_t m_keepRunning = 1;

static void *socket_handler(void *argument){
	uint8_t *keep = (uint8_t *)argument;
	struct sockaddr_in clientAddr;
	struct sockaddr_ll destAddr;
	int addrLength, responseLength, recvBytes, sendBytes;
	uint8_t *response;

	addrLength = sizeof(clientAddr);
	while(*keep){
		DEBUG("Trying to receive...");
		recvBytes = recvfrom(m_socket, payload, SOCKET_MAX_PAYLOAD, MSG_WAITALL, (struct sockaddr *)&clientAddr, &addrLength);
		if(recvBytes > 0){
			DEBUG("Received %d bytes", recvBytes);
			if(m_callback){
       responseLength = m_callback(payload, recvBytes, &response);
     		if(responseLength > 0){
					// memset(&clientAddr, 0, sizeof(clientAddr));
					// clientAddr.sin_family = AF_INET;
					// clientAddr.sin_port = htons(68);
					// clientAddr.sin_addr.s_addr = INADDR_BROADCAST;
					// bzero(&clientAddr.sin_zero, sizeof(clientAddr.sin_zero));

					memset(&destAddr, 0, sizeof(destAddr));
					destAddr.sll_family = PF_PACKET;
					destAddr.sll_protocol =

					sendBytes = sendto(m_socket, response, responseLength, MSG_DONTWAIT, (struct sockaddr *)&clientAddr, addrLength);
					DEBUG("Sent %d bytes to client...", sendBytes);
				}
			}
		}
	}

	pthread_exit(NULL);
}

int socket_openServer(uint16_t port){
	int ret = 0;
	struct timeval timeout;
	struct ifreq ifr;
	int broadcastFlag = 1;

	timeout.tv_sec = 0;
	timeout.tv_usec = (SOCKET_RCVTIMEOUT_IN_MS * 1000);

	m_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if(m_socket < 0)
		return m_socket;
	DEBUG("Socket created ok, with code: %d!", m_socket);

	memset(&ifr, 0, sizeof(struct ifreq));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "eth1");
	ret = setsockopt(m_socket, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(struct ifreq));
       	if(ret)
		return ret;
	DEBUG("Using '%s' as bound interface", ifr.ifr_name);

	ret = setsockopt(m_socket, SOL_SOCKET, SO_BROADCAST, (void *)&broadcastFlag, sizeof(int));
	if(ret)
		return ret;
	DEBUG("Enabled broadcast feature");

	ret = setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, (void *)&timeout, sizeof(struct timeval));
	if(ret)
		return ret;
	DEBUG("Timeout configured ok!");

	memset(&m_serverAddr, 0, sizeof(m_serverAddr));

	m_serverAddr.sin_family = AF_INET;
	m_serverAddr.sin_addr.s_addr = INADDR_ANY;
	m_serverAddr.sin_port = htons(port);

	ret = bind(m_socket, (const struct sockaddr *)&m_serverAddr, sizeof(m_serverAddr));
	if(ret < 0){
		close(m_socket);
		return ret;
	}
	DEBUG("Socket bound!");

	ret = pthread_create(&m_socketThread, NULL, socket_handler, (void *)&m_keepRunning);
	if(ret){
		close(m_socket);
		return ret;
	}
	DEBUG("Thread created, continue with this baby!");

	// all good, let it roll
	return 0;
}

int socket_closeServer(void){
	if(m_socket >= 0){
		DEBUG("There\'s a socket to be closed...");
		if(m_socketThread){
			DEBUG("Closing thread PID..");
			m_keepRunning = 0;
			pthread_join(m_socketThread, NULL);
		}

		DEBUG("Closing socket: %d", m_socket);
		return close(m_socket);
	}else{
		DEBUG("Nothing to close...go away!");
		return 0;
	}
}

int socket_setRecvTimeout(unsigned int ms){
	struct timeval timeout;
	int ret;

	if(ms >= 1000){
		timeout.tv_sec = (int)(ms / 1000);
		ms -= (int)(timeout.tv_sec * 1000);
	}
	timeout.tv_usec = (ms * 1000);

	if(m_socket > 0)
		return setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, (void *)&timeout, sizeof(struct timeval));
	else
		return -EPERM;
}

void socket_defineCallback(socket_callback func){
	m_callback = func;
}
