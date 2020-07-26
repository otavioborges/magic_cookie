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

#include <sys/ioctl.h>

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
	struct arpreq req;
	int addrLength, responseLength, recvBytes, sendBytes;
	uint8_t *response;

	addrLength = sizeof(clientAddr);
	while(*keep){
		config_log(CONFIG_LOG_DEBUG, "Waiting for DHCP message...");
		recvBytes = recvfrom(m_socket, payload, SOCKET_MAX_PAYLOAD, MSG_WAITALL, (struct sockaddr *)&clientAddr, &addrLength);
		if(recvBytes > 0){
			config_log(CONFIG_LOG_DEBUG, "Received %d bytes from %d", recvBytes, inet_ntoa(clientAddr.sin_addr));
			if(m_callback){
			 memset(&clientAddr, 0, sizeof(clientAddr));
			 memset(&req, 0, sizeof(req));
       responseLength = m_callback(payload, recvBytes, &response, &req);
     		if(responseLength > 0){
					((struct sockaddr_in *)&req.arp_pa)->sin_port = htons(68);

					req.arp_flags |= ATF_COM;
					strcpy(req.arp_dev, "eth0");
					int ret = ioctl(m_socket, SIOCSARP, (caddr_t)&req);
					if(ret < 0){
						config_log(CONFIG_LOG_WARNING, "%s - Error adding entry at ARP table, error: %d", __func__, ret);
						continue;
					}


					sendBytes = sendto(m_socket, response, responseLength, MSG_DONTWAIT, (struct sockaddr *)&(req.arp_pa), addrLength); //&clientAddr, addrLength);
					config_log(CONFIG_LOG_DEBUG, "Sent %d bytes to client %s", sendBytes, inet_ntoa(((struct sockaddr_in *)&req.arp_pa)->sin_addr));
				}
			}
		}
	}

	config_log(CONFIG_LOG_NORMAL, "Exiting socket thread");
	pthread_exit(NULL);
}

int socket_openServer(uint16_t port){
	int ret = 0;
	struct timeval timeout;
	struct ifreq ifr;
	int broadcastFlag = 1;

	timeout.tv_sec = 0;
	timeout.tv_usec = (SOCKET_RCVTIMEOUT_IN_MS * 1000);

	m_socket = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(m_socket < 0)
		return m_socket;
	config_log(CONFIG_LOG_DEBUG, "Created socket for listening DHCP packets");

	memset(&ifr, 0, sizeof(struct ifreq));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "eth0");
	ret = setsockopt(m_socket, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(struct ifreq));
       	if(ret)
		return ret;
	config_log(CONFIG_LOG_DEBUG, "Using '%s' as bound interface", ifr.ifr_name);

	ret = setsockopt(m_socket, SOL_SOCKET, SO_BROADCAST, (void *)&broadcastFlag, sizeof(int));
	if(ret)
		return ret;

	ret = setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, (void *)&timeout, sizeof(struct timeval));
	if(ret)
		return ret;

	memset(&m_serverAddr, 0, sizeof(m_serverAddr));

	m_serverAddr.sin_family = AF_INET;
	m_serverAddr.sin_addr.s_addr = INADDR_ANY;
	m_serverAddr.sin_port = htons(port);

	ret = bind(m_socket, (const struct sockaddr *)&m_serverAddr, sizeof(m_serverAddr));
	if(ret < 0){
		close(m_socket);
		return ret;
	}

	ret = pthread_create(&m_socketThread, NULL, socket_handler, (void *)&m_keepRunning);
	if(ret){
		close(m_socket);
		return ret;
	}

	// all good, let it roll
	return 0;
}

int socket_closeServer(void){
	if(m_socket >= 0){
		if(m_socketThread){
			config_log(CONFIG_LOG_DEBUG, "Closing socket thread");
			m_keepRunning = 0;
			pthread_join(m_socketThread, NULL);
		}

		return close(m_socket);
	}else{
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
