#define DHCP_PACKET_OVERHEAD	240

#define DHCP_OP_DISCOVER			1
#define DHCP_OP_OFFER					2
#define DHCP_OP_REQUEST				3
#define DHCP_OP_ACK						5
#define DHCP_OP_NACK					6

#define DHCP_PACKET_OP_REQ		1
#define DHCP_PACKET_OP_RES		2

#define DHCP_PACKET_HTYPE_ETH	1
#define DHCP_BROADCAST_FLAG		32768UL

#define DHCP_OPT_MAND_TTL					0x01
#define DHCP_OPT_MAND_LEASE_TIME	0x02
#define DHCP_OPT_MAND_RENEWAL			0x04
#define DHCP_OPT_MAND_REBINDING		0x08

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#include <arpa/inet.h>

#include <pthread.h>
#include <unistd.h>

#include "config.h"
#include "dhcp.h"
#include "database.h"

static struct dhcp_options *parsed_options[128];
static struct dhcp_server_config default_config;
static uint8_t m_keepRunning = 1;
static pthread_t m_dhcpHandler = 0;
static pthread_mutex_t m_dhcpWait = PTHREAD_MUTEX_INITIALIZER;

static int dhcp_get_available_lease(struct in_addr *lease);
static struct dhcp_options *dhcp_search_options(uint8_t option, uint8_t *where, int length);
// use after lease is done!
static struct dhcp_options *dhcp_get_option_value(uint8_t option, struct dhcp_options *op, int *opLength, int args, ...);
static int dhcp_is_valid_ip(struct in_addr *ip);
static void *dhcp_monitorThread(void *arguments);

static uint8_t m_response[2048];
static char m_result[32];

int dhcp_socketCallback(uint8_t *payload, int length, uint8_t **response, struct arpreq *client){
	struct dhcp_packet *request = (struct dhcp_packet *)payload;
	struct dhcp_packet *result  = (struct dhcp_packet *)m_response;
	struct dhcp_options *currentOption;
	struct dhcp_lease possibleLease, searchLease;
	uint8_t *requestedOptions;
	int idx, responseLength, optionsLength, reqOptLength, ipIsDefined;
	uint8_t responseMessageType;

	ipIsDefined = 0;
	// copy parts of request to response
	result->op = DHCP_PACKET_OP_RES;
	result->htype = request->htype;
	result->hlen = request->hlen;
	result->hops = request->hops;
	result->xid = request->xid;
	result->flags = 0;//htons(DHCP_BROADCAST_FLAG);
	result->cIAddr.s_addr = 0;
	result->yIAddr.s_addr = 0;
	result->sIAddr.s_addr = default_config.serverIP.s_addr;
	result->gIAddr.s_addr = 0;
	memcpy(result->chAddr, request->chAddr, 16+64+128); // copy the info from the client. not used
	result->magicCookie = request->magicCookie;
	result->options[0] = 0xFF; // no options for now!

	if(request->op == DHCP_PACKET_OP_REQ){
		// branch on DISCOVER or REQUEST
		config_log(CONFIG_LOG_DEBUG, "Received a DHCP request");
		optionsLength = (length - DHCP_PACKET_OVERHEAD);

		if((request->htype != DHCP_PACKET_HTYPE_ETH) || (request->hlen != 6)){
			// we don't know how to handle IPv6
			return 0;
		}

		// Define client HW address
		currentOption = dhcp_search_options(DHCP_OPTION_CLIENT_ID, request->options, optionsLength);
		if(currentOption && (currentOption->length == 7) && (currentOption->data[0] == 0x01)){
			memcpy(possibleLease.hwAddr, (currentOption->data + 1), 6);
		}else{
			// we couldn't find the MAC of the client use chAddr
			memcpy(possibleLease.hwAddr, request->chAddr, 6);
		}
		config_log(CONFIG_LOG_DEBUG, "Client MAC address is %s", dhcp_htoa(possibleLease.hwAddr));

		currentOption = dhcp_search_options(DHCP_OPTION_HOSTNAME, request->options, optionsLength);
		if(currentOption){
			// client sent us a hostname
			memcpy(possibleLease.hostname, currentOption->data, currentOption->length);
			possibleLease.hostname[currentOption->length] = '\0'; // terminate the string

			config_log(CONFIG_LOG_DEBUG, "Client hostname is '%s'", possibleLease.hostname);
		}else{
			// no hostname
			possibleLease.hostname[0] = '\0';
		}

		// no IP available, sorry, no apples for you!
		client->arp_flags = 0;
		currentOption = dhcp_search_options(DHCP_OPTION_OP, request->options, optionsLength);
		if(currentOption && (currentOption->data[0] == DHCP_OP_DISCOVER)){
			// discover, let's find an IP for you buddy
			if(db_searchStaticLease(&possibleLease, possibleLease.hwAddr) == DB_RESULTS_FOUND){
				config_log(CONFIG_LOG_NORMAL, "Found a static lease with IP %s", possibleLease.ipAddr);
				ipIsDefined = 1;
			}

			// check if we have a older lease for this client
			// TODO: renew and check lease time
			if(db_searchLease(&possibleLease, possibleLease.hwAddr) == DB_RESULTS_FOUND){
				config_log(CONFIG_LOG_NORMAL, "Found a old lease for %s with IP %s", dhcp_htoa(possibleLease.hwAddr), inet_ntoa(possibleLease.ipAddr));
				ipIsDefined = 1;
			}

			if(!ipIsDefined){
				// let's get a IP
				if(dhcp_get_available_lease(&(possibleLease.ipAddr)))
					ipIsDefined = 1;
				else
					ipIsDefined = 0;
			}

			if(!ipIsDefined){ // no IP , shhhh, say nothing
				config_log(CONFIG_LOG_WARNING, "No available leases for %s", dhcp_htoa(possibleLease.hwAddr));
				return 0;
			}else{
				config_log(CONFIG_LOG_NORMAL, "Found a new IP %s for %s", inet_ntoa(possibleLease.ipAddr), dhcp_htoa(possibleLease.hwAddr));
				responseMessageType = DHCP_OP_OFFER;
			}
		}else if(currentOption && (currentOption->data[0] == DHCP_OP_REQUEST)){
			// check if client is asking for an IP and if it's valid
			currentOption = dhcp_search_options(DHCP_OPTION_REQ, request->options, optionsLength);
			if(currentOption && !ipIsDefined){
				if(dhcp_is_valid_ip(((struct in_addr *)currentOption->data))){
					if(db_searchByIP(&searchLease, *((struct in_addr *)currentOption->data)) == DB_RESULTS_FOUND){
						if(dhcp_macMatch(searchLease.hwAddr, possibleLease.hwAddr)){
							memcpy(&possibleLease, &searchLease, sizeof(struct dhcp_lease));
							ipIsDefined = 1;
						}
					}else{
						possibleLease.ipAddr = *((struct in_addr *)currentOption->data);
						ipIsDefined = 1;
					}
				}
			}else{
				if(request->cIAddr.s_addr){
					if(dhcp_is_valid_ip(&request->cIAddr)){
						if(db_searchByIP(&searchLease, request->cIAddr) == DB_RESULTS_FOUND){
							if(dhcp_macMatch(searchLease.hwAddr, possibleLease.hwAddr)){
								memcpy(&possibleLease, &searchLease, sizeof(struct dhcp_lease));
								ipIsDefined = 1;
							}
						}
					}
				}
			}

			if(!ipIsDefined){ // no IP return a NACK
				config_log(CONFIG_LOG_WARNING, "Sending a NACK for %s, requesting for IP %s", dhcp_htoa(possibleLease.hwAddr), inet_ntoa(possibleLease.ipAddr));
				responseMessageType = DHCP_OP_NACK;
			}else{
				config_log(CONFIG_LOG_NORMAL, "Confirming IP %s for %s", inet_ntoa(possibleLease.ipAddr), dhcp_htoa(possibleLease.hwAddr));
				responseMessageType = DHCP_OP_ACK;
				// add this sucker to the lease table
				db_addLease(&possibleLease);
				client->arp_flags = ATF_PERM;
			}
		}else{
			config_log(CONFIG_LOG_WARNING, "Unknown DHCP request, ID: %d", currentOption->data[0]);
			return 0; // we don't know what you're doing
		}

		// parse the options to the return packet
		result->yIAddr.s_addr = possibleLease.ipAddr.s_addr;
		responseLength = DHCP_PACKET_OVERHEAD;

		// check for options we will send
		currentOption = dhcp_search_options(DHCP_OPTION_PARAMS, request->options, optionsLength);
		if(currentOption){
			requestedOptions = currentOption->data;
			reqOptLength = currentOption->length;

			currentOption = (struct dhcp_options *)result->options;
			currentOption = dhcp_get_option_value(DHCP_OPTION_OP, currentOption, &optionsLength, 1, responseMessageType);
			responseLength += optionsLength;

			ipIsDefined = 0; // let's use this variable again! SO? GOT PROBLEM?
			for(idx = 0; idx < reqOptLength; idx++){
				switch(requestedOptions[idx]){
					case DHCP_OPTION_HOSTNAME:
						currentOption = dhcp_get_option_value(DHCP_OPTION_HOSTNAME, currentOption, &optionsLength, 1, possibleLease.hostname);
						break;
					case DHCP_OPTION_REQ:
						currentOption = dhcp_get_option_value(DHCP_OPTION_REQ, currentOption, &optionsLength, 1, &possibleLease.ipAddr);
						break;
					case DHCP_OPTION_DEFAULT_TTL:
						ipIsDefined |= DHCP_OPT_MAND_TTL;
					case DHCP_OPTION_LEASE_TIME:
						ipIsDefined |= DHCP_OPT_MAND_LEASE_TIME;
					case DHCP_OPTION_RENEWAL:
						ipIsDefined |= DHCP_OPT_MAND_RENEWAL;
					case DHCP_OPTION_REBINDING:
						ipIsDefined |= DHCP_OPT_MAND_REBINDING;
					default:
						currentOption = dhcp_get_option_value(requestedOptions[idx], currentOption, &optionsLength, 0);
				}
				responseLength += optionsLength;
			}

			if(!(ipIsDefined & DHCP_OPT_MAND_TTL)){
				currentOption = dhcp_get_option_value(DHCP_OPTION_DEFAULT_TTL, currentOption, &optionsLength, 0);
				responseLength += optionsLength;
			}
			if(!(ipIsDefined & DHCP_OPT_MAND_LEASE_TIME)){
				currentOption = dhcp_get_option_value(DHCP_OPTION_LEASE_TIME, currentOption, &optionsLength, 0);
				responseLength += optionsLength;
			}
			if(!(ipIsDefined & DHCP_OPT_MAND_RENEWAL)){
				currentOption = dhcp_get_option_value(DHCP_OPTION_RENEWAL, currentOption, &optionsLength, 0);
				responseLength += optionsLength;
			}
			if(!(ipIsDefined & DHCP_OPT_MAND_REBINDING)){
				currentOption = dhcp_get_option_value(DHCP_OPTION_REBINDING, currentOption, &optionsLength, 0);
				responseLength += optionsLength;
			}
		}else{
			// send the default configs
			currentOption = (struct dhcp_options *)result->options;

			currentOption = dhcp_get_option_value(DHCP_OPTION_OP, currentOption, &optionsLength, 1, responseMessageType);
			responseLength += optionsLength;

			currentOption = dhcp_get_option_value(DHCP_OPTION_HOSTNAME, currentOption, &optionsLength, 1, possibleLease.hostname);
			responseLength += optionsLength;

			currentOption = dhcp_get_option_value(DHCP_OPTION_SUBNET_MASK, currentOption, &optionsLength, 0);
			responseLength += optionsLength;

			currentOption = dhcp_get_option_value(DHCP_OPTION_ROUTER, currentOption, &optionsLength, 0);
			responseLength += optionsLength;

			currentOption = dhcp_get_option_value(DHCP_OPTION_LEASE_TIME, currentOption, &optionsLength, 0);
			responseLength += optionsLength;

			currentOption = dhcp_get_option_value(DHCP_OPTION_SERVER_ID, currentOption, &optionsLength, 0);
			responseLength += optionsLength;

			currentOption = dhcp_get_option_value(DHCP_OPTION_DNS_SERVER, currentOption, &optionsLength, 0);
			responseLength += optionsLength;

			currentOption = dhcp_get_option_value(DHCP_OPTION_DEFAULT_TTL, currentOption, &optionsLength, 0);
			responseLength += optionsLength;

			currentOption = dhcp_get_option_value(DHCP_OPTION_RENEWAL, currentOption, &optionsLength, 0);
			responseLength += optionsLength;

			currentOption = dhcp_get_option_value(DHCP_OPTION_REBINDING, currentOption, &optionsLength, 0);
			responseLength += optionsLength;
		}

		// terminate the options
		currentOption->op = DHCP_OPTION_END;
		responseLength++;

		struct sockaddr_in *si;
		si = (struct sockaddr_in *)&(client->arp_pa);
		si->sin_family = AF_INET;
		si->sin_addr.s_addr = result->yIAddr.s_addr;
		client->arp_ha.sa_family = ARPHRD_ETHER;
		memcpy(client->arp_ha.sa_data, possibleLease.hwAddr, 6);

		*response = m_response;
		return responseLength;
	}else{
		// we only respond to requests
		return 0;
	}
}

int dhcp_macMatch(uint8_t *a, uint8_t *b){
	int idx;

	for(idx = 0; idx < 6; idx++){
		if(a[idx] != b[idx])
			return 0;
	}

	return 1; // they MATCH
}

int dhcp_init(char *configFile){
	int ret = 0;

	// get config info
	ret = config_loadFromFile(configFile, &default_config);
	if(ret)
		return ret;
	config_log(CONFIG_LOG_NORMAL, "Loaded DHCP server configuration");

	m_keepRunning = 1;
	ret = pthread_create(&m_dhcpHandler, NULL, dhcp_monitorThread, (void *)&m_keepRunning);
	if(ret){
		return ret;
	}

	config_log(CONFIG_LOG_DEBUG, "DHCP thread created!");
	return 0;
}

int dhcp_end(void){
	free(default_config.routers);
	free(default_config.dns);

	// end monitor thread
	m_keepRunning = 0;
	pthread_mutex_unlock(&m_dhcpWait);
	pthread_join(m_dhcpHandler, NULL);

	config_log(CONFIG_LOG_NORMAL, "Closing DHCP server");
	return 0;
}

char *dhcp_htoa(uint8_t *hwAddr){
	sprintf(m_result, "%02X:%02X:%02X:%02X:%02X:%02X", hwAddr[0], hwAddr[1], hwAddr[2], hwAddr[3], hwAddr[4], hwAddr[5]);
	return m_result;
}

static int dhcp_get_available_lease(struct in_addr *lease){
	uint32_t nextLease = default_config.initialRange;
	struct in_addr invertMask = {.s_addr = ~(default_config.netmask.s_addr)};
	struct dhcp_lease *currentLeases;
	struct dhcp_lease *staticLeases;
	int lCount, sCount, isFree;

	currentLeases = db_getLeases(&lCount);
	staticLeases = db_getStaticLeases(&sCount);

	// this may not be reach if the MAC has a static lease
	do{
		if(nextLease > default_config.endRange)
			return 0;

		lease->s_addr = (ntohl(nextLease) & invertMask.s_addr) | default_config.subnet.s_addr;
		isFree = db_containsLease(*lease, currentLeases, lCount);
		if(isFree == DB_RESULTS_FOUND){
			nextLease++;
			continue;
		}

		isFree = db_containsLease(*lease, staticLeases, sCount);
		nextLease++;
	}while(isFree == DB_RESULTS_FOUND);

	// next lease is found and free
	return 1;
}

static struct dhcp_options *dhcp_search_options(uint8_t option, uint8_t *where, int length){
	struct dhcp_options *currentOp = (struct dhcp_options *)where;

	while(currentOp->op != 0xFF){
		if(currentOp->op == option)
			return currentOp;

		currentOp = (struct dhcp_options *)((uint8_t *)currentOp + (currentOp->length + 2));
		if((uint8_t *)currentOp > (where + length))
			return NULL;
	}
	// option was not present
	return NULL;
}

static struct dhcp_options *dhcp_get_option_value(uint8_t option, struct dhcp_options *op ,int *opLength, int args, ...){
	struct in_addr *helper = NULL;
	char *aString;
	va_list list;
	int idx;

	if(args > 0)
		va_start(list, args);

	*opLength = 0;
	op->length = 0; // will force invalid option in case of fallthrough
	switch(option){
		case DHCP_OPTION_SUBNET_MASK:
			op->op = DHCP_OPTION_SUBNET_MASK;
			op->length = sizeof(struct in_addr);
			((struct in_addr *)op->data)->s_addr = default_config.netmask.s_addr;
			break;
		case DHCP_OPTION_ROUTER:
			op->op = DHCP_OPTION_ROUTER;
			op->length = 0;
			helper = default_config.routers;
			if(helper->s_addr){
				idx = 0;
				while(helper->s_addr){
					op->length += sizeof(struct in_addr);
					((struct in_addr *)op->data)[idx].s_addr = helper->s_addr;

					idx++;
					helper += sizeof(struct in_addr);
				}
			}else{
				// no default router, use us!
				op->length = sizeof(struct in_addr);
				((struct in_addr *)op->data)->s_addr = default_config.serverIP.s_addr;
			}
			break;
		case DHCP_OPTION_HOSTNAME:
			if(args > 0){
				aString = va_arg(list, char *);
				if(aString[0] == '\0')
					break; // empty string, skip

				op->op = DHCP_OPTION_HOSTNAME;
				op->length = strlen(aString);
				strcpy((char *)op->data, aString);
			}
			break;
		case DHCP_OPTION_DOMAIN_NAME:
			if(default_config.domainName){
				op->op = DHCP_OPTION_DOMAIN_NAME;
				op->length = strlen(default_config.domainName);
				strcpy((char *)op->data, default_config.domainName);
			}
			break;
		case DHCP_OPTION_DNS_SERVER:
			op->op = DHCP_OPTION_DNS_SERVER;
			op->length = 0;
			helper = default_config.dns;

			idx = 0;
			if(helper->s_addr){

				idx = 0;
				while(helper->s_addr){
					op->length += sizeof(struct in_addr);
					((struct in_addr *)op->data)[idx].s_addr = helper->s_addr;

					idx++;
					helper += sizeof(struct in_addr);
				}
			}else{
				// no default dns, use us!
				op->length = sizeof(struct in_addr);
				((struct in_addr *)op->data)->s_addr = default_config.serverIP.s_addr;
			}
			break;
		case DHCP_OPTION_TIME_OFFSET:
			op->op = DHCP_OPTION_TIME_OFFSET;
			op->length = 4;
			*((int32_t *)op->data) = ntohl(default_config.timezone);
			break;
		// case DHCP_OPTION_INTERFACE_MTU: // let's wait for this one!
		case DHCP_OPTION_BROADCAST_ADDR:
			op->op = DHCP_OPTION_BROADCAST_ADDR;
			op->length = sizeof(struct in_addr);
			((struct in_addr *)op->data)->s_addr = ((default_config.subnet.s_addr & default_config.netmask.s_addr) | (~default_config.netmask.s_addr));
		break;
		case DHCP_OPTION_SERVER_ID:
			// that's us :)
			op->op = DHCP_OPTION_SERVER_ID;
			op->length = sizeof(struct in_addr);
			((struct in_addr *)op->data)->s_addr = default_config.serverIP.s_addr;
		break;
		case DHCP_OPTION_LEASE_TIME:
			op->op = DHCP_OPTION_LEASE_TIME;
			op->length = 4;
			*((uint32_t *)op->data) = ntohl(3600U);//ntohl(default_config.leaseTime);
			break;
		case DHCP_OPTION_OP:
			if(args > 0){
				op->op = DHCP_OPTION_OP;
				op->length = 1;
				*((uint8_t *)op->data) = (uint8_t)va_arg(list, int);
			}
			break;
		case DHCP_OPTION_DEFAULT_TTL:
			op->op = DHCP_OPTION_DEFAULT_TTL;
			op->length = 1;
			op->data[0] = 64;
			break;
		case DHCP_OPTION_RENEWAL:
			op->op = DHCP_OPTION_RENEWAL;
			op->length = 4;
			*((uint32_t *)op->data) = ntohl(1800U);
			break;
		case DHCP_OPTION_REBINDING:
			op->op = DHCP_OPTION_REBINDING;
			op->length = 4;
			*((uint32_t *)op->data) = ntohl(1800U);
			break;
	}

	if(args > 0)
		va_end(list);

	if(op->length > 0){
		*opLength = op->length + 2;
		op = (struct dhcp_options *)((uint8_t *)op + (op->length + 2));
	}else{
		*opLength = 0;
	}

	return op;
}

static int dhcp_is_valid_ip(struct in_addr *ip){
	if((ip->s_addr & default_config.netmask.s_addr) == (default_config.subnet.s_addr & default_config.netmask.s_addr))
		return 1;	// this IP is within the subnet
	else
		return 0;
}

static void *dhcp_monitorThread(void *arguments){
	uint8_t *keepRunning = (uint8_t *)arguments;
	struct timespec timeout;

	while(*keepRunning){
		clock_gettime(CLOCK_REALTIME, &timeout);
		timeout.tv_sec += 60;

		pthread_mutex_timedlock(&m_dhcpWait, &timeout);
		db_deleteOlderThan(default_config.leaseTime);
	}

	pthread_exit(NULL);
}
