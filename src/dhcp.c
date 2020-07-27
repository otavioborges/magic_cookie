#define DHCP_PACKET_OVERHEAD	240

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
#include "parser.h"

static struct dhcp_options *parsed_options[128];
static struct dhcp_server_config default_config;
static uint8_t m_keepRunning = 1;
static pthread_t m_dhcpHandler = 0;
static pthread_mutex_t m_dhcpWait = PTHREAD_MUTEX_INITIALIZER;

static struct dhcp_options *dhcp_get_option_value(uint8_t option, struct dhcp_options *op, int *opLength, int args, ...);
static void *dhcp_monitorThread(void *arguments);

static uint8_t m_response[2048];
static char m_result[32];

int dhcp_socketCallback(uint8_t *payload, int length, uint8_t **response, struct arpreq *client){
	struct dhcp_packet *request = (struct dhcp_packet *)payload;
	struct dhcp_packet *result  = (struct dhcp_packet *)m_response;
	int optionsLength, responseLength, flags, reqOptLength, idx;
	struct dhcp_options *currentOption;
	struct dhcp_lease possibleLease;
	uint8_t *requestedOptions;
	uint8_t responseMessageType;

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

		if((request->htype != DHCP_PACKET_HTYPE_ETH) || (request->hlen != 6)){
			// we don't know how to handle IPv6
			config_log(CONFIG_LOG_WARNING, "Client has an unknown hardware address. Type: %d, length: %d", request->htype, request->hlen);
			return 0;
		}

		client->arp_flags = 0;
		optionsLength = (length - DHCP_PACKET_OVERHEAD);
		responseMessageType = parser_manageLease(&possibleLease, request, default_config, optionsLength);
		if(responseMessageType != DHCP_REQ_NONE){
			if(responseMessageType == DHCP_REQ_ACK)
				client->arp_flags = ATF_PERM;

			config_log(CONFIG_LOG_NORMAL, "Replying client %s with type '%s', client IP is %s", dhcp_htoa(possibleLease.hwAddr), dhcp_strreq(responseMessageType),
				inet_ntoa(possibleLease.ipAddr));

			// parse the options to the return packet
			result->yIAddr.s_addr = possibleLease.ipAddr.s_addr;
			responseLength = DHCP_PACKET_OVERHEAD;

			currentOption = (struct dhcp_options *)result->options;
			currentOption = dhcp_get_option_value(DHCP_OPTION_OP, currentOption, &optionsLength, 1, responseMessageType);
			responseLength += optionsLength;

			optionsLength = (length - DHCP_PACKET_OVERHEAD);
			currentOption = dhcp_search_options(DHCP_OPTION_PARAMS, request->options, optionsLength);
			if(currentOption){
				requestedOptions = currentOption->data;
				reqOptLength = currentOption->length;

				flags = 0; // let's use this variable again! SO? GOT PROBLEM?
				for(idx = 0; idx < reqOptLength; idx++){
					switch(requestedOptions[idx]){
						case DHCP_OPTION_HOSTNAME:
							currentOption = dhcp_get_option_value(DHCP_OPTION_HOSTNAME, currentOption, &optionsLength, 1, possibleLease.hostname);
							break;
						case DHCP_OPTION_REQ:
							currentOption = dhcp_get_option_value(DHCP_OPTION_REQ, currentOption, &optionsLength, 1, &possibleLease.ipAddr);
							break;
						case DHCP_OPTION_DEFAULT_TTL:
							flags |= DHCP_OPT_MAND_TTL;
						case DHCP_OPTION_LEASE_TIME:
							flags |= DHCP_OPT_MAND_LEASE_TIME;
						case DHCP_OPTION_RENEWAL:
							flags |= DHCP_OPT_MAND_RENEWAL;
						case DHCP_OPTION_REBINDING:
							flags |= DHCP_OPT_MAND_REBINDING;
						default:
							currentOption = dhcp_get_option_value(requestedOptions[idx], currentOption, &optionsLength, 0);
					}
					responseLength += optionsLength;
				}

				if(!(flags & DHCP_OPT_MAND_TTL)){
					currentOption = dhcp_get_option_value(DHCP_OPTION_DEFAULT_TTL, currentOption, &optionsLength, 0);
					responseLength += optionsLength;
				}
				if(!(flags & DHCP_OPT_MAND_LEASE_TIME)){
					currentOption = dhcp_get_option_value(DHCP_OPTION_LEASE_TIME, currentOption, &optionsLength, 0);
					responseLength += optionsLength;
				}
				if(!(flags & DHCP_OPT_MAND_RENEWAL)){
					currentOption = dhcp_get_option_value(DHCP_OPTION_RENEWAL, currentOption, &optionsLength, 0);
					responseLength += optionsLength;
				}
				if(!(flags & DHCP_OPT_MAND_REBINDING)){
					currentOption = dhcp_get_option_value(DHCP_OPTION_REBINDING, currentOption, &optionsLength, 0);
					responseLength += optionsLength;
				}
			}else{ // DHCP_OPTION_PARAMS is not defined!
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
		}else{ // parser didn't send a DHCP requisition code
			return 0; // parser could not handle the request, reply nothing
		}
	}

	// not a request, we only serve
	return 0;
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

char *dhcp_strreq(uint8_t req){
	switch(req){
		case DHCP_REQ_NONE:
			strcpy(m_result, "NONE");
			break;
		case DHCP_REQ_DISCOVER:
			strcpy(m_result, "DISCOVER");
			break;
		case DHCP_REQ_OFFER:
			strcpy(m_result, "OFFER");
			break;
		case DHCP_REQ_REQUEST:
			strcpy(m_result, "REQUEST");
			break;
		case DHCP_REQ_DECLINE:
			strcpy(m_result, "DECLINE");
			break;
		case DHCP_REQ_ACK:
			strcpy(m_result, "ACK");
			break;
		case DHCP_REQ_NACK:
			strcpy(m_result, "NACK");
			break;
		case DHCP_REQ_RELEASE:
			strcpy(m_result, "RELEASE");
			break;
		case DHCP_REQ_INFORM:
			strcpy(m_result, "INFORM");
			break;
		default:
			strcpy(m_result, "UNKNOWN");
	}
}

struct dhcp_options *dhcp_search_options(uint8_t option, uint8_t *where, int length){
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
