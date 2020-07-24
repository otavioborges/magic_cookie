#define DHCP_PACKET_OVERHEAD	236

#define DHCP_OP_DISCOVER			1
#define DHCP_OP_OFFER					2
#define DHCP_OP_REQUEST				3
#define DHCP_OP_ACK						5
#define DHCP_OP_NACK					6

#define DHCP_PACKET_OP_REQ		1
#define DHCP_PACKET_OP_RES		2

#define DHCP_PACKET_HTYPE_ETH	1

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "dhcp.h"
#include "database.h"

struct dhcp_server_config{
	struct in_addr serverIP;
	uint8_t serverHw[6];
	struct in_addr netmask;
	struct in_addr subnet;
	struct in_addr *routers;
	struct in_addr *dns;
	char *domainName;
	uint32_t leaseTime;
	uint32_t initialRange;
	uint32_t endRange;

	int32_t timezone; // offset in seconds from GMT
	uint16_t mtu;
};

static struct dhcp_options *parsed_options[128];
static struct dhcp_server_config default_config;

static int dhcp_get_available_lease(struct in_addr *lease);
static struct dhcp_options *dhcp_search_options(uint8_t option, uint8_t *where, int length);
// use after lease is done!
static struct dhcp_options *dhcp_get_option_value(uint8_t option, struct dhcp_options *op, int *opLength, int args, ...);
static int dhcp_is_valid_ip(struct in_addr *ip);

static uint8_t m_response[2048];

int dhcp_socketCallback(uint8_t *payload, int length, uint8_t **response){
	struct dhcp_packet *request = (struct dhcp_packet *)payload;
	struct dhcp_packet *result  = (struct dhcp_packet *)m_response;
	struct dhcp_options *currentOption;
	struct dhcp_lease possibleLease;
	uint8_t *requestedOptions;
	int idx, responseLength, optionsLength, reqOptLength, ipIsDefined;

	ipIsDefined = 0;
	// copy parts of request to response
	result->op = DHCP_PACKET_OP_RES;
	result->htype = request->htype;
	result->hlen = request->hlen;
	result->hops = request->hops+1;
	result->xid = request->xid;
	result->flags = request->flags;
	result->cIAddr.s_addr = 0;
	result->yIAddr.s_addr = 0;
	result->sIAddr.s_addr = ntohl(default_config.serverIP.s_addr);
	result->gIAddr.s_addr = ntohl(default_config.serverIP.s_addr);
	memcpy(result->chAddr, request->chAddr, 16+64+128); // copy the info from the client. not used
	result->magicCookie = request->magicCookie;
	result->options[0] = 0xFF; // no options for now!

	if(request->op == DHCP_PACKET_OP_REQ){
		// branch on DISCOVER or REQUEST
		optionsLength = (length - DHCP_PACKET_OVERHEAD);

		currentOption = dhcp_search_options(DHCP_OPTION_OP, request->options, optionsLength);
		if(currentOption && (currentOption->data[0] == DHCP_OP_DISCOVER)){
			// discover, let's find an IP for you buddy
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

			// check if we have a static lease for this client
			if(db_searchStaticLease(&possibleLease, possibleLease.hwAddr) == DB_RESULTS_FOUND)
				ipIsDefined = 1;

			// check if we have a older lease for this client
			// TODO: renew and check lease time
			if(db_searchLease(&possibleLease, possibleLease.hwAddr) == DB_RESULTS_FOUND)
				ipIsDefined = 1;

			// check if client is asking for an IP and if it's valid
			currentOption = dhcp_search_options(DHCP_OPTION_REQ, request->options, optionsLength);
			if(currentOption && !ipIsDefined){
				if(dhcp_is_valid_ip(((struct in_addr *)currentOption->data))){
					if(db_searchByIP(&possibleLease, *((struct in_addr *)currentOption->data)) == DB_RESULTS_NONE)
						ipIsDefined = 1;
				}
			}

			if(!ipIsDefined){
				// let's get a IP
				if(dhcp_get_available_lease(&(possibleLease.ipAddr)))
					ipIsDefined = 1;
				else
					ipIsDefined = 0;
			}

			// no IP available, sorry, no apples for you!
			if(!ipIsDefined)
				return 0;

			currentOption = dhcp_search_options(DHCP_OPTION_HOSTNAME, request->options, optionsLength);
			if(currentOption){
				// client sent us a hostname
				memcpy(possibleLease.hostname, currentOption->data, currentOption->length);
				possibleLease.hostname[currentOption->length] = '\0'; // terminate the string
			}else{
				// no hostname
				possibleLease.hostname[0] = '\0';
			}

			// TODO: define a real timestamp
			possibleLease.leaseTimestamp = 0;

			// parse the options to the return packet
			result->yIAddr.s_addr = ntohl(possibleLease.ipAddr.s_addr);
			responseLength = DHCP_PACKET_OVERHEAD;

			// check for options we will send
			currentOption = dhcp_search_options(DHCP_OPTION_PARAMS, request->options, optionsLength);
			if(currentOption){
				requestedOptions = currentOption->data;
				reqOptLength = currentOption->length;

				currentOption = (struct dhcp_options *)result->options;
				currentOption = dhcp_get_option_value(DHCP_OPTION_OP, currentOption, &optionsLength, 1, DHCP_OP_OFFER);
				responseLength += optionsLength;

				ipIsDefined = 0; // let's use this variable again! SO? GOT PROBLEM?
				for(idx = 0; idx < reqOptLength; idx++){
					switch(requestedOptions[idx]){
						case DHCP_OPTION_HOSTNAME:
							currentOption = dhcp_get_option_value(DHCP_OPTION_HOSTNAME, currentOption, &optionsLength, 1, possibleLease.hostname);
							break;
						case DHCP_OPTION_REQ:
							currentOption = dhcp_get_option_value(DHCP_OPTION_REQ, currentOption, &optionsLength, 1, &possibleLease.ipAddr);
							ipIsDefined = 1;
							break;
						default:
							currentOption = dhcp_get_option_value(requestedOptions[idx], currentOption, &optionsLength, 0);
					}
					responseLength += optionsLength;
				}

				if(!ipIsDefined){
					currentOption = dhcp_get_option_value(DHCP_OPTION_REQ, currentOption, &optionsLength, 1, &possibleLease.ipAddr);
					responseLength += optionsLength;
				}
			}else{
				// send the default configs
				currentOption = (struct dhcp_options *)result->options;

				currentOption = dhcp_get_option_value(DHCP_OPTION_OP, currentOption, &optionsLength, 1, DHCP_OP_OFFER);
				responseLength += optionsLength;

				currentOption = dhcp_get_option_value(DHCP_OPTION_REQ, currentOption, &optionsLength, 1, &possibleLease.ipAddr);
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
			}

			// terminate the options
			currentOption->op = DHCP_OPTION_END;
			responseLength++;

			*response = m_response;
			return responseLength;
		}else if(currentOption && (currentOption->data[0] == DHCP_OP_REQUEST)){
			// request, can you have this IP?
		}else{
			return 0; // we don't recognize that operation
		}
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

int dhcp_init(void){
	default_config.routers = (struct in_addr *)malloc((sizeof(struct in_addr) * 2));
	default_config.dns = (struct in_addr *)malloc((sizeof(struct in_addr) * 2));

	default_config.serverIP.s_addr		= 0x01000b0a;

	default_config.serverHw[0]				= 0x00;
	default_config.serverHw[1]				= 0x01;
	default_config.serverHw[2]				= 0x73;
	default_config.serverHw[3]				= 0x00;
	default_config.serverHw[4]				= 0x00;
	default_config.serverHw[5]				= 0x02;

	default_config.netmask.s_addr 		= 0x00FFFFFF;
	default_config.subnet.s_addr			= 0x00000b0a;

	default_config.routers[0].s_addr	= 0x01000b0a;
	default_config.routers[1].s_addr	= 0;

	default_config.dns[0].s_addr			= 0x08080808;
	default_config.dns[1].s_addr			= 0;

	default_config.domainName					= "oleivas.com.br";
	default_config.leaseTime					= 86400;
	default_config.initialRange				= 10;
	default_config.endRange						= 200;
	default_config.timezone						= -23200;
	default_config.mtu								= 0;
}

int dhcp_end(void){
	free(default_config.routers);
	free(default_config.dns);
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

		lease->s_addr = ((ntohl(nextLease) & invertMask.s_addr) | default_config.subnet.s_addr);
		isFree = db_containsLease(*lease, currentLeases, lCount);
		if(isFree == DB_RESULTS_FOUND)
			continue;

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
			((struct in_addr *)op->data)->s_addr = ntohl(default_config.subnet.s_addr);
			break;
		case DHCP_OPTION_ROUTER:
			op->op = DHCP_OPTION_ROUTER;
			op->length = 0;
			helper = default_config.routers;
			if(helper->s_addr){
				idx = 0;
				while(helper->s_addr){
					op->length += sizeof(struct in_addr);
					((struct in_addr *)op->data)[idx].s_addr = ntohl(helper->s_addr);

					idx++;
					helper += sizeof(struct in_addr);
				}
			}else{
				// no default router, use us!
				op->length = sizeof(struct in_addr);
				((struct in_addr *)op->data)->s_addr = ntohl(default_config.serverIP.s_addr);
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
					((struct in_addr *)op->data)[idx].s_addr = ntohl(helper->s_addr);

					idx++;
					helper += sizeof(struct in_addr);
				}
			}else{
				// no default dns, use us!
				op->length = sizeof(struct in_addr);
				((struct in_addr *)op->data)->s_addr = ntohl(default_config.serverIP.s_addr);
			}
			break;
		case DHCP_OPTION_TIME_OFFSET:
			op->op = DHCP_OPTION_TIME_OFFSET;
			op->length = 4;
			*((int32_t *)op->data) = default_config.timezone;
			break;
		// case DHCP_OPTION_INTERFACE_MTU: // let's wait for this one!
		case DHCP_OPTION_BROADCAST_ADDR:
			op->op = DHCP_OPTION_BROADCAST_ADDR;
			op->length = sizeof(struct in_addr);
			((struct in_addr *)op->data)->s_addr = ntohl((default_config.subnet.s_addr & default_config.netmask.s_addr) | (~default_config.netmask.s_addr));
		break;
		case DHCP_OPTION_SERVER_ID:
			// that's us :)
			op->op = DHCP_OPTION_SERVER_ID;
			op->length = sizeof(struct in_addr);
			((struct in_addr *)op->data)->s_addr = ntohl(default_config.serverIP.s_addr);
		break;
		case DHCP_OPTION_LEASE_TIME:
			op->op = DHCP_OPTION_LEASE_TIME;
			op->length = 4;
			*((uint32_t *)op->data) = default_config.leaseTime;
			break;
		case DHCP_OPTION_OP:
			if(args > 0){
				op->op = DHCP_OPTION_OP;
				op->length = 1;
				*((uint8_t *)op->data) = (uint8_t)va_arg(list, int);
			}
			break;
		case DHCP_OPTION_REQ:
			if(args > 0){
				op->op = DHCP_OPTION_REQ;
				op->length = sizeof(struct in_addr);

				helper = va_arg(list, struct in_addr *);
				((struct in_addr *)op->data)->s_addr = helper->s_addr;
			}
			break;
	}

	if(args > 0)
		va_end(list);

	if(op->length > 0)
		op = (struct dhcp_options *)((uint8_t *)op + (op->length + 2));

	*opLength = op->length + 2;
	return op;
}

static int dhcp_is_valid_ip(struct in_addr *ip){
	if((ip->s_addr & default_config.netmask.s_addr) == (default_config.subnet.s_addr & default_config.netmask.s_addr))
		return 1;	// this IP is within the subnet
	else
		return 0;
}
