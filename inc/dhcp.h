#ifndef _INC_DHCP_H_
#define _INC_DHCP_H_

#define DHCP_OPTION_SUBNET_MASK			1U
#define DHCP_OPTION_TIME_OFFSET			2U
#define DHCP_OPTION_ROUTER					3U
#define DHCP_OPTION_TIME_SERVER			4U
#define DHCP_OPTION_NAME_SERVER			5U
#define DHCP_OPTION_DNS_SERVER			6U
#define DHCP_OPTION_LOG_SERVER			7U
#define DHCP_OPTION_COOKIE_SERVER		8U
#define DHCP_OPTION_LPR_SERVER			9U
#define DHCP_OPTION_IMPRESS_SERVER	10U
#define DHCP_OPTION_RLS							11U
#define DHCP_OPTION_HOSTNAME				12U
#define DHCP_OPTION_BOOTP_SIZE			13U
#define DHCP_OPTION_MERIT_DUMP_FILE	14U
#define DHCP_OPTION_DOMAIN_NAME			15U
#define DHCP_OPTION_SWAP_SERVER			16U
#define DHCP_OPTION_ROOT_PATH				17U
#define DHCP_OPTION_EXT_PATH				18U
#define DHCP_OPTION_DEFAULT_TTL			23U
#define DHCP_OPTION_INTERFACE_MTU		26U
#define DHCP_OPTION_BROADCAST_ADDR	28U
#define DHCP_OPTION_STATIC_ROUTE		33U
#define DHCP_OPTION_NIS_DOMAIN			40U
#define DHCP_OPTION_NIS_SERVER			41U
#define DHCP_OPTION_NTP_SERVER			42U
#define DHCP_OPTION_REQ							50U
#define DHCP_OPTION_LEASE_TIME			51U
#define DHCP_OPTION_OP							53U
#define DHCP_OPTION_SERVER_ID				54U
#define DHCP_OPTION_PARAMS					55U
#define DHCP_OPTION_MAX_SIZE				57U
#define DHCP_OPTION_RENEWAL					58U
#define DHCP_OPTION_REBINDING				59U
#define DHCP_OPTION_CLIENT_ID				61U
#define DHCP_OPTION_DOMAIN_SEARCH		119U
#define DHCP_OPTION_CLASSNET_STATIC	121u
#define DHCP_OPTION_P_STATIC_ROUTER	249U
#define DHCP_OPTION_AUTODISCOVERY		252U
#define DHCP_OPTION_END							255U

#define DHCP_REQ_NONE								0
#define DHCP_REQ_DISCOVER						1
#define DHCP_REQ_OFFER							2
#define DHCP_REQ_REQUEST						3
#define DHCP_REQ_DECLINE						4
#define DHCP_REQ_ACK								5
#define DHCP_REQ_NACK								6
#define DHCP_REQ_RELEASE						7
#define DHCP_REQ_INFORM							8

#include <netinet/in.h>
#include <stdint.h>

#include "socket.h"

struct dhcp_lease{
	struct in_addr ipAddr;
	uint8_t hwAddr[6];
	char hostname[64];
	uint64_t leaseTimestamp;
};

struct dhcp_options{
	uint8_t op;
	uint8_t length;
	uint8_t data[];
};

struct dhcp_packet{
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	struct in_addr cIAddr;
	struct in_addr yIAddr;
	struct in_addr sIAddr;
	struct in_addr gIAddr;
	uint8_t chAddr[16];
	char sname[64];
	char file[128];
	uint32_t magicCookie;
	uint8_t options[256];
};

struct dhcp_server_config{
	char *interface;
	struct in_addr serverIP;
	struct in_addr netmask;
	struct in_addr subnet;
	struct in_addr *routers;
	struct in_addr *dns;
	char *domainName;
	uint32_t initialRange;
	uint32_t endRange;

	int32_t timezone; // offset in seconds from GMT
	uint16_t mtu;

	uint32_t leaseTime;
	uint32_t bindindTime;
};

int dhcp_socketCallback(uint8_t *payload, int length, uint8_t **response, struct arpreq *client);
int dhcp_macMatch(uint8_t *a, uint8_t *b);
int dhcp_init(char *configFile);
int dhcp_end(void);
char *dhcp_htoa(uint8_t *hwAddr);
char *dhcp_strreq(uint8_t req);

struct dhcp_options *dhcp_search_options(uint8_t option, uint8_t *where, int length);

#endif // _INC_DHCP_H_
