#ifndef _INC_DHCP_H_
#define _INC_DHCP_H_

#include <netinet/in.h>
#include <stdint.h>

struct dhcp_lease{
	struct in_addr ipAddr;
	uint8_t hwAddr[6];
	char hostname[64];
	uint64_t leaseTimestamp;
};

struct dhcp_options{
	uint8_t op;
	uint8_t length;
	uint8_t *data;
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
	uint8_t *options;
};

int dhcp_socketCallback(uint8_t *payload, int length, uint8_t *response);

#endif // _INC_DHCP_H_
