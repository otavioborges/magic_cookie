#ifndef _INC_DATABASE_H_
#define _INC_DATABASE_H_

#define DB_RESULTS_NONE			0
#define DB_RESULTS_FOUND		1
#define DB_RESULTS_ADDED		2
#define DB_RESULTS_REMOVED	3
#define DB_RESULTS_EXISTS		4

#include "dhcp.h"

struct dhcp_lease *db_getLeases(int *count);
struct dhcp_lease *db_getStaticLeases(int *count);

int db_searchLease(struct dhcp_lease *result, uint8_t *hwAddr);
int db_searchStaticLease(struct dhcp_lease *result, uint8_t *hwAddr);

int db_addLease(struct dhcp_lease *lease);
int db_addStaticLease(struct dhcp_lease lease);

int db_removeLease(uint8_t *hwAddr);
int db_removeStaticLease(uint8_t *hwAddr);

int db_containsLease(struct in_addr ip, struct dhcp_lease *list, int count);
int db_searchByIP(struct dhcp_lease *result, struct in_addr ip, uint8_t includeStatic);

int db_updateLeaseTime(uint8_t *hw);
int db_deleteOlderThan(uint32_t seconds);

#endif // _INC_DATABASE_H_
