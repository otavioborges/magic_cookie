#define DHCP_FIXED_COL_ID						0
#define DHCP_FIXED_COL_IP						1
#define DHCP_FIXED_COL_HW						2

#define DHCP_RELEASES_COL_ID				0
#define DHCP_RELEASES_COL_IP				1
#define DHCP_RELEASES_COL_HOSTNAME	2
#define DHCP_RELEASES_COL_STATUS		3
#define DHCP_RELEASES_COL_HW				4
#define DHCP_RELEASES_COL_TIME			5

#define DHCP_OPTIONS_OFFSET					236

#define ntohll(x)	((((uint64_t)x >> 56) & 0xFF) | (((uint64_t)x >> 40) & 0xFF00) | (((uint64_t)x >> 24) & 0xFF0000) | (((uint64_t)x >> 8) & 0xFF000000) | \
									(((uint64_t)x << 8) & 0xFF00000000) | (((uint64_t)x << 24) & 0xFF0000000000) | (((uint64_t)x << 40) & 0xFF000000000000) | (((uint64_t)x << 56) & 0xFF00000000000000))

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <libpq-fe.h>

#include "config.h"
#include "database.h"

const static char DEFAULT_CONN_STR[] = "user=router dbname=router password=3948h4ng345850r08f9h4098";

static PGconn *m_conn = NULL;
static pthread_mutex_t m_mutex_conn = PTHREAD_MUTEX_INITIALIZER; // avoid multiple connections

static uint64_t db_hwAddrToDB(uint8_t *hwAddr);
static void db_DBToHwAddr(uint64_t *dbValue, uint8_t *hwAddr);
static int db_connectDB(char *connectString);
static void db_closeDB(void);

int db_cmpHwAddr(uint8_t *a, uint8_t *b){
	int idx;
	for(idx = 0; idx < 6; idx++){
		if(a[idx] != b[idx])
			return 0;
	}
	// all match
	return 1;
}

struct dhcp_lease *db_getLeases(int *count){
	struct dhcp_lease *results;
	int idx, ret;

	ret = db_connectDB(NULL);
	if(ret){
		*count = -1;

		DEBUG("Error while trying to get the static leases");
		return NULL;
	}

	PGresult *res = PQexecParams(m_conn, "SELECT * FROM dhcp_releases;", 0, NULL, NULL, NULL, NULL, 1);
	if(PQresultStatus(res) != PGRES_TUPLES_OK){
		*count = 0;

		DEBUG("No fixed releases");
		return NULL;
	}

	results = (struct dhcp_lease *)malloc((sizeof(struct dhcp_lease) * PQntuples(res)));
	*count = PQntuples(res);
	for(idx = 0; idx < (*count); idx++){
		results[idx].ipAddr.s_addr = ntohl(*((uint32_t *)PQgetvalue(res, idx, DHCP_RELEASES_COL_IP)));
		db_DBToHwAddr((uint64_t *)PQgetvalue(res, idx, DHCP_RELEASES_COL_HW), results[idx].hwAddr);
		strcpy(results[idx].hostname, (char *)PQgetvalue(res, idx, DHCP_RELEASES_COL_HOSTNAME));
		results[idx].leaseTimestamp = ntohll(*((uint64_t *)PQgetvalue(res, idx, DHCP_RELEASES_COL_TIME)));
	}

	PQclear(res);
	db_closeDB();
	return results;
}

struct dhcp_lease *db_getStaticLeases(int *count){
	struct dhcp_lease *results;
	int idx, ret;

	ret = db_connectDB(NULL);
	if(ret){
		*count = -1;

		DEBUG("Error while trying to get the static leases");
		return NULL;
	}

	PGresult *res = PQexecParams(m_conn, "SELECT * FROM dhcp_fixed;", 0, NULL, NULL, NULL, NULL, 1);
	if(PQresultStatus(res) != PGRES_TUPLES_OK){
		*count = 0;

		DEBUG("No fixed releases");
		return NULL;
	}

	results = (struct dhcp_lease *)malloc((sizeof(struct dhcp_lease) * PQntuples(res)));
	*count = PQntuples(res);
	for(idx = 0; idx < (*count); idx++){
		results[idx].ipAddr.s_addr = ntohl(*((uint32_t *)PQgetvalue(res, idx, DHCP_FIXED_COL_IP)));
		db_DBToHwAddr((uint64_t *)PQgetvalue(res, idx, DHCP_FIXED_COL_HW), results[idx].hwAddr);
		results[idx].hostname[0] = '\0';
		results[idx].leaseTimestamp = 0;
	}

	PQclear(res);
	db_closeDB();
	return results;
}

int db_searchLease(struct dhcp_lease *result, uint8_t *hwAddr){
	int ret;
	char query[128];

	ret = db_connectDB(NULL);
	if(ret){
		DEBUG("Error while trying to get the leases");
		return ret;
	}

	sprintf(query, "SELECT * FROM dhcp_releases WHERE hw_addr=%llu;", db_hwAddrToDB(hwAddr));
	PGresult *res = PQexecParams(m_conn, query, 0, NULL, NULL, NULL, NULL, 1);
	if(PQresultStatus(res) != PGRES_TUPLES_OK){
		DEBUG("No leases matching found");
		return DB_RESULTS_NONE;
	}

	if(PQntuples(res) == 0)
		return DB_RESULTS_NONE;

	result->ipAddr.s_addr = ntohl(*((uint32_t *)PQgetvalue(res, 0, DHCP_RELEASES_COL_IP)));
	db_DBToHwAddr((uint64_t *)PQgetvalue(res, 0, DHCP_RELEASES_COL_HW), result->hwAddr);
	strcpy(result->hostname, (char *)PQgetvalue(res, 0, DHCP_RELEASES_COL_HOSTNAME));
	result->leaseTimestamp = ntohll(*((uint64_t *)PQgetvalue(res, 0, DHCP_RELEASES_COL_TIME)));

	PQclear(res);
	db_closeDB();
	return DB_RESULTS_FOUND;
}

int db_searchStaticLease(struct dhcp_lease *result, uint8_t *hwAddr){
	int ret;
	char query[128];

	ret = db_connectDB(NULL);
	if(ret){
		DEBUG("Error while trying to get the leases");
		return ret;
	}

	sprintf(query, "SELECT * FROM dhcp_fixed WHERE hw_addr=%llu;", db_hwAddrToDB(hwAddr));
	PGresult *res = PQexecParams(m_conn, query, 0, NULL, NULL, NULL, NULL, 1);
	if(PQresultStatus(res) != PGRES_TUPLES_OK){
		DEBUG("No leases matching found");
		return DB_RESULTS_NONE;
	}

	if(PQntuples(res) == 0)
		return DB_RESULTS_NONE;
	
	result->ipAddr.s_addr = ntohl(*((uint32_t *)PQgetvalue(res, 0, DHCP_FIXED_COL_IP)));
	db_DBToHwAddr((uint64_t *)PQgetvalue(res, 0, DHCP_FIXED_COL_HW), result->hwAddr);
	result->hostname[0] = '\0';
	result->leaseTimestamp = 0;

	PQclear(res);
	db_closeDB();
	return DB_RESULTS_FOUND;
}

int db_addLease(struct dhcp_lease lease){
	int ret;
	char query[128];

	ret = db_connectDB(NULL);
	if(ret){
		DEBUG("Error while trying to get the leases");
		return ret;
	}

	sprintf(query, "INSERT INTO dhcp_releases(ip_addr, hostname, status, hw_addr, lease_time) VALUES (%u, '%s', true, %llu, 0)",
		lease.ipAddr.s_addr,
		lease.hostname,
		db_hwAddrToDB(lease.hwAddr));

	PGresult *res = PQexec(m_conn, query);
	if(PQresultStatus(res) != PGRES_COMMAND_OK){
		DEBUG("Leases already exists");
		return DB_RESULTS_EXISTS;
	}

	return DB_RESULTS_ADDED;
}

int db_addStaticLease(struct dhcp_lease lease){
	int ret;
	char query[128];

	ret = db_connectDB(NULL);
	if(ret){
		DEBUG("Error while trying to get the leases");
		return ret;
	}

	sprintf(query, "INSERT INTO dhcp_fixed(ip_addr, hw_addr) VALUES (%u, %llu)",
		lease.ipAddr.s_addr,
		db_hwAddrToDB(lease.hwAddr));

	PGresult *res = PQexec(m_conn, query);
	if(PQresultStatus(res) != PGRES_COMMAND_OK){
		DEBUG("Fixed leases already exists");
		return DB_RESULTS_EXISTS;
	}

	return DB_RESULTS_ADDED;
}

int db_removeLease(uint8_t *hwAddr){
	int ret;
	char query[128];

	ret = db_connectDB(NULL);
	if(ret){
		DEBUG("Error while trying to get the leases");
		return ret;
	}

	sprintf(query, "DELETE FROM dhcp_releases WHERE hw_addr=%llu", db_hwAddrToDB(hwAddr));
	PGresult *res = PQexec(m_conn, query);
	if(PQresultStatus(res) != PGRES_COMMAND_OK){
		DEBUG("Fixed leases already exists");
		return DB_RESULTS_NONE;
	}

	return DB_RESULTS_REMOVED;
}

int db_removeStaticLease(uint8_t *hwAddr){
	int ret;
	char query[128];

	ret = db_connectDB(NULL);
	if(ret){
		DEBUG("Error while trying to get the leases");
		return ret;
	}

	sprintf(query, "DELETE FROM dhcp_fixed WHERE hw_addr=%llu", db_hwAddrToDB(hwAddr));
	PGresult *res = PQexec(m_conn, query);
	if(PQresultStatus(res) != PGRES_COMMAND_OK){
		DEBUG("Fixed leases already exists");
		return DB_RESULTS_NONE;
	}

	return DB_RESULTS_REMOVED;
}

static uint64_t db_hwAddrToDB(uint8_t *hwAddr){
	uint64_t searchHw;

	searchHw = hwAddr[5];
	searchHw = (searchHw << 8) + hwAddr[4];
	searchHw = (searchHw << 8) + hwAddr[3];
	searchHw = (searchHw << 8) + hwAddr[2];
	searchHw = (searchHw << 8) + hwAddr[1];
	searchHw = (searchHw << 8) + hwAddr[0];

	return searchHw;
}

static void db_DBToHwAddr(uint64_t *dbValue, uint8_t *hwAddr){
	uint8_t *hwPointer = (uint8_t *)dbValue;

	// revert bits
	hwAddr[0] = hwPointer[7];
	hwAddr[1] = hwPointer[6];
	hwAddr[2] = hwPointer[5];
	hwAddr[3] = hwPointer[4];
	hwAddr[4] = hwPointer[3];
	hwAddr[5] = hwPointer[2];
}

static int db_connectDB(char *connectString){
	if(m_conn)
		return 0;

	if(connectString == NULL)
		connectString = (char *)DEFAULT_CONN_STR;

	pthread_mutex_lock(&m_mutex_conn);
	DEBUG("Connecting to DB using string: %s", connectString);
	m_conn = PQconnectdb(connectString);
	if(PQstatus(m_conn) == CONNECTION_BAD){
		DEBUG("Error connecting to DB, message: %s", PQerrorMessage(m_conn));
		return -EACCES;
	}

	return 0;
}

static void db_closeDB(void){
	if(m_conn){
		PQfinish(m_conn);
		m_conn = NULL;
		pthread_mutex_unlock(&m_mutex_conn);
	}
}
