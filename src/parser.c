#include <string.h>
#include <arpa/inet.h>

#include "config.h"
#include "dhcp.h"
#include "database.h"

static int parser_discover(struct dhcp_lease *lease, struct dhcp_server_config config);
static int parser_request(struct dhcp_lease *lease, struct dhcp_server_config config);
static void parser_release(struct dhcp_lease *lease);

static int parser_getNewLease(struct dhcp_lease *lease, struct dhcp_server_config config);
static int parser_isValidIp(struct dhcp_lease *lease, struct dhcp_server_config config);

int parser_manageLease(struct dhcp_lease *lease, struct dhcp_packet *payload, struct dhcp_server_config config, int optionsLength){
  struct dhcp_options *currentOp;

  // Define client HW address
  currentOp = dhcp_search_options(DHCP_OPTION_CLIENT_ID, payload->options, optionsLength);
  if(currentOp && (currentOp->length == 7) && (currentOp->data[0] == 0x01)){
    memcpy(lease->hwAddr, (currentOp->data + 1), 6);
  }else{
    // we couldn't find the MAC of the client use chAddr
    memcpy(lease->hwAddr, payload->chAddr, 6);
  }
  config_log(CONFIG_LOG_DEBUG, "Client MAC address is %s", dhcp_htoa(lease->hwAddr));

  currentOp = dhcp_search_options(DHCP_OPTION_HOSTNAME, payload->options, optionsLength);
  if(currentOp){
    // client sent us a hostname
    memcpy(lease->hostname, currentOp->data, currentOp->length);
    lease->hostname[currentOp->length] = '\0'; // terminate the string

    config_log(CONFIG_LOG_DEBUG, "Client hostname is '%s'", lease->hostname);
  }else if(payload->sname[0] != '\0'){
    strcpy(lease->hostname, payload->sname);

    config_log(CONFIG_LOG_DEBUG, "Client hostname is '%s'", lease->hostname);
  }else{
    // no hostname
    lease->hostname[0] = '\0';
  }

  // check for requested IP
  currentOp = dhcp_search_options(DHCP_OPTION_REQ, payload->options, optionsLength);
  if(currentOp){
    lease->ipAddr.s_addr = ((struct in_addr *)currentOp->data)->s_addr;
  }

  currentOp = dhcp_search_options(DHCP_OPTION_OP, payload->options, optionsLength);
  if(currentOp){
    switch(currentOp->data[0]){
      case DHCP_REQ_DISCOVER:
        if(parser_discover(lease, config))
          return DHCP_REQ_OFFER;
        else
          return DHCP_REQ_NONE;
      case DHCP_REQ_REQUEST:
        if(parser_request(lease, config))
          return DHCP_REQ_ACK;
        else
          return DHCP_REQ_NACK;
      case DHCP_REQ_RELEASE:
        parser_release(lease);
        return DHCP_REQ_NONE;
      default:
        config_log(CONFIG_LOG_WARNING, "Client %s provided unhandled request '%s'", dhcp_htoa(lease->hwAddr), dhcp_strreq(currentOp->data[0]));
        return DHCP_REQ_NONE;
    }
  }else{
    config_log(CONFIG_LOG_WARNING, "Client %s sent DHCP message without proper request", dhcp_htoa(lease->hwAddr));
    return DHCP_REQ_NONE; // no request, don't know what to do with this
  }
}

static int parser_discover(struct dhcp_lease *lease, struct dhcp_server_config config){
  int ret;
  // we got a discover let's try to find a new IP
  config_log(CONFIG_LOG_NORMAL, "Client %s requested DHCP DISCOVER", dhcp_htoa(lease->hwAddr));

  // does this client have a static lease
  ret = db_searchStaticLease(lease, lease->hwAddr);
  if(ret == DB_RESULTS_FOUND)
    return 1;

  // does this client have a valid older lease
  ret = db_searchLease(lease, lease->hwAddr);
  if(ret == DB_RESULTS_FOUND)
    return 1;

  // create a new lease for this client
  return parser_getNewLease(lease, config);
}

static int parser_request(struct dhcp_lease *lease, struct dhcp_server_config config){
  int ret;
  struct dhcp_lease possible;
  // we got a discover let's try to find a new IP
  config_log(CONFIG_LOG_NORMAL, "Client %s requested DHCP REQUEST", dhcp_htoa(lease->hwAddr));

  if(!parser_isValidIp(lease, config))
    return 0; // this IP is not valid on the subnet

  if(db_searchByIP(&possible, lease->ipAddr, 0) == DB_RESULTS_FOUND){
    // this lease exists, is it for this client
    if(dhcp_macMatch(possible.hwAddr, lease->hwAddr)){
      // renew and go
      config_log(CONFIG_LOG_DEBUG, "Updating lease for %s", inet_ntoa(lease->ipAddr));
      if(db_updateLeaseTime(lease->hwAddr) == DB_RESULTS_FOUND)
        return 1;
      else
        return 0;
    }else{
      // this IP exists and is for another client, NACK it
      return 0;
    }
  }else{
    // this IP is free, but does this client require an Static lease?
    if(db_searchStaticLease(&possible, lease->hwAddr) == DB_RESULTS_FOUND)
      return 0; // you should use the static lease

    // this is a valid lease, add it and ACK it
    config_log(CONFIG_LOG_DEBUG, "Adding new lease %s for client %s", inet_ntoa(lease->ipAddr), dhcp_htoa(lease->hwAddr));
    if(db_addLease(lease) == DB_RESULTS_ADDED)
      return 1;
    else
      return 0;
  }
}

static void parser_release(struct dhcp_lease *lease){
  config_log(CONFIG_LOG_NORMAL, "Client %s requested DHCP RELEASE", dhcp_htoa(lease->hwAddr));
  db_removeLease(lease->hwAddr);
}

static int parser_getNewLease(struct dhcp_lease *lease, struct dhcp_server_config config){
  uint32_t nextLease;
  struct in_addr IPaddress;

  for(nextLease = config.initialRange; nextLease < config.endRange; nextLease++){
    IPaddress.s_addr = (ntohl(nextLease) | config.subnet.s_addr);
    if(db_searchByIP(NULL, IPaddress, 1) == DB_RESULTS_NONE){
      config_log(CONFIG_LOG_DEBUG, "A new lease %s has been found", inet_ntoa(lease->ipAddr));
      lease->ipAddr = IPaddress;
      return 1;
    }
  }

  config_log(CONFIG_LOG_WARNING, "No leases available for %s", dhcp_htoa(lease->hwAddr));
  return 0;
}

static int parser_isValidIp(struct dhcp_lease *lease, struct dhcp_server_config config){
  struct in_addr checkValue;

  checkValue.s_addr = (lease->ipAddr.s_addr & config.netmask.s_addr);

  if(checkValue.s_addr == config.subnet.s_addr)
    return 1;
  else
    return 0;
}
