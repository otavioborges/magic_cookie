#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <ifaddrs.h>
#include <string.h>

#include "config.h"

static int config_getInterfaces(char **values);

static int m_definedConfigLevel = CONFIG_LOG_NORMAL; // Log level is normal
static pthread_mutex_t m_msgMutex = PTHREAD_MUTEX_INITIALIZER;

int config_loadFromFile(char *path, struct dhcp_server_config *config){
/*
  int num, iCount, fd, lineCount;
  char * line = NULL;
  size_t len = 0;
  FILE *configFile;
  char interfacesAvail[16][64];
  char wanInterface[64];
  char configName[32];
  struct ifreq ifr;

  lineCount = 0;
  configFile = fopen(path, "r");
  if(configFile){
    while (getline(&line, &len, fp) != -1) {
      sscanf(line, "%s %*s", configName);

      if(strcmp(configName, "interface") == 0){
        sscanf(line,"%*s %s", configName);
        config->interface = (char *)malloc(strlen(configName) + 1);
        strcpy(config->interface, configName);

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        ifr.ifr_addr.sa_family = AF_INET;
        strncpy(ifr.ifr_name, config->interface, IFNAMSIZ-1);
        ret = ioctl(fd, SIOCGIFADDR, &ifr);
        if(ret){
          printf("\033[0;31m\033[0m")
          return ret;
        }

        close(fd);

        config->serverIP.s_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
      }else if(strcmp(configName, )){

      }

      lineCount++;
    }

    fclose(configFile);
  }
*/
  config->interface = "eth0";

  config->routers = (struct in_addr *)malloc((sizeof(struct in_addr) * 2));
	config->dns = (struct in_addr *)malloc((sizeof(struct in_addr) * 2));

  config->serverIP.s_addr		= 0x0200a0a;

  // config->routers            = NULL;
	// config->dns                = NULL;

	config->netmask.s_addr 		= 0x00FFFFFF;
	config->subnet.s_addr			= 0x00000a0a;

	config->routers[0].s_addr	= 0x01000a0a;
	config->routers[1].s_addr	= 0;

	config->dns[0].s_addr			= 0x08080808;
	config->dns[1].s_addr			= 0;

	config->domainName					= NULL;
	config->initialRange				= 10;
	config->endRange						= 200;
	config->timezone						= -23200;
	config->mtu								= 0;

  config->leaseTime					= 3600U;
  config->bindindTime        = 1800U;

  return CONFIG_LOADED;
}

void config_defineLogLevel(int lvl){
  if(lvl < 0)
    m_definedConfigLevel = CONFIG_LOG_DEBUG;
  else
    m_definedConfigLevel = lvl;
}

int config_log(int lvl, char *msg, ...){
  int ret = 0;
  va_list list;

  if(lvl < m_definedConfigLevel)
    return 0; // this message will not be printed

  pthread_mutex_lock(&m_msgMutex);
  switch(lvl){
    case CONFIG_LOG_DEBUG:
      printf("[\033[0;32mDEBUG\033[0m] - ");
      break;
    case CONFIG_LOG_WARNING:
      printf("[\033[0;33mWARNING\033[0m] - ");
      break;
    case CONFIG_LOG_ERROR:
      printf("[\033[0;31mERROR\033[0m] - ");
      break;
    default: // default to a normal message
      printf("[\033[0;32mMSG\033[0m] - ");
  }

  va_start(list, msg);
  ret = vprintf(msg,list);
  printf("\n");
  va_end(list);

  pthread_mutex_unlock(&m_msgMutex);
  return ret;
}

static int config_getInterfaces(char **values){
  struct ifaddrs *addrs,*tmp;
  int count = 0;

  getifaddrs(&addrs);
  tmp = addrs;

  while (tmp){
    if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET)
      strcpy(values[count], tmp->ifa_name);

    tmp = tmp->ifa_next;
    count++;
  }

  freeifaddrs(addrs);
  return count;
}
