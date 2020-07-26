#ifndef _INC_CONFIG_H_
#define _INC_CONFIG_H_

#define CONFIG_LOADED           0
#define CONFIG_BAD_FILE         1
#define CONFIG_NO_SUBNET_CONFIG 2

#define CONFIG_LOG_DEBUG        0
#define CONFIG_LOG_NORMAL       1
#define CONFIG_LOG_WARNING      2
#define CONFIG_LOG_ERROR        3

#define CONFIG_FILE_PATH        "magic-cookie.conf"

#include <stdarg.h>

#include "dhcp.h"


int config_loadFromFile(char *path, struct dhcp_server_config *config);
void config_defineLogLevel(int lvl);
int config_log(int lvl, char *msg, ...);

#endif // _INC_CONFIG_H_
