#ifndef _INC_SOCKET_H_
#define _INC_SOCKET_H_

#define SOCKET_RCVTIMEOUT_IN_MS		300
#define SOCKET_MAX_CLIENTS		10
#define SOCKET_MAX_PAYLOAD		2048

#include <stdint.h>
#include <netinet/in.h>

typedef int (*socket_callback)(uint8_t *, int, uint8_t *);

int socket_openServer(uint16_t port);
int socket_closeServer(void);
int socket_setRecvTimeout(unsigned int ms);
void socket_defineCallback(socket_callback func);

#endif // _INC_SOCKET_H_
