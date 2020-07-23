#ifndef _INC_CONFIG_H_
#define _INC_CONFIG_H_

#ifdef DEBUG_MSG
#define DEBUG(x, ...)	fprintf(stderr, "DEBUG: "#x"\n", ##__VA_ARGS__)
#else
#define DEBUG(x, ...)
#endif

#endif // _INC_CONFIG_H_
