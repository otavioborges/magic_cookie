#include "dhcp.h"

static struct dhcp_options *parsed_options[128];

static void dhcp_parse_options(uint8_t *offset, int length, int *count){
	uint8_t *currentOp = offset;
	*count = 0;

	while(*currentOp != 0xFF){
		parsed_options[(*count)] = (struct dhcp_options *)currentOp;

		currentOp += parsed_options[(*count)]->length + 2;
		(*count)++;

		if(currentOp > (offset + length))
			break;
	}
}
