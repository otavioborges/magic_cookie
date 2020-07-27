#ifndef _INC_PARSER_H_
#define _INC_PARSER_H_

int parser_manageLease(struct dhcp_lease *lease, struct dhcp_packet *payload, struct dhcp_server_config config, int optionsLength);

#endif // _INC_PARSER_H_
