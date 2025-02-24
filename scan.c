/****************************************************************
 * Project: IPK Project 1 - OMEGA: L4 Scanner
 * File: scan.c
 * Date: 18.02.2025
 * Author: Marek Pazúr
 * 
 * Description: L4 scanner core functions.
 * 
 ****************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <poll.h>

#include "scan.h"
#include "opts.h"
#include "net_utils.h"

#define SOURCE_PORT 12345 // Should be randomized, fix later

int start_scan(cfg_t *cfg) {
	struct addrinfo *addrinfo, hints = {0};

	/* Get host address info */
	if (getaddrinfo(cfg->dn_ip, NULL, &hints, &addrinfo) != 0) {
		fprintf(stderr, "ipk-l4-scan: error: Unable to get host %s address information!\n", cfg->dn_ip);
		return EXIT_FAILURE;
	}
	hints = hints; // Remove later, maybe useful?
	
	/* Iterate through all host ip addresses */
	struct addrinfo *ai = addrinfo; // Temporary variable, preserve head of LL struct
	struct sockaddr *src_addr;		// Generic source address
	socklen_t src_len = sizeof(struct sockaddr);
	l4_scanner s = {0};	// Init. of scanner struct

	while (ai) {
		/* Get source address of given (client) interface corresponding to given host address family */
		if((src_addr = get_ifaddr(cfg->ifaddr, cfg->interface, ai->ai_addr->sa_family)) == NULL){
			printf("ipk-l4-scan: error: Unable to get interface (source) address\n");
			return EXIT_FAILURE;
		}

		/* Scanner setup */
		s.source_addr = src_addr;
		s.source_addr_len = src_len;
		s.source_port = SOURCE_PORT;

		s.family = ai->ai_addr->sa_family;
		s.destination_addr = ai->ai_addr;
		s.destination_addr_len = ai->ai_addrlen;

		printf("Interesting ports on %s ", cfg->dn_ip);

		putchar('(');

		if(print_addr(ai->ai_addr, ai->ai_addr->sa_family)) {
			fprintf(stderr, "ipk-l4-scan: error: Scan failure\n");
			return EXIT_FAILURE;
		}

		putchar(')');

		printf(":\nPORT STATE\n");

		/* Iterate given ports and scan by using corresponding protocol */
		process_ports(cfg, &s, TCP);
		process_ports(cfg, &s, UDP);

		ai = ai->ai_next;
	}

	close(s.socket_fd);
	freeaddrinfo(addrinfo);

	return EXIT_SUCCESS;
}

int process_ports(cfg_t *cfg, l4_scanner *scanner, int protocol) {
	ports_t ports;
	char *prot_str;
	int prot_socket;

	/* Protocol handle selector */
	if (protocol == TCP) {
		ports = cfg->tcp_ports;
		prot_str = "tcp";
		prot_socket = IPPROTO_TCP;
	}
	else if (protocol == UDP) {
		ports = cfg->udp_ports;
		prot_str = "udp";
		prot_socket = IPPROTO_UDP;
	}	
	else {
		fprintf(stderr, "ipk-l4-scan: error: Invalid protocol, unable to process ports\n");
		return EXIT_FAILURE;
	}

	/* Create RAW socket for given interface & port & address family */
	if((scanner->socket_fd = create_socket(cfg->interface, scanner->source_addr->sa_family, SOCK_RAW, prot_socket)) < 0) {
		fprintf(stderr, "ipk-l4-scan: error: Invalid socket file descriptor!\n");
		return EXIT_FAILURE;
	}

	/* Iterate through ports */
	if (ports.access_type == P_RANGE) {
		for (unsigned int port = ports.range.from; port <= ports.range.to; ++port)
		{
			printf("%d/%s ", port, prot_str);
			scanner->destination_port = port;
			port_scan(cfg, scanner, port);
		}
	}
	else if (ports.access_type == P_LIST) {
		for (size_t i = 0; i < ports.list_length; ++i)
		{
			unsigned int port = ports.port_list[i];
			printf("%d/%s ?\n", port, prot_str);
			scanner->destination_port = port;
			port_scan(cfg, scanner, port);
		}
	}

	return EXIT_SUCCESS;
}

int port_scan(cfg_t *cfg, l4_scanner *scanner, int port) {
	cfg=cfg; scanner=scanner; port=port;

	packet_assembly();
	
	return EXIT_SUCCESS;
}