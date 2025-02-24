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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

#include "scan.h"
#include "opts.h"

int setup_scan(cfg_t *cfg) {
	struct addrinfo *addrinfo, *ai, hints = {0};

	if (getaddrinfo(cfg->dn_ip, NULL, &hints, &addrinfo) != 0) {
		fprintf(stderr, "ipk-l4-scan: error: Unable to get host %s address information!\n", cfg->dn_ip);
		return EXIT_FAILURE;
	}

	hints=hints;
	ai = addrinfo;

	/* Iterate through all ip addresses */
	l4_scanner l4_scanner = {0};

	while (ai) {

		printf("Interesting ports on %s ():\n"
			   "PORT STATE\n"
			   , cfg->dn_ip
		);

		
		process_ports(cfg, &l4_scanner, TCP);
		process_ports(cfg, &l4_scanner, UDP);

		ai = ai->ai_next;
	}

	freeaddrinfo(addrinfo);

	return EXIT_SUCCESS;
}

int process_ports(cfg_t *cfg, l4_scanner *scanner, int protocol) {
	ports_t ports;

	if (protocol == TCP)
		ports = cfg->tcp_ports;
	else if (protocol == UDP)
		ports = cfg->udp_ports;
	else {
		fprintf(stderr, "ipk-l4-scan: error: Invalid protocol, unable to process ports\n");
		return EXIT_FAILURE;
	}

	if (ports.access_type == P_RANGE) {
		for (unsigned int port = ports.range.from; port <= ports.range.to; ++port)
		{
			port_scan(cfg, scanner, port);
		}
	}
	else if (ports.access_type == P_LIST) {
		for (size_t i = 0; i < ports.list_length; ++i)
		{
			unsigned int port = ports.port_list[i];
			port_scan(cfg, scanner, port);
		}
	}
	else {
		fprintf(stderr, "ipk-l4-scan: error: Port structure undefined\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int port_scan(cfg_t *cfg, l4_scanner *scanner, int port) {
	cfg=cfg; scanner=scanner;
	printf("%d/port todo\n", port);
	return EXIT_SUCCESS;
}