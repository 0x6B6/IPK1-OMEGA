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

#define SOURCE_PORT 12345 // Should be randomized?, perhaps rework later

void hexdump_packet(char unsigned* address, int length) {
	printf("Packet length: %d\n", length);

	for (int i = 0; i < length; ++i) {
		printf("%02X ", address[i]);
	}
	putchar('\n');
}

int start_scan(cfg_t *cfg) {
	l4_scanner s = {0};								// Init. of scanner struct
	struct addrinfo *addrinfo, *ai, hints = {0};	// Host address info
	struct sockaddr *source_addr;					// Source address
	socklen_t sa_len = sizeof(struct sockaddr);		// Source address length

	/* Get host address info */
	if (getaddrinfo(cfg->dn_ip, NULL, &hints, &addrinfo) != 0) {
		fprintf(stderr, "ipk-l4-scan: error: Unable to get host %s address information!\n", cfg->dn_ip);
		return EXIT_FAILURE;
	}

	hints = hints; // Remove later, maybe useful?
	ai = addrinfo; // Temporary variable, preserve head of LL struct

	/* Iterate through all host ip addresses */
	while (ai) {
		/* Get source address of given (client) interface corresponding to given host address family */
		if((source_addr = get_ifaddr(cfg->ifaddr, cfg->interface, ai->ai_addr->sa_family)) == NULL){
			printf("ipk-l4-scan: error: Unable to get interface (source) address\n");
			return EXIT_FAILURE;
		}

		/* Scanner setup */
		s.source_addr = source_addr;
		s.source_addr_len = sa_len;

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
		if (process_ports(cfg, &s, TCP)) {
			return EXIT_FAILURE;
		}
		
		if (process_ports(cfg, &s, UDP)) {
			return EXIT_FAILURE;
		}

		ai = ai->ai_next;

		//break; //!!! FIX THIS ISSUE
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

			if(port_scan(cfg, scanner, protocol)) {
				fprintf(stderr, "ipk-l4-scan: error: port scan\n");
				return EXIT_FAILURE;
			}
		}
	}
	else if (ports.access_type == P_LIST) {
		for (size_t i = 0; i < ports.list_length; ++i)
		{
			unsigned int port = ports.port_list[i];
			printf("%d/%s ", port, prot_str);
			scanner->destination_port = port;

			if (port_scan(cfg, scanner, protocol)) {
				fprintf(stderr, "ipk-l4-scan: error: port scan\n");
				return EXIT_FAILURE;
			}
		}
	}

	return EXIT_SUCCESS;
}

int port_scan(cfg_t *cfg, l4_scanner *scanner, int protocol) {
	struct pollfd pfd = {0};
	packet query_packet = {0}, response_packet = {0};
	int recv_socket_fd, retry = 1, size = 0, iphdr_offset = 0;

	/* Set receive socket */
	if (protocol == TCP) {
		recv_socket_fd = scanner->socket_fd;
	}

	if (protocol == UDP) {
		if ((recv_socket_fd = create_socket(cfg->interface, scanner->family, SOCK_RAW, scanner->family == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6)) < 0) {
			fprintf(stderr, "ipk-l4-scan: error: Invalid socket file descriptor");
			return EXIT_FAILURE;
		}
	}

	/* Set poll to receive from recv socket */
	pfd.fd = recv_socket_fd;
	pfd.events = POLLIN;
	
	size = packet_assembly(scanner, query_packet, protocol, &iphdr_offset);

	int sr = sendto(scanner->socket_fd, query_packet + iphdr_offset, size - iphdr_offset, 0, scanner->destination_addr, scanner->destination_addr_len); // FIX

	if (sr < 0) {
		perror("ipk-l4-scan: error: sendto");
		return EXIT_FAILURE;
	}

	/* Poll and handle response */
	while (1) {
		int rs = poll(&pfd, 1, cfg->timeout);

		if (rs < 0) {
			fprintf(stderr, "ipk-l4-scan: error: poll failure");
			break;
		}

		/* No response */
		if (rs == 0) {
			if (retry) {
				/* Resending packet */

				sr = sendto(scanner->socket_fd, query_packet + iphdr_offset, size - iphdr_offset, 0, scanner->destination_addr, scanner->destination_addr_len);

					if (sr < 0) {
						perror("ipk-l4-scan: error: sendto");
						return EXIT_FAILURE;
					}

				--retry;
				continue;
			}

			printf("%s\n", protocol == TCP ? "filtered" : "open|filtered");
			break;
		}
		/* Response received */
		else {
			struct sockaddr source_address;
			socklen_t sa_len = sizeof(source_address);

			int rr = recvfrom(recv_socket_fd, response_packet, PACKET_SIZE, 0, &source_address, &sa_len);
			
			if (rr < 0) {
				perror("ipk-l4-scan: error: recvfrom");
				return EXIT_FAILURE;
			}

			unsigned char *bp = response_packet + iphdr_offset; /* Base pointer (Skip over ip header) */

			/* Response packet filter and data extraction */
			if (filter_addresses(&source_address, scanner->destination_addr, scanner->family) == 0) {
				if (extract_data(bp, scanner->destination_port, scanner->family, protocol, iphdr_offset) == 0) {
					break;
				}
			}
		}
	}

	return EXIT_SUCCESS;
}