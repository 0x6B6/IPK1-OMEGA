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

#define SOURCE_PORT 12345 // Should be randomized instead, used for debug purposes

void set_scanner(l4_scanner *s, struct sockaddr *src_a, struct sockaddr *dst_a, socklen_t src_al, socklen_t dst_al, sa_family_t family) {
		/* Interface source address */
		s->source_addr = src_a;			
		s->source_addr_len = src_al;	

		/* Host destination address */
		s->destination_addr = dst_a;
		s->destination_addr_len = dst_al;

		/* Source port */
		s->source_port = randomize_port();

		/* Host address family (IPv4/IPv6) */
		s->family = family;
}

int start_scan(cfg_t *cfg) {
	l4_scanner s = {0};								// Init. of scanner struct
	struct addrinfo *addrinfo, *ai, hints = {0};	// Host address info
	struct sockaddr *source_addr;					// Source address
	socklen_t sa_len = sizeof(struct sockaddr);		// Source address length

	hints.ai_socktype = SOCK_RAW;	// Set this to filter addresses with raw sockets, otherwise the list will contain duplicate addresses (other socket types) 

	/* Get host address info */
	if (getaddrinfo(cfg->dn_ip, NULL, &hints, &addrinfo) != 0) {
		fprintf(stderr, "ipk-l4-scan: error: Unable to get host (%s) address information\n", cfg->dn_ip); // Client device may not support IPv6 addresses
		return EXIT_FAILURE;
	}

	ai = addrinfo; // Temporary variable to preserve head of LL struct

	/* Fixes the loopback route issue */
	if (strcasecmp(cfg->dn_ip, "localhost") == 0 || 
    	strcasecmp(cfg->dn_ip, "127.0.0.1") == 0 || 
    	strcasecmp(cfg->dn_ip, "::1") == 0)
		cfg->interface = "lo"; 

	/* Iterate through all host ip addresses */
	while (ai) {
		/* Get (client) source address of the given interface, corresponding to the host family address */
		if ((source_addr = get_ifaddr(cfg->ifaddr, cfg->interface, ai->ai_addr->sa_family)) == NULL){
			fprintf(stderr, "ipk-l4-scan: error: Unable to get interface (%s) source address\n", cfg->interface);
			freeaddrinfo(addrinfo);
			return EXIT_FAILURE;
		}

		/* Scanner setup */
		set_scanner(&s, source_addr, ai->ai_addr, sa_len, ai->ai_addrlen, ai->ai_addr->sa_family);

		/* Display current address to be scanned */
		if (addr_to_string(ai->ai_addr, ai->ai_addr->sa_family, cfg->addr_str, sizeof(cfg->addr_str))) {
			fprintf(stderr, "ipk-l4-scan: error: Address conversion failure\n");
			freeaddrinfo(addrinfo);
			return EXIT_FAILURE;
		}

		//printf("Interesting ports on %s (%s):\nPORT STATE\n", cfg->dn_ip, cfg->addr_str);

		/* Iterate given ports and scan them by using corresponding protocol procedures */
		if (process_ports(cfg, &s, TCP) || process_ports(cfg, &s, UDP)) {
			freeaddrinfo(addrinfo);
			return EXIT_FAILURE;
		}
		
		ai = ai->ai_next;
	}

	close(s.socket_fd);
	freeaddrinfo(addrinfo);

	return EXIT_SUCCESS;
}

int process_ports(cfg_t *cfg, l4_scanner *scanner, int protocol) {
	ports_t ports;
	int prot_socket;

	/* Protocol handle selector */
	if (protocol == TCP) {
		ports = cfg->tcp_ports;
		prot_socket = IPPROTO_TCP;
	}
	else if (protocol == UDP) {
		ports = cfg->udp_ports;
		prot_socket = IPPROTO_UDP;
	}	
	else {
		fprintf(stderr, "ipk-l4-scan: error: Invalid protocol, unable to process ports\n");
		return EXIT_FAILURE;
	}

	/* Create RAW socket for given interface & port & address family */
	if ((scanner->socket_fd = create_socket(cfg->interface, scanner->source_addr->sa_family, SOCK_RAW, prot_socket)) < 0) {
		fprintf(stderr, "ipk-l4-scan: error: Invalid socket file descriptor!\n");
		return EXIT_FAILURE;
	}

	/* Iterate through ports */
	if (ports.access_type == P_RANGE) {
		for (unsigned int port = ports.range.from; port <= ports.range.to; ++port)
		{
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
			scanner->destination_port = ports.port_list[i];

			if (port_scan(cfg, scanner, protocol)) {
				fprintf(stderr, "ipk-l4-scan: error: port scan\n");
				return EXIT_FAILURE;
			}
		}
	}

	close(scanner->socket_fd);

	return EXIT_SUCCESS;
}

int port_scan(cfg_t *cfg, l4_scanner *scanner, int protocol) {
	int recv_socket_fd = -1, retry = cfg->retry, size = 0, iphdr_offset = 0;
	packet query_packet = {0}, response_packet = {0};
	struct pollfd pfd = {0};
	char *prot_str = protocol == TCP ? "[TCP-SYN]" : "[UDP]";

	if (cfg->verbose) {
		printf("[INFO] Processing port %d", scanner->destination_port);
		service(scanner->destination_port, protocol);
		putchar('\n');
	}

	/* Set receive socket */
	if (protocol == TCP) { // Expected response --> TCP protocol
		recv_socket_fd = scanner->socket_fd;
	}
	else if (protocol == UDP) { // Expected response --> ICMP/ICMPV6 protocol
		if ((recv_socket_fd = create_socket(cfg->interface, scanner->family, SOCK_RAW, scanner->family == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6)) < 0) {
			fprintf(stderr, "ipk-l4-scan: error: Invalid socket file descriptor\n");
			
			if (close(scanner->socket_fd)) {
				perror("ipk-l4-scan: error: close() socket_fd");
			}
			
			return EXIT_FAILURE;
		}
	}

	/* Set poll to receive from recv socket */
	pfd.fd = recv_socket_fd;
	pfd.events = POLLIN;
	
	/* Packet assembly */
	size = packet_assembly(scanner, query_packet, protocol, &iphdr_offset); 

	if (cfg->verbose)
		printf("[INFO] Sending %s packet to %s:%d\n", prot_str, cfg->addr_str, scanner->destination_port);

	int sr = sendto(scanner->socket_fd, query_packet + iphdr_offset, size - iphdr_offset, 0, scanner->destination_addr, scanner->destination_addr_len);

	if (sr < 0) { // send result
		perror("ipk-l4-scan: error: sendto");
		close_socket_fd(scanner->socket_fd, recv_socket_fd);
		return EXIT_FAILURE;
	}

	/* Poll and handle response */
	while (1) {
		int pr = poll(&pfd, 1, cfg->timeout);

		if (pr < 0) { // poll result
			fprintf(stderr, "ipk-l4-scan: error: poll failure");
			close_socket_fd(scanner->socket_fd, recv_socket_fd);
			return EXIT_FAILURE;
		}

		/* No response */
		if (pr == 0) {
			if (cfg->verbose)
				printf("\033[0;31m[NO RESPONSE]\033[0m\n");
			
			if (retry) {
				if (cfg->verbose)
					printf("[RETRANSMISSION] Sending %s packet to %s:%d\n", prot_str, cfg->addr_str, scanner->destination_port);

				/* Resending packet */
				sr = sendto(scanner->socket_fd, query_packet + iphdr_offset, size - iphdr_offset, 0, scanner->destination_addr, scanner->destination_addr_len);

				if (sr < 0) {
					perror("ipk-l4-scan: error: sendto");
					close_socket_fd(scanner->socket_fd, recv_socket_fd);
					return EXIT_FAILURE;
				}

				--retry;
			}
			else {
				if (cfg->verbose)
					printf("\033[0;33m[TIMEOUT]\033[0m ");

				printf("%s %d %s %s\n", cfg->addr_str, scanner->destination_port, protocol == TCP ? "tcp" : "udp",protocol == TCP ? "filtered" : "open");
				break;
			}
		}
		/* Response received */
		else {
			struct sockaddr_storage source_address; // Enough space for both IPv4 and IPv6 adresses
			socklen_t sa_len = sizeof(struct sockaddr_storage);

			int rr = recvfrom(recv_socket_fd, response_packet, PACKET_SIZE, 0, (struct sockaddr *) &source_address, &sa_len);
			
			if (rr < 0) { // receive result
				perror("ipk-l4-scan: error: recvfrom");
				close_socket_fd(scanner->socket_fd, recv_socket_fd);
				return EXIT_FAILURE;
			}

			/* Packet base pointer (Skip over ip header), Important: The IPv6 protocol DOES NOT return an IP header unlike IPv4  */
			unsigned char *bp = response_packet + (scanner->family == AF_INET ? iphdr_offset : 0);

			/* Throw away loopback TCP packets that match the ones sent */
			if (strncmp(cfg->interface, "lo", 2) == 0 && protocol == TCP) {
				if (filter_lo_packet(query_packet + iphdr_offset, bp)) {
					continue;
				}
			}

			/* Response packet filter and data extraction */
			if (filter_addresses((struct sockaddr *) &source_address, scanner->destination_addr, scanner->family) == 0) {
				if (extract_data(cfg, bp, scanner->destination_port, scanner->family, protocol, iphdr_offset) == 0) {
					break;
				}
			}
		}
	}

	if (scanner->socket_fd != recv_socket_fd) {
		close(recv_socket_fd);
	}

	/* Ratelimit between UDP scans */
	if (protocol == UDP) {
		rate_limit(cfg->rate_limit);
	}

	return EXIT_SUCCESS;
}