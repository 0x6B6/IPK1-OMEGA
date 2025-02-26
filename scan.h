/****************************************************************
 * Project: IPK Project 1 - OMEGA: L4 Scanner
 * File: scan.h
 * Date: 18.02.2025
 * Author: Marek Pazúr
 * 
 * Description: L4 scanner core functions.
 * 
 ****************************************************************/
#ifndef SCAN_H
#define SCAN_H

#include <sys/socket.h>
#include <sys/types.h>

#include "opts.h"

/* L4 Scanner Structure */
typedef struct l4_scanner {
	int socket_fd;						// Socket file descriptor

	uint16_t source_port;				// Source port (randomized)
	uint16_t destination_port;			// Destination port (selected by input)

	sa_family_t family;					// Address family (IPv4/IPv6)

	struct sockaddr *source_addr;		// Source address (selected interface)
	struct sockaddr *destination_addr;	// Destination address (derived from host(s) address or domain name)

	socklen_t source_addr_len;			// Source addres length
	socklen_t destination_addr_len;		// Destination address length
} l4_scanner;

/* Initialisation and release of resources */
void init_scanner(l4_scanner *scanner);
void free_scanner(l4_scanner *scanner);

/* Starting point scan function */
int start_scan(cfg_t *cfg);

/* Processes and handles the ports structure by the given protocol, invokes port_scan function */
int process_ports(cfg_t *cfg, l4_scanner *scanner, int protocol);

/* Last part of the scan process, at this stage every information needed is collected,
 * all thats left is to scan the selected port(s) and analyze the response.
 */
int port_scan(cfg_t *cfg, l4_scanner *scanner, int protocol);

#endif