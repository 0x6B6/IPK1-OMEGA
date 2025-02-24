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

#define PACKET_SIZE 64
typedef char packet[PACKET_SIZE];

#define TCP 0x0
#define UDP 0x1

typedef struct l4_scanner {
	int socket_fd;

	uint16_t port;

	struct sockaddr *source;
	struct sockaddr *destination;

	socklen_t source_len;
	socklen_t destination_len;
	
} l4_scanner;

typedef struct pseudo_ipv4_h {

} pseudo_ipv4_h;

typedef struct pseudo_ipv6_h {

} pseudo_ipv6_h;

/* Initialisation and free of resources */
void init_scanner(l4_scanner *scanner);
void free_scanner(l4_scanner *scanner);

/* Setup function */
int setup_scan(cfg_t *cfg);

/* Iterates through given ports and calls port_scan to scan them one by one */
int process_ports(cfg_t *cfg, l4_scanner *scanner, int protocol);

int port_scan(cfg_t *cfg, l4_scanner *scanner, int port);

#endif