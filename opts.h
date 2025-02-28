/****************************************************************
 * Project: IPK Project 1 - OMEGA: L4 Scanner
 * File: opts.h
 * Date: 18.02.2025
 * Author: Marek Pazúr
 * 
 * Description: Options and arguments parsing, option functions (parameter processing).
 * 
 ****************************************************************/

#ifndef OPTS_H
#define OPTS_H

#include <ifaddrs.h>	// Network interfaces
#include <net/if.h>		// Flags, network structs
#include <arpa/inet.h>  // Host and network byte order conversion

#define P_UNDEF 0x00
#define P_RANGE 0x01
#define P_LIST 0x02

typedef struct ports {
	unsigned int access_type; // Either range or list

	struct range {
		unsigned int from;
		unsigned int to;
	} range;

	unsigned int *port_list;
	size_t list_length;
	size_t list_capacity;
} ports_t;

typedef struct config {
	char *interface;		// Given interace
	struct ifaddrs *ifaddr; // Interface adress(es) information

	ports_t tcp_ports;
	ports_t udp_ports;

	unsigned int timeout;
	unsigned int rate_limit;

	char *dn_ip;
	char *payload;
} cfg_t;

typedef struct interface interface_t;

/**
 * @brief Initialises the cfg_t structure
 * 
 * @param cfg Pointer to the configuration structure 
 */
void init_cfg(cfg_t *cfg);

/**
 * @brief Releases resources used by cfg_t structure
 * 
 * @param cfg Pointer to the configuration structure
 */
void free_cfg(cfg_t *cfg);

/**
 * @brief Parses optional parameters
 * 
 * parse_opt() parses specified command line arguments and sets the cfg_t structure accordingly.
 * 
 * @param cfg Pointer to the configuration structure
 * @param argc Argument count
 * @param argv Pointer to argv argument array  
 * 
 * @return Returns EXIT_SUCCESS on success or EXIT_FAILURE on encountering sparsing error or invalid arguments
 */
int parse_opt(cfg_t *cfg, int argc, char *argv[]);

#endif