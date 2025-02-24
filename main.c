/****************************************************************
 * Project: IPK Project 1 - OMEGA: L4 Scanner
 * File: main.c
 * Date: 18.02.2025
 * Author: Marek Pazúr
 * 
 * Description: Simple TCP and UDP network L4 scanner.
 * 
 ****************************************************************/

/* Standard utility libraries */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h> // File descriptor (Socket) settings
#include <sys/ioctl.h>

/* CTRL + C Signal handle */
#include <signal.h>

/* Useful network libraries */
#include <sys/socket.h> // Socket library
#include <sys/types.h>  // System data types
#include <netdb.h>		// Domain name and IP address services
#include <arpa/inet.h>  // Host and network byte order conversion

/* Move later */
#include <ifaddrs.h>	// Network interfaces
#include <net/if.h>		// Flags, network structs

/* Project libraries */
#include "opts.h"
#include "net_utils.h"
#include "scan.h"

void INThandler(int sig) {
	printf("Terminating the program. Interrupt signal - %d\n", sig);
}

int main(int argc, char *argv[]) {
	//signal(SIGINT, INThandler);
	/* L4 scan configuration */
	cfg_t cfg;
	init_cfg(&cfg);
	get_interfaces(&cfg);

/*	if (argc == 1) { // Has no parameters, lists network interfaces and ends
		return list_interfaces(cfg.ifaddr);
	}

	if (parse_opt(&cfg, argc, argv)) { // Parameter processing and parameter functions
		fprintf(stderr, "ipk-l4-scan: error: Unable to parse given optional arguments\n");
		free_cfg(&cfg);
		return EXIT_FAILURE;
	}*/

	argc = argc, argv=argv;
	struct sockaddr *address;

	if((address = get_ifaddr(cfg.ifaddr, "ens33", AF_INET))){
			printf("Found\n");
				struct sockaddr_in *ipv4 = (struct sockaddr_in*) address;
			 	char addr_buffer[INET_ADDRSTRLEN];
			 	
			 	if (inet_ntop(AF_INET, &ipv4->sin_addr, addr_buffer, sizeof(addr_buffer))) {
			 		printf("IPv4: %s\n", addr_buffer);
			 	} else {
			 		perror("IPv4 inet_ntop");
			 		return EXIT_FAILURE;
			 	}
		}
	else
		printf("Not found\n");

	/* DEBUG PRINT */
    /*printf("Configuration\n\n"
			"interface: %s\n"
			"domain name - ip: %s\n"
			"timeout: %d\n"
			"TCP ports:\n"
			,
			cfg.interface,	
			cfg.dn_ip,
			cfg.timeout
		);
		if (cfg.tcp_ports.access_type == P_LIST) {
			printf("Capacity %ld, length %ld\n", cfg.tcp_ports.list_capacity, cfg.tcp_ports.list_length);
			for (unsigned int i = 0; i < cfg.tcp_ports.list_length; ++i)
			{
				printf("%d, ", cfg.tcp_ports.port_list[i]);
			}
		} else if (cfg.tcp_ports.access_type == P_RANGE) {
			printf("Ports: %d - %d", cfg.tcp_ports.range.from, cfg.tcp_ports.range.to);
		}
		printf("UDP ports:\n");
		if (cfg.udp_ports.access_type == P_LIST) {
			printf("Capacity %ld, length %ld\n", cfg.udp_ports.list_capacity, cfg.udp_ports.list_length);
			for (unsigned int i = 0; i < cfg.udp_ports.list_length; ++i)
			{
				printf("%d, ", cfg.udp_ports.port_list[i]);
			}
		} else if(cfg.udp_ports.access_type == P_RANGE) {
			printf("Ports: %d - %d", cfg.udp_ports.range.from, cfg.tcp_ports.range.to);
		}
		putchar('\n');
	*/ /* DEBUG PRINT END */

	//setup_scan(&cfg); // Setup of the main scan procedure

	free_cfg(&cfg); // Free remaining resources

	return EXIT_SUCCESS;
}