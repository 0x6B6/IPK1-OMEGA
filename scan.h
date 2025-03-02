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
	int socket_fd;                      // Socket file descriptor

	uint16_t source_port;               // Source port (randomized)
	uint16_t destination_port;          // Destination port (selected by input)

	sa_family_t family;                 // Address family (IPv4/IPv6)

	struct sockaddr *source_addr;       // Source address (selected interface)
	struct sockaddr *destination_addr;  // Destination address (derived from host(s) address or domain name)

	socklen_t source_addr_len;          // Source addres length
	socklen_t destination_addr_len;     // Destination address length
} l4_scanner;

/**
 * @brief Sets up scanner structure
 * 
 * @param s Pointer to the scanner structure
 * @param source_addr Pointer to the source address
 * @param dest_addr Pointer to the destination address
 * @param source_addr_len Source address length
 * @param dest_addr_len Destination address length
 * @param family Address family type
 */
void set_scanner(l4_scanner *s,
						struct sockaddr *source_addr,
						struct sockaddr *dest_addr,
						socklen_t source_addr_len,
						socklen_t dest_addr_len,
						sa_family_t family);

/**
 * @brief Scanner starting point function
 * 
 * start_scan() uses specified configuration to fetch host (destination) addresses via DNS requests and retrieves device interface (source) address information.
 * It sets up the scanner structure and then begins scanning ports at each host address. 
 * 
 * @param cfg Pointer to the configuration structure that contains necessary settings such as interface, domain/ip address, timeout, ports
 * 
 * @return Returns EXIT_SUCCESS on success, else EXIT_FALURE if an error occurs during the scanning process
 */
int start_scan(cfg_t *cfg);

/**
 * @brief Processes the given ports structure based on the specified protocol and invokes the port scan function
 * 
 * process_ports() iterates through an array or a range of TCP/UDP ports included in the cfg configuration structure.
 * It also creates a raw socket file descriptor, setting the socket type to either IPPROTO_TCP or IPPROTO_UDP.
 * Each port is then scanned and printed with corresponding protocol info.
 * On exit, the socket file descriptor is closed. 
 * 
 * @param cfg Pointer to the configuration structure that contains the list or range of TCP/UDP ports to be processed
 * @param scanner Pointer to the scanner structure
 * @param protocol Protocol to be used for scanning ports, either TCP or UDP
 * 
 * @return Returns EXIT_SUCCESS on success, else EXIT_FALURE if an error occurs during the scanning process
 */
int process_ports(cfg_t *cfg, l4_scanner *scanner, int protocol);

/**
 * @brief Assembles and sends TCP SYN/UDP packets by given protocol, then awaits a response and evaluates port state. 
 * 
 * Final step of the TCP SYN/UDP scanning process. At this stage every information needed is collected,
 * the function proceeds to scan the selected port(s) and analyze the response.
 * 
 * port_scan() creates a packet with aproppriate protocol (TCP or UDP) header, sends it to the destination address and awaits response.
 * If a response is received, then the data from the response packet is extracted and interpreted.
 * If no response is received, the packet is resent again. After a specified number of retries, if still no response, the port is marked as filtered | open.
 * 
 * Depending on the protocol, second socket file descriptor may be created to receive packet responses, since closed UDP ports send ICMP responses back.
 * 
 * 
 * @param cfg Pointer to the configuration structure that contains necessary settings such as interface, domain/ip address, timeout, ports
 * @param scanner Pointer to the scanner structure
 * @param protocol Protocol to be used for scanning ports, either TCP or UDP
 * 
 * @return Returns EXIT_SUCCESS on success, else EXIT_FALURE if an error occurs during the scanning process
 */
int port_scan(cfg_t *cfg, l4_scanner *scanner, int protocol);

#endif