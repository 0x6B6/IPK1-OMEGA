/****************************************************************
 * Project: IPK Project 1 - OMEGA: L4 Scanner
 * File: net_utils.h
 * Date: 18.02.2025
 * Author: Marek Pazúr
 * 
 * Description: Network and utillity functions and structures.
 * 
 ****************************************************************/

#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <sys/types.h>
#include <ifaddrs.h>

#include "opts.h"
#include "scan.h"

#define PACKET_SIZE 4096
typedef unsigned char packet[PACKET_SIZE];

#define TCP 0x0
#define UDP 0x1

/* Pseudo-header-IPv4 for checksum computation
 *
 * Bit|0         7|8        15|16       23|24       31|
 *   0| 			   Source address			      |
 *  32| 			Destination address			      |
 *  64|  Zeroes   |Protocol(6)|    TCP/UDP length     |
 */
typedef struct pseudo_ipv4_h {
	uint32_t ipv4_source_addr;
	uint32_t ipv4_dest_addr;
	uint8_t zeroes;
	uint8_t protocol;
	uint16_t tcp_udp_length;
} pseudo_ipv4_h;

/* Pseudo-header-IPv6 for checksum computation
 *
 * Bit|0        7|8        15|16       23|24       31|
 *   0|												 |
 *  32|				Source address				     |
 *  64|											     |
 *  96|______________________________________________|
 * 128|												 |
 * 160|				Destination address				 |
 * 192|												 |
 * 224|______________________________________________|
 * 256|					TCP/UDP length               |
 * 288|			      Zeroes             |Next header|
 */
typedef struct pseudo_ipv6_h {
	uint8_t ipv6_source_addr[16];
	uint8_t ipv6_dest_addr[16];
	uint32_t tcp_udp_length;
	uint8_t zeroes[3];
	uint8_t prot_header;
} pseudo_ipv6_h;

/***
 * General utility functions
 */

/* Prints given addresses by their family type (IPv4, IPv6, MAC) */
int print_addr(struct sockaddr *addr, sa_family_t family);

/* Create socket, specified by address family, type protocol, thats bound to given interface */
int create_socket(const char *interface, sa_family_t family, int type, int protocol);

/*** 
 * Interface functions
 */

/* Fetches interface LL struct */
int get_interfaces(cfg_t *cfg);

/* Displays network interface(s) of user device */
int list_interfaces(struct ifaddrs *ifa);

/* Prints interface flags */
void print_if_flags(unsigned int flags);

/* Returns address of specified interface */
struct sockaddr* get_ifaddr(struct ifaddrs *ifaddr, const char *interface, sa_family_t family);

/***
 * Packet assembly pipeline
 * 
 * Protocol TCP/UDP header --> Pseudo IPv4/IPv6 header --> Checksum --> IPv4/IPv6 header --> Packet Assembly Finish Line
 * 
 * Memory layout of a packet:
 * 
 * +------------------+ <--- packet[0]
 * | IPv4/IPv6 header |
 * +------------------+ <--- packet[sizeof(ip_offset)] (20B-40B)
 * |  TCP/UDP header  |
 * +------------------+ <--- packet[sizeof(protocol_offset)] (20B-8B)
 * |       Data       |
 * +------------------+
 * 
 */

/* TCP/UDP header */
int create_prot_header(l4_scanner *scanner, unsigned char *packet, int protocol);

/* Pseudo headers */
pseudo_ipv4_h create_pseudo_ipv4_h(l4_scanner *scanner, int protocol, uint32_t protocol_h_length);
pseudo_ipv6_h create_pseudo_ipv6_h(l4_scanner *scanner, int protocol, uint32_t protocol_h_length);

/* Calculate checksum */
uint16_t calculate_checksum(void *data, size_t size);

/* IPv4/IPv6 header */
int create_iphdr(l4_scanner *scanner, unsigned char *packet, int protocol, uint32_t protocol_h_length);

/* Packet assembly line main function, need to pay attention to offsets */
int packet_assembly(l4_scanner *scanner, unsigned char *packet, int protocol, int *iphdr_offset);

int filter_addresses(struct sockaddr *source, struct sockaddr *destination, sa_family_t family);

int filter_ports(uint16_t port1, uint16_t port2);

void extract_data(unsigned char *packet, int protocol);

#endif