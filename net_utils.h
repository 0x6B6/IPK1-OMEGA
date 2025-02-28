/****************************************************************
 * Project: IPK Project 1 - OMEGA: L4 Scanner
 * File: net_utils.h
 * Date: 18.02.2025
 * Last change: 01.03.2025
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
 *   0|               Source address                  |
 *  32|          Destination address                  |
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
 *   0|                                              |
 *  32|                Source address                |
 *  64|                                              |
 *  96|______________________________________________|
 * 128|                                              |
 * 160|             Destination address              |
 * 192|                                              |
 * 224|______________________________________________|
 * 256|                TCP/UDP length                |
 * 288|               Zeroes             |Next header|
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

/**
 * @brief Hex dumps the content of a packet
 *
 * This function takes a pointer to the packet and its length
 * and prints the content of the packet in hexadecimal format.
 * Used for debugging or inspecting the content of the packet.
 *
 * @param address Pointer to packet.
 * @param length Length of the packet in bytes.
 */
void hexdump_packet(char unsigned* address, int length);

/**
 * @brief Converts given addresses from binary format to ASCII string.
 *
 * addr_to_string() takes a pointer to sockaddr structure containing address and converts the binary
 * representation of the address to ASCII string. Addresses with IPv4, IPv6 and MAC
 * address family are converted and then stored in the given buffer.
 *
 * @param addr Pointer to generic sockaddr structure containing the address to be converted.
 * @param family Adress family type (IPv4 | IPv6 | MAC)
 * @param buf Pointer to buffer where the resulting ASCII string will be stored.
 * @param len Length of the buffer in bytes.
 * 
 * @return Returns EXIT_SUCCESS on success or EXIT_FAILURE on error.
 */
int addr_to_string(struct sockaddr *addr, sa_family_t family, char *buf, size_t len);

/** 
 * @brief Creates socket, specified by address family, type protocol, thats bound to given interface
 * 
 * @param interface Pointer to a interface name string
 * @param family Address family
 * @param type Socket type
 * @param protocol TCP/UDP protocol
 */
int create_socket(const char *interface, sa_family_t family, int type, int protocol);

/**
 * @brief Closes socket file descriptors, it is necessary to distinguish them
 * 
 * This function takes sendto and recv sockets file descriptors and closes them.
 * If they describe the same socket, send_fd is closed.
 * If they describe different sockets, both of them are closed.
 * 
 * @param send_fd Send socket file descriptor
 * @param recv_fd Receive socket file descriptor
 */
void close_socket_fd(int send_fd, int recv_fd);

/*** 
 * Interface functions
 */

/**
 * @brief Fetches interface getaddrsinfo linked list
 * 
 * Uses function getaddrsinfo() to get a linked list containing information about every interface on the device,
 * then puts a reference to configuration structure.
 * 
 * @warning The caller is responsible for releasing the allocated memory
 * 
 *@param cfg Pointer to the configuration structure that contains necessary settings such as interface, domain/ip address, timeout, ports 
 * 
 * @returns Returns EXIT_SUCCESS on success, else EXIT_FAILURE if getaddrsinfo() error encountered 
 */
int get_interfaces(cfg_t *cfg);

/**
 * @brief Displays network interface(s) of user device
 * 
 * Iterates through the struct iffadrs linked list and prints each interface with additional information such as STATE and ADDRESS.
 * Each interface may have multiple addresses of different family types (IPv4 | IPv6 | MAC). 
 *
 * @param ifa Pointer to the ifaddrs linked list containing information about each interface on the device
 * 
 * @return Returns EXIT_SUCCESS on success, EXIT_FAILURE on error encountered when printing addresses 
 */
int list_interfaces(struct ifaddrs *ifa);

/**
 * @brief Prints interface flags
 * 
 * Prints interface flags to STDOUT
 * 
 * @param flags Interface flags
 */
void print_if_flags(unsigned int flags);

/**
 * @brief Returns pointer to sockaddr struct address of specified interface
 *
 * Traverses through the interface linked list to find the interface node containing
 * the address of corresponding address family
 * 
 * @param ifaddr Pointer to the head node of the interface linked list
 * @param interface Interface name string
 * @param family Address family type
 */
struct sockaddr* get_ifaddr(struct ifaddrs *ifaddr, const char *interface, sa_family_t family);

/***
 * Packet assembly pipeline
 * 
 * Protocol TCP/UDP header --> Pseudo IPv4/IPv6 header --> Checksum --> IPv4/IPv6 header --> Ready packet
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

/**
 * @brief Creates a TCP/UDP header inside a packet
 * 
 * This function creates a TCP/UDP protocol header. In case of the TCP header, the SYN flag is set to initiate communication with target.
 * Finally a checksum is calculated for both headers to ensure data integrity.
 * Header is implicitly a part of the packet.
 *
 * @param scanner Pointer to scanner structure
 * @param packet Pointer to a packet starting at an offset of the size of the ip header (packet[sizeof(ip_header_offset)])
 * @param protocol TCP/UDP protocol type
 * 
 * @return offset Returns the protocol header size
 */
int create_prot_header(l4_scanner *scanner, unsigned char *packet, int protocol);

/* Pseudo headers */

/**
 * @brief Creates a pseudo IPv4 header
 * 
 * This function creates a pseudo IPv4 header structure to be later used in checksum calculation,
 * to ensure data integrity.
 * 
 * @warninig pseudo IPv4 header cannot be used for IPv6 addressing!
 * 
 * @param scanner Pointer to the scanner structure
 * @param protocol TCP/UDP protocol type
 * @param protocol_h_length Size of the used protocol (TCP/UDP)
 * 
 * @return Returns configured pseudo IPv4 header
 */
pseudo_ipv4_h create_pseudo_ipv4_h(l4_scanner *scanner, int protocol, uint32_t protocol_h_length);

/**
 * @brief Creates a pseudo IPv6 header
 * 
 * This function creates a pseudo IPv6 header structure to be later used in checksum calculation,
 * to ensure data integrity.
 * 
 * @warninig pseudo IPv4 header cannot be used for IPv4 addressing!
 * 
 * @param scanner Pointer to the scanner structure
 * @param protocol TCP/UDP protocol type
 * @param protocol_h_length Size of the used protocol (TCP/UDP)
 * 
 * @return Returns configured pseudo IPv6 header
 */
pseudo_ipv6_h create_pseudo_ipv6_h(l4_scanner *scanner, int protocol, uint32_t protocol_h_length);

/**
 * @brief Calculate checksum
 *
 * This function calculates checksum of given data, to ensure its integrity when sending the data over the network.
 * 
 * Code inspiration source [RFC 1071]: https://datatracker.ietf.org/doc/html/rfc1071
 *
 * @param data Pointer to the data on which the checksum will be calculated  
 * @param size Size of the data in bytes 
 * 
 * @return Returns the calculated checksum value
 */
uint16_t calculate_checksum(void *data, size_t size);

/**
 * @brief Create IPv4/IPv6 header inside a packet
 *
 * Depending on the address family that is currently set in the scanner structure an IP header is created.
 * 
 * In case of address family being AF_INET (IPv4) an IPv4 header is created.
 * In case of address family being AF_INET6 (IPv6) an IPv6 header is created.
 * 
 * IP header is inserted at the start of the packet.
 * 
 * @warning Deprecated function (not used)
 * @note Can be used, but not needed. If you want to use this function you must change the flags in create_socket -> setsockopt function accordingly.
 * 
 * @param scanner Pointer to the scanner structure
 * @param packet Pointer to the starting address of a packet
 * @param protocol TCP/UDP protocol type
 * @param protocol_h_length Size of the protocol header
 * 
 * @return Returns offset of size of either IPv4 or IPv6 header.
 */
int create_iphdr(l4_scanner *scanner, unsigned char *packet, int protocol, uint32_t protocol_h_length);

/**
 * @brief Assembles a packet
 * 
 * packet_assembly() function invokes the packet assembly process.
 * The resulting packet will be created corresponding to given protocol and address family.
 * 
 * [1] Data/Payload copy (no data needed in TCP SYN scan)
 * [2] Protocol header creation using create_prot_header()
 * [3] IP header creation using create_iphdr()
 * 
 * After all mentioned steps above, the size of the assembled packet is returned.
 * 
 * @warning IP header create function is not being utilized, since the sockets are currently set to create their own IP header.
 * @note If needed, the socket flags in create_socket -> setsockopt function must be set accordingly.
 * 
 * @param scanner Pointer to the scanner structure
 * @param packet Pointer to the starting address of a packet, where the function puts necessary data.
 * @param protocol Protocol of type TCP or UDP
 * @param iphdr_offset Pointer to a callee function variable that will contain the offset of the ip header size.
 * 
 * @return Total size of the assembled packet
 */
int packet_assembly(l4_scanner *scanner, unsigned char *packet, int protocol, int *iphdr_offset);

/**
 * @brief Filters response addresses
 * 
 * This function filters out unwanted response packets by comparing the addresses using memcmp.
 * 
 * The source and destination addresses must match,
 * because the response is received from the address to which the scanner sent the request  
 * 
 * @param source Pointer to a source address of type struct sockaddr
 * @param desstination Pointer to a destination address of type struct sockaddr
 * @param family Address family
 * 
 * @return Returns EXIT_SUCCESS on match, EXIT_FAILURE on mismatch
 */
int filter_addresses(struct sockaddr *source, struct sockaddr *destination, sa_family_t family);

/**
 * @brief Filters response by ports
 * 
 * This function filters out unwanted response packets, by matching the right source and destination ports.
 * 
 * @warninig Source port is converted using ntohs() function
 * 
 * @param source Source port, converted using ntohs() function
 * @param destination Destination port
 * 
 * @return Returns EXIT_SUCCESS on match, EXIT_FAILURE on mistmatch
 */
int filter_ports(uint16_t source, uint16_t destination);

/**
 * @brief Extracts data from a packet
 * 
 * This function parses the packet according to its protocol type, either TCP or UDP. For TCP SYN scanning, a response with the TCP protocol is expected, for UDP scanning without payload, a response with either ICMP or ICMP6 protocol is expected depending on the address family.
 *
 * TCP:
 * If it is a packet with the TCP protocol type, the response is evaluated as follows:
 * [1] SYN && ACK - Port is open
 * [2] RST && ACK - Port is closed
 * [3] Otherwise - Port is filtered
 *
 * UDP:
 * If it is a packet with the UDP protocol type, the ICMP response is evaluated as follows:
 * [1] DEST_UNREACH && PORT_UNREACH - Port is closed
 * [2] Otherwise - Port is filtered
 *
 * If the scanner and packet ports do not match, the function fails.
 * 
 * @param packet Pointer to a packet offset by the size of iphdr_offset
 * @param destination_port Destination port, needed by filter_ports function to filter out unwanted packets
 * @param family Address family
 * @param protocol Protocol type of TCP or UDP
 * @param iphdr_offset Offset of size of the packets IP header type
 * 
 * @return Returns EXIT_SUCCESS on valid response, else EXIT_FAILURE
 */
int extract_data(unsigned char *packet, uint16_t destination_port, sa_family_t family, int protocol, int iphdr_offset);

#endif