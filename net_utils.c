/****************************************************************
 * Project: IPK Project 1 - OMEGA: L4 Scanner
 * File: net_utils.c
 * Date: 18.02.2025
 * Author: Marek Pazúr
 * 
 * Description: Network and utillity functions.
 * 
 ****************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include "net_utils.h"

/* Hex dumps packet content */
void hexdump_packet(char unsigned* address, int length) {
	printf("Packet length: %d\n\nHex dump:\n", length);

	for (int i = 0; i < length; ++i) {
		printf("%02X ", address[i]);
	}
	putchar('\n');
}

/* Puts a pointer to dynamically allocated LL interface 
 *structure in the scan program configuration structure.
 */
int get_interfaces(cfg_t *cfg) {
	struct ifaddrs *ifaddr;

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		return EXIT_FAILURE;
	}

	cfg->ifaddr = ifaddr;

	return EXIT_SUCCESS;
}

/* Prints interface status flags */
void print_if_flags(unsigned int flags) {
	if (flags & IFF_UP) {
		printf("UP ");
	}
	if (flags & IFF_BROADCAST) {
		printf("BROADCAST ");
	}
	if (flags & IFF_LOOPBACK) {
		printf("LOOPBACK ");
	}
	if (flags & IFF_POINTOPOINT) {
		printf("POINT-TO-POINT ");
	}
	if (flags & IFF_NOARP) {
		printf("NO_ARP ");
	}
	if (flags & IFF_ALLMULTI) {
		printf("MULTICAST ");
	}
	if (flags & IFF_DYNAMIC) {
		printf("DYNAMIC ");
	}
	if (flags & IFF_PORTSEL) {
		printf("PORTSEL ");
	}

	putchar('\n');
}

/* FIX Prints a list with information about interfaces */
int list_interfaces(struct ifaddrs *ifa) {
	sa_family_t family;
	struct sockaddr *address;
	struct ifaddrs *ifa_hd = ifa;
	char addr_str[64];

	printf("Active interfaces:\n\n");

	while (ifa) {

		family = ifa->ifa_addr->sa_family;
		address = ifa->ifa_addr; 

		if (family == AF_INET || family == AF_INET6 || family == AF_PACKET) {
			printf("Interface: %s\n"
				   "Status: ",
				   ifa->ifa_name);

			print_if_flags(ifa->ifa_flags);

			if (family == AF_INET)
				printf("IPv4: ");
			else if (family == AF_INET6)
				printf("IPv6: ");
			else 
				printf("MAC: ");

			addr_to_string(address, family, addr_str, sizeof(addr_str));
			printf("%s\n\n", addr_str);
		} 

		ifa = ifa->ifa_next;
	}

	freeifaddrs(ifa_hd); // Free resources here

  	return EXIT_SUCCESS;
}

/* Returns interface IPv4/IPv6 (source) address */
struct sockaddr* get_ifaddr(struct ifaddrs *ifaddr, const char *interface, sa_family_t family) {
	struct sockaddr *address = NULL;

	while (ifaddr) {

		if (strcmp(ifaddr->ifa_name, interface) == 0 && family == ifaddr->ifa_addr->sa_family) {
			address = ifaddr->ifa_addr;
		}

		ifaddr = ifaddr->ifa_next;
	}

	return address;
}

/* Converts IPv4/IPv6/MAC adresses from binary to ASCII characters and assigns them to given buffer */
int addr_to_string(struct sockaddr *addr, sa_family_t family, char *buf, size_t len) {
	/* IPv4 */
	if (family == AF_INET) {
		struct sockaddr_in *ipv4 = (struct sockaddr_in*) addr;
		
		if (inet_ntop(AF_INET, &ipv4->sin_addr, buf, len) == NULL) {
			perror("IPv4 inet_ntop");
			return EXIT_FAILURE;
		}
	}
	/* IPv6 */
	else if (family == AF_INET6) {
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6*) addr;

		if (inet_ntop(AF_INET6, &ipv6->sin6_addr, buf, len) == NULL) {
			perror("IPv6 inet_ntop");
			 return EXIT_FAILURE;
		}
	}
	/* MAC */
	else if (family == AF_PACKET) { 
		struct sockaddr_ll *ll = (struct sockaddr_ll*) addr;
		unsigned char *mac = ll->sll_addr;
		char *str = buf;
			 	
		for (int i = 0; i < 6; ++i) {
			str += snprintf(str, len, "%02x", mac[i]);

			if (i != 5) {
				(*str++)= ':';
			}
		}
	}
	else {
		fprintf(stderr, "ipk-l4-scan: error: Unknown address format\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

/* Creates a socket bound to interface, returns -1 on failure */
int create_socket(const char *interface, sa_family_t family, int type, int protocol) {
	/* Create socket */
	int fd = socket(family, type, protocol);

	if (fd <= 0) {
		perror("ipk-l4-scan: error: socket");
		return -1;
	}

	/* Set Non-blocking Network I/O */
	int flags = fcntl(fd, F_GETFL, 0);

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		perror("ipk-l4-scan: error: fcntl");
		close(fd);
		return -1;
	}

	/* Bind socket to given interface */
	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface))) {
		perror("ipk-l4-scan: error: setsockopt SO_BINDTODEVICE");
		close(fd);
		return -1;
	}

	return fd;
}

/* Closes socket file descriptors */
void close_socket_fd(int send_fd, int recv_fd) {
	if (send_fd < 0 || recv_fd < 0) {
		return;
	}

	if (send_fd == recv_fd) {
		if (close(send_fd) == -1) {
			perror("ipk-l4-scan: error: close() send_socket_fd");
		}
	}
	else {
		if (close(send_fd) == -1) {
			perror("ipk-l4-scan: error: close() send_socket_fd");
		}
		if (close(recv_fd) == -1) {
			perror("ipk-l4-scan: error: close() recv_socket_fd");
		}
	}
}

/* Pseudo IPv4 header */
pseudo_ipv4_h create_pseudo_ipv4_h(l4_scanner *scanner, int protocol, uint32_t protocol_h_length) {
	/* Initialize to 0 */
	pseudo_ipv4_h ph = {0};
	
	/* Source and destination adresses */
	ph.ipv4_source_addr = ((struct sockaddr_in *) scanner->source_addr)->sin_addr.s_addr;
	ph.ipv4_dest_addr = ((struct sockaddr_in *) scanner->destination_addr)->sin_addr.s_addr;
	
	/* Zero padding */
	ph.zeroes = 0; // Zeroes set already, but just to be sure..
	/* TCP/UDP */
	ph.protocol = protocol;
	/* TCP/UDP header length */
	ph.tcp_udp_length = htons(protocol_h_length);

	return ph;
}

/* Pseudo IPv6 header */
pseudo_ipv6_h create_pseudo_ipv6_h(l4_scanner *scanner, int protocol, uint32_t protocol_h_length) {
	pseudo_ipv6_h ph = {0};

	/* Source and destination addreses (Needs to be memcpied, since IPv6 is 16 bytes of memory) */
	memcpy(&ph.ipv6_source_addr,
		   &((struct sockaddr_in6 *) scanner->source_addr)->sin6_addr,
		   sizeof(struct in6_addr)
		   );

	memcpy(&ph.ipv6_dest_addr,
		   &((struct sockaddr_in6 *) scanner->destination_addr)->sin6_addr,
		   sizeof(struct in6_addr)
		   );
	
	/* Zero padding, memset to zero just to be sure */
	memset(ph.zeroes, 0, sizeof(uint8_t) * 3);

	/* TCP/UDP header size */
	ph.tcp_udp_length = htonl(protocol_h_length);
	
	/* TCP/UDP protocol */
	ph.prot_header = protocol;

	return ph;
}

/* TCP/UDP header */
int create_prot_header(l4_scanner *scanner, unsigned char *packet, int protocol) {
	int offset = 0;	// Protocol header size offset

	if (protocol == TCP) {
		struct tcphdr *tcphdr = (struct tcphdr *) packet;

		tcphdr->th_sport = htons(scanner->source_port);			// Source port
		tcphdr->th_dport = htons(scanner->destination_port);	// Destination port
		tcphdr->th_seq = htonl(0);								// Sequence number (should increment, but we send only one packet)
		tcphdr->th_ack = htonl(0);								// Acknowlidgement number
		tcphdr->th_off = 5;										// Data offset = base + (sizeof(struct tcphdr) / 4)
		tcphdr->th_flags = TH_SYN;								// SYN !!!
		tcphdr->th_win = htons(65535);							// Window size, 65535 bytes to look like a 'normal' client
		tcphdr->th_sum = 0;										// CHECKSUM Set to zero for now
		tcphdr->th_urp = 0;										// Not urgent by any means

		/* Checksum here */
		if (scanner->family == AF_INET) {
			pseudo_ipv4_h ipv4_ph = create_pseudo_ipv4_h(scanner, IPPROTO_TCP, sizeof(struct tcphdr));

			uint8_t buffer[sizeof(pseudo_ipv4_h) + sizeof(struct tcphdr)];
			memcpy(buffer, &ipv4_ph, sizeof(pseudo_ipv4_h));
			memcpy(buffer + sizeof(pseudo_ipv4_h), tcphdr, sizeof(struct tcphdr));

			tcphdr->th_sum = calculate_checksum(buffer, sizeof(buffer));
		}
		else if (scanner->family == AF_INET6) {
			pseudo_ipv6_h ipv6_ph = create_pseudo_ipv6_h(scanner, IPPROTO_TCP, sizeof(struct tcphdr));

			uint8_t buffer[sizeof(pseudo_ipv6_h) + sizeof(struct tcphdr)];
			memcpy(buffer, &ipv6_ph, sizeof(pseudo_ipv6_h));
			memcpy(buffer + sizeof(pseudo_ipv6_h), tcphdr, sizeof(struct tcphdr));

			tcphdr->th_sum = calculate_checksum(buffer, sizeof(buffer));
		}

		offset = sizeof(struct tcphdr);
	}
	else if (protocol == UDP) {
		struct udphdr *udphdr = (struct udphdr *) packet;

		udphdr->uh_sport = htons(scanner->source_port);			// Source port
		udphdr->uh_dport = htons(scanner->destination_port);	// Destination port
		udphdr->uh_ulen = htons(sizeof(struct udphdr));			// + payload, which will be added later hopefully :-)
		udphdr->uh_sum = 0;										// CHECKSUM Set to zero for now

		/* Checksum here, if UDP payload included, must be careful with data offset */
		if (scanner->family == AF_INET) {
			pseudo_ipv4_h ipv4_ph = create_pseudo_ipv4_h(scanner, IPPROTO_UDP, sizeof(struct udphdr));

			uint8_t buffer[sizeof(struct pseudo_ipv4_h) + sizeof(struct udphdr)];
			memcpy(buffer, &ipv4_ph, sizeof(pseudo_ipv4_h));
			memcpy(buffer + sizeof(struct pseudo_ipv4_h), udphdr, sizeof(struct udphdr));

			udphdr->uh_sum = calculate_checksum(buffer, sizeof(buffer));
		}
		else if (scanner->family == AF_INET6) {
			pseudo_ipv6_h ipv6_ph = create_pseudo_ipv6_h(scanner, IPPROTO_UDP, sizeof(struct udphdr));

			uint8_t buffer[sizeof(struct pseudo_ipv6_h) + sizeof(struct udphdr)];
			memcpy(buffer, &ipv6_ph, sizeof(pseudo_ipv6_h));
			memcpy(buffer + sizeof(struct pseudo_ipv6_h), udphdr, sizeof(struct udphdr));

			udphdr->uh_sum = calculate_checksum(buffer, sizeof(buffer));
		}

		offset = sizeof(struct udphdr);
	}

	return offset; // Size of protocol header
}

/* IPv4/IPv6 header */
int create_iphdr(l4_scanner *scanner, unsigned char *packet, int protocol, uint32_t protocol_h_length) {
	/* Create IP HEADER first */
	int offset = 0;

	if (scanner->family == AF_INET) {
		struct iphdr *iph = (struct iphdr *) packet;

		iph->ihl = 5;
		iph->version = 4;
		iph->tos = 0;
		iph->tot_len = htons(sizeof(struct iphdr) + protocol_h_length);
		iph->id = htons(12345);
		iph->frag_off = 0;
		iph->ttl = 64;
		iph->protocol = protocol;
		iph->check = 0; // Checksum ! !
		iph->saddr = ((struct sockaddr_in *) scanner->source_addr)->sin_addr.s_addr;
		iph->daddr = ((struct sockaddr_in *) scanner->destination_addr)->sin_addr.s_addr;

		iph->check = calculate_checksum(iph, sizeof(struct iphdr));

		offset = sizeof(struct iphdr);
	}
	else if (scanner->family == AF_INET6) {
		struct ip6_hdr *ip6h = (struct ip6_hdr *) packet;

		ip6h->ip6_nxt = protocol;
		ip6h->ip6_vfc = (6 << 4);
		ip6h->ip6_plen = htons(protocol_h_length);
		ip6h->ip6_hlim = 64;
		// No checksum here :-)

		memcpy(&ip6h->ip6_src, &((struct sockaddr_in6 *) scanner->source_addr)->sin6_addr, sizeof(struct in6_addr));	
		memcpy(&ip6h->ip6_dst, &((struct sockaddr_in6 *) scanner->destination_addr)->sin6_addr, sizeof(struct in6_addr));

		offset = sizeof(struct ip6_hdr);
	}

	return offset;
}

/* Packet assembly */
int packet_assembly(l4_scanner *scanner, unsigned char *packet, int protocol, int *iphdr_offset) {
	int packet_size = 0, prot_hdr_size = 0, ip_hdr_size = 0;

	if (scanner->family == AF_INET) {
		ip_hdr_size = sizeof(struct iphdr);	  // 20 bytes
	}
	else if (scanner->family == AF_INET6) {
		ip_hdr_size = sizeof(struct ip6_hdr); // 40 bytes
	}
	else {
		fprintf(stderr, "ipk-l4-scan: error: packet assembly invalid address family\n");
		return -1;
	}

	prot_hdr_size = create_prot_header(scanner, packet + ip_hdr_size, protocol);
	//create_iphdr(scanner, packet, protocol, protocol == TCP ? sizeof(struct tcphdr) : sizeof(struct udphdr));
	*iphdr_offset = ip_hdr_size; 
	packet_size = ip_hdr_size + prot_hdr_size;

	return packet_size;
}

/* GENERIC CHECKSUM
 * Code inspiration source (RFC 1071): https://datatracker.ietf.org/doc/html/rfc1071
 */
uint16_t calculate_checksum(void *addr, size_t size) {
	uint32_t sum = 0;
	uint16_t *data, checksum;

	if (addr == NULL || size == 0) {
		return 0;
	}

	data = (uint16_t *) addr;

	/* Sum data by 2 bytes (16-bits) */
	while (size > 1) {
		sum +=  *data++;
		size -= 2; // Skip 2 bytes (16-bits)
	}

	/* Add left-over byte to the sum, if any  */
	if (size & 0x1) {
		sum += *(uint8_t *) data;
	}

	/* Fold 32-bits to 16-bits (Carry bit) */
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	checksum = (uint16_t) ~sum;

	return checksum;
}

int filter_addresses(struct sockaddr *source, struct sockaddr *destination, sa_family_t family) {
	int not_equal = 1;

	if (family == AF_INET) {
		not_equal = memcmp(&((struct sockaddr_in *) source)->sin_addr,
						   &((struct sockaddr_in *) destination)->sin_addr,
						   sizeof(struct in_addr)
						   );
	}

	if (family == AF_INET6) {
		not_equal = memcmp(&((struct sockaddr_in6 *) source)->sin6_addr,
		 				   &((struct sockaddr_in6 *) destination)->sin6_addr,
		 				   sizeof(struct in6_addr)
		 				   );
	}

	if (not_equal) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int filter_ports(uint16_t source, uint16_t destination) {
	if (ntohs(source) != destination) {
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

int extract_data(unsigned char *packet, uint16_t destination_port, sa_family_t family, int protocol, int iphdr_offset) {
	if (protocol == TCP) {
		struct tcphdr *t = (struct tcphdr *) packet;

		if (filter_ports(t->th_sport, destination_port)) {
			return EXIT_FAILURE;
		}

		if(t->th_flags & TH_SYN && t->th_flags & TH_ACK) {
			printf("open [SYN, ACK]\n");
		}
		else if(t->th_flags & TH_RST && t->th_flags & TH_ACK) {
			printf("closed [RST, ACK]\n");
		}
		else printf("filtered\n");	
	}

	if (protocol == UDP) {
		struct udphdr *u;
		int icmp_offset = 0;

		if (family == AF_INET) {
			struct icmphdr *icmp = (struct icmphdr *) packet;
			icmp_offset = sizeof(struct icmphdr);
			
			if (icmp->type != ICMP_DEST_UNREACH || icmp->code != ICMP_PORT_UNREACH) {
				return EXIT_FAILURE;
			}
		}
		
		if (family == AF_INET6) {
			struct icmp6_hdr *icmp6 = (struct icmp6_hdr*) packet;
			icmp_offset = sizeof(struct icmp6_hdr);

			if (icmp6->icmp6_type != ICMP6_DST_UNREACH || icmp6->icmp6_code != ICMP6_DST_UNREACH_NOPORT) {
				return EXIT_FAILURE;
			}
		}

		u = (struct udphdr *) (packet + icmp_offset + iphdr_offset);

		if (filter_ports(u->uh_dport, destination_port)) {
			return EXIT_FAILURE;
		}

		printf("closed [ICMP]\n");
	}

	return EXIT_SUCCESS;
}