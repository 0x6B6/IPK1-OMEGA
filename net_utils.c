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
#include <linux/if.h>
#include <linux/if_packet.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>

#include "net_utils.h"

int get_interfaces(cfg_t *cfg) {
	struct ifaddrs *ifaddr;

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		return EXIT_FAILURE;
	}

	cfg->ifaddr = ifaddr;

	return EXIT_SUCCESS;
}

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
	if (flags & IFF_LOWER_UP) {
		printf("LOWER_UP ");
	}
	if (flags & IFF_PORTSEL) {
		printf("PORTSEL ");
	}

	putchar('\n');
}

int list_interfaces(struct ifaddrs *ifa) {
	sa_family_t family;
	struct sockaddr *address;

	while (ifa) {

		family = ifa->ifa_addr->sa_family;
		address = ifa->ifa_addr; 

		if (family == AF_INET || family == AF_INET6 || family == AF_PACKET) {
			printf("Interface: %s\n"
				   "Status: ",
				   ifa->ifa_name);

			print_if_flags(ifa->ifa_flags);
			print_addr(address, family);
			printf("\n\n");
		} 

		ifa = ifa->ifa_next;
	}

  	return EXIT_SUCCESS;
}

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

/* Todo rewrite to toString() like func */
int print_addr(struct sockaddr *addr, sa_family_t family) {
	char addr_buffer[INET6_ADDRSTRLEN]; /* IPv6 length enough for both formats */

	if (family == AF_INET) { /* IPv4 */
		struct sockaddr_in *ipv4 = (struct sockaddr_in*) addr;
		
		if (inet_ntop(AF_INET, &ipv4->sin_addr, addr_buffer, sizeof(addr_buffer))) {
			 printf("%s", addr_buffer);
		}
		else {
			perror("IPv4 inet_ntop");
			return EXIT_FAILURE;
		}
	}
	else if (family == AF_INET6) { /* IPv6 */
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6*) addr;

		if (inet_ntop(AF_INET6, &ipv6->sin6_addr, addr_buffer, sizeof(addr_buffer))) {
			printf("%s", addr_buffer);
		}
		else {
			perror("IPv6 inet_ntop");
			 return EXIT_FAILURE;
		}
	}
	else if (family == AF_PACKET) { /* MAC */
		struct sockaddr_ll *ll = (struct sockaddr_ll*) addr;
		
		unsigned char *mac = ll->sll_addr;
			 	
		for (int i = 0; i < 6; ++i) {
			printf("%02x", mac[i]);

			if (i != 5) {
				printf(":");
			}
		}
	}
	else {
		fprintf(stderr, "ipk-l4-scan: error: Unknown address format\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

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

pseudo_ipv4_h create_pseudo_ipv4_h(l4_scanner *scanner, int protocol, uint32_t protocol_h_length) {
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

pseudo_ipv6_h create_pseudo_ipv6_h(l4_scanner *scanner, int protocol, uint32_t protocol_h_length) {
	pseudo_ipv6_h ph = {0};

	/* Source and destination addreses */
	memcpy(&ph.ipv6_source_addr, &((struct sockaddr_in6 *) scanner->source_addr)->sin6_addr, sizeof(struct in6_addr));
	memcpy(&ph.ipv6_dest_addr, &((struct sockaddr_in6 *) scanner->destination_addr)->sin6_addr, sizeof(struct in6_addr));
	
	/* Zero padding, memset to zero just to be sure */
	memset(ph.zeroes, 0, sizeof(ph.zeroes));

	/* TCP/UDP header size */
	ph.tcp_udp_length = htonl(protocol_h_length);
	
	/* TCP/UDP protocol */
	ph.prot_header = protocol;

	return ph;
}

int create_header(l4_scanner *scanner, packet *packet, int protocol) {
	//static uint64_t seq = 0;
	int offset;

	if (protocol == TCP) {
		struct tcphdr *tcphdr = (struct tcphdr *) packet;

		tcphdr->th_sport = htons(scanner->source_port);
		tcphdr->th_dport = htons(scanner->destination_port);
		tcphdr->th_seq = htonl(0);
		tcphdr->th_ack = htonl(0);
		tcphdr->th_off = 5;
		tcphdr->th_flags = TH_SYN; // SYN !!!
		tcphdr->th_win = htons(65535);
		tcphdr->th_sum = 0;
		tcphdr->th_urp = 0;

		/* checksum here */
		offset = sizeof(struct tcphdr);
	} else if (protocol == UDP) {
		struct udphdr *udphdr = (struct udphdr *) packet;

		udphdr->uh_sport = htons(scanner->source_port);
		udphdr->uh_dport = htons(scanner->destination_port);
		udphdr->uh_ulen = htons(sizeof(struct udphdr)); /* + payload, which will be added later hopefully :-) */
		udphdr->uh_sum = 0;

		/*checksum here*/
		offset = sizeof(struct udphdr);
	}

	return offset;
}

int create_iphdr(l4_scanner *scanner, packet *packet, int protocol, uint32_t protocol_h_length) {
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
		iph->check = 0;
		iph->saddr = ((struct sockaddr_in *) scanner->source_addr)->sin_addr.s_addr;
		iph->daddr = ((struct sockaddr_in *) scanner->destination_addr)->sin_addr.s_addr;

		offset = sizeof(struct iphdr);
	}
	else if (scanner->family == AF_INET6) {
		struct ip6_hdr *ip6h = (struct ip6_hdr *) packet;

		ip6h->ip6_nxt = protocol;
		ip6h->ip6_vfc = (6 << 4);
		ip6h->ip6_plen = htons(protocol_h_length);
		ip6h->ip6_hlim = 64;

		memcpy(&ip6h->ip6_src, &((struct sockaddr_in6 *) scanner->source_addr)->sin6_addr, sizeof(struct in6_addr));	
		memcpy(&ip6h->ip6_dst, &((struct sockaddr_in6 *) scanner->destination_addr)->sin6_addr, sizeof(struct in6_addr));

		offset = sizeof(struct ip6_hdr);
	}

	printf("%d", offset);

	return offset;
}

/* PACKET ASSEMBLY LINE */
void packet_assembly(void) {
	printf("\nPacket assembly is happening:\n");

	printf("Creating pseudo ip header\n");

	printf("Creating corresponding protocol header\n");

	printf("Calculating checksum\n");

	printf("Creating corresponding ip header\n");

	printf("Calculating ip checksum\n");

	printf("Packet succesfuly assembled\n\n");

	return;
}