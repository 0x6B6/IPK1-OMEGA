/****************************************************************
 * Project: IPK Project 1 - OMEGA: L4 Scanner
 * File: net_utils.c
 * Date: 18.02.2025
 * Author: Marek Pazúr
 * 
 * Description: Network and utillity functions.
 * 
 ****************************************************************/

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if.h>
#include <linux/if_packet.h>

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

	while (ifa) {

		sa_family_t family = ifa->ifa_addr->sa_family;

		if (family == AF_INET || family == AF_INET6 || family == AF_PACKET) {
			printf("Interface: %s\n"
				   "Status: ",
				   ifa->ifa_name);

			print_if_flags(ifa->ifa_flags);

			 if (ifa->ifa_addr && family == AF_INET) {
			 	struct sockaddr_in *ipv4 = (struct sockaddr_in*) ifa->ifa_addr;
			 	char addr_buffer[INET_ADDRSTRLEN];
			 	
			 	if (inet_ntop(AF_INET, &ipv4->sin_addr, addr_buffer, sizeof(addr_buffer))) {
			 		printf("IPv4: %s\n", addr_buffer);
			 	} else {
			 		perror("IPv4 inet_ntop");
			 		return EXIT_FAILURE;
			 	}
			 }
			 else if (ifa->ifa_addr && family == AF_INET6) {
			 	struct sockaddr_in6 *ipv6 = (struct sockaddr_in6*) ifa->ifa_addr;
			 	char addr_buffer[INET6_ADDRSTRLEN];

			 	if (inet_ntop(AF_INET6, &ipv6->sin6_addr, addr_buffer, sizeof(addr_buffer))) {
			 		printf("IPv6: %s\n", addr_buffer);
			 	} else {
			 		perror("IPv6 inet_ntop");
			 		return EXIT_FAILURE;
			 	}
			 }
			 else {
			 	struct sockaddr_ll *ll = (struct sockaddr_ll*) ifa->ifa_addr;
			 	unsigned char *mac = ll->sll_addr;

			 	printf("MAC: ");
			 	
				 for (int i = 0; i < 6; ++i) {
				        printf("%02x", mac[i]);
				        if (i != 5) {
				            printf(":");
				        }
				    }
				    printf("\n");
			 }

			putchar('\n');
		} 

		ifa = ifa->ifa_next;
	}

  	return EXIT_SUCCESS;
}

struct sockaddr* get_ifaddr(struct ifaddrs *ifaddr, const char *interface, unsigned int family) {
	struct sockaddr *address = NULL;

	while (ifaddr) {

		if (strcmp(ifaddr->ifa_name, interface) == 0 && family == ifaddr->ifa_addr->sa_family) {
			address = ifaddr->ifa_addr;
		}

		ifaddr = ifaddr->ifa_next;
	}

	return address;
}

int create_socket(const char *interface, int family, int type, int protocol) {
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