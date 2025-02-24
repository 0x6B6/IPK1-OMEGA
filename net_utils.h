/****************************************************************
 * Project: IPK Project 1 - OMEGA: L4 Scanner
 * File: net_utils.h
 * Date: 18.02.2025
 * Author: Marek Pazúr
 * 
 * Description: Network and utillity functions, structs.
 * 
 ****************************************************************/
#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <sys/types.h>
#include <ifaddrs.h>

#include "opts.h"
#include "scan.h"

/* Fetches interface LL struct */
int get_interfaces(cfg_t *cfg);

/* Prints interface flags */
void print_if_flags(unsigned int flags);

/* Displays network interface(s) of user device */
int list_interfaces(struct ifaddrs *ifa);

/* Returns address of specified interface */
struct sockaddr* get_ifaddr(struct ifaddrs *ifaddr, const char *interface, unsigned int family);

/* Create functions */
int create_socket(const char *interface, int family, int type, int protocol);
int create_packet(void);
int create_header(void);
int create_pseudo(void);

int checksum(void);

#endif