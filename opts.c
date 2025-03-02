/****************************************************************
 * Project: IPK Project 1 - OMEGA: L4 Scanner
 * File: opts.c
 * Date: 18.02.2025
 * Author: Marek Pazúr
 * 
 * Description: Options and arguments parsing (processing), option functions.
 * 
 ****************************************************************/

#include "opts.h"
#include "net_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <ctype.h>


/* Bitwise flags used to track *necessary* optional parameter selection,
 * 	in order to prevent duplicity or missing mandatory parameters.
 *
 * Each flag represents specific parameter
 */
#define F_IFN (1 << 0)        // Interface name
#define F_TCP (1 << 1)        // TCP port(s) 
#define F_UDP (1 << 2)        // UDP port(s)
#define F_TIMEOUT (1 << 3)    // Timeout
#define F_DN_IP (1 << 4)      // Domain name or IP address of the host
#define F_RATE_LIMIT (1 << 5) // Rate limit for UDP scanning
#define F_RESEND (1 << 6)     // Number of times a packet should be resent in case of no response
#define F_VERBOSE (1 << 7)    // Show detailed information

/* Helper macro(s) */
#define CHECK_PARAM(i, argc, argv, msg) \
	do { \
		if ((i) >= (argc) || (argv)[i][0] == ('-')) { \
			fprintf(stderr, "ipk-l4-scan: error: %s\n", (msg)); \
			return EXIT_FAILURE; \
		} \
	} while(0)

/* Helper functions */
int parse_number(unsigned int *target, char *str); /* Parses timeout */

int parse_ports(ports_t *ports, char *port_str); /* Parses port(s), checks their validity */

static inline int is_opt(char *arg, char *opt_1, char *opt_2) { /* Matches given argument with optional parameters */
	return  (strcmp(arg, opt_1) == 0 || strcmp(arg, opt_2) == 0);
}

void init_cfg(cfg_t *cfg) {
	memset(cfg, 0, sizeof(cfg_t));

	cfg->tcp_ports = (ports_t) {.access_type = P_UNDEF, .range.from = 1, .range.to = 65536, .list_capacity = 16};
	cfg->udp_ports = (ports_t) {.access_type = P_UNDEF, .range.from = 1, .range.to = 65536, .list_capacity = 16};
	cfg->timeout = 5000;   // 5000 ms default
	cfg->rate_limit = 1000; // 1000 ms default source [RFC 1812]: https://datatracker.ietf.org/doc/html/rfc1812#page-56
	cfg->retry = 1;        // 1 packet retransmission default
}

void free_cfg(cfg_t *cfg) {
	if (cfg->udp_ports.access_type == P_LIST) {
		free(cfg->udp_ports.port_list);
	}

	if (cfg->tcp_ports.access_type == P_LIST) {
		free(cfg->tcp_ports.port_list);
	}

	if (cfg->ifaddr) {
		freeifaddrs(cfg->ifaddr);
	}
}

/* Main parse function */
int parse_opt(cfg_t *cfg, int argc, char *argv[]) { /* Parses arguments */
	char *dn_ip;
	int opts = 0x00; // Optional parameters

	/* Argument parse */
	for (int i = 1; i < argc; ++i)
	{
		/* Scanner parameters */
		if (argv[i][0] == '-') { /* -opt | --opt, the if statemenet is probably unnecessary, however I find it more readable */

			if (is_opt(argv[i], "-i", "--interface")) { /* Interface */
				if (argc == 2) { /* Is only parameter ./ipk-l4-scan -i | --interface, lists interfaces */
					exit(list_interfaces(cfg->ifaddr));
				}

				if (opts & F_IFN) { /* Duplicite parameter catch */
					fprintf(stderr, "ipk-l4-scan: error: Multiple [-i interface | --interface interface] parameters '%s' given!\n", argv[i]);
					return EXIT_FAILURE;
				}

				++i; /* Move to the additional argument */

				CHECK_PARAM(i, argc, argv, "Missing [-i | --interface] [interface] argument!");

				char *interface = argv[i];

				if (if_nametoindex(interface) == 0) { /* Make sure given interface exists on the device */
					perror("ipk-l4-scan: error: if_nametoindex");
					fprintf(stderr, "ipk-l4-scan: error: Unable to recognize given interface name '%s'. Does it exist on this device?\n", interface);
					return EXIT_FAILURE;
				}

				opts |= F_IFN;
				cfg->interface = interface;
			}

			else if (is_opt(argv[i], "-t", "--pt")) {	/* TCP port(s) */
				if (opts & F_TCP) { /* Duplicite parameter catch */
					fprintf(stderr, "ipk-l4-scan: error: Multiple [-t port-ranges | --pt port-ranges] parameters '%s' given!\n", argv[i]);
					return EXIT_FAILURE;
				}

				++i; /* Move to the additional argument */

				CHECK_PARAM(i, argc, argv, "Missing [-t | --pt] [TCP port(s)] argument!");

				if(parse_ports(&cfg->tcp_ports, argv[i])) {
					fprintf(stderr, "ipk-l4-scan: error: Ports parser failed!\n");
					return EXIT_FAILURE;
				}

				opts |= F_TCP;
			}

			else if (is_opt(argv[i], "-u", "--pu")) {	/* UDP port(s) */
				if (opts & F_UDP) { /* Duplicite parameter catch */
					fprintf(stderr, "ipk-l4-scan: error: Multiple [-u port-ranges | --pu port-ranges] parameters '%s' given!\n", argv[i]);
					return EXIT_FAILURE;				
				}

				++i; /* Move to the additional argument */

				CHECK_PARAM(i, argc, argv, "Missing [-u | --pu] [UDP port(s)] argument!");

				if(parse_ports(&cfg->udp_ports, argv[i])) {
					fprintf(stderr, "ipk-l4-scan: error: Ports parser failed!\n");
					return EXIT_FAILURE;
				}

				opts |= F_UDP;
			}

			else if (is_opt(argv[i], "-w", "--wait")) { /* Timeout in miliseconds, default = 5000ms */
				if (opts & F_TIMEOUT) { /* Duplicite parameter catch */
					fprintf(stderr, "ipk-l4-scan: error: Multiple [-w | --wait] parameters '%s' given!\n", argv[i]);
					return EXIT_FAILURE;				
				}

				++i; /* Move to the additional argument */

				CHECK_PARAM(i, argc, argv, "Missing [-w | --wait] [timeout] (in milliseconds) argument!");

				if (parse_number(&cfg->timeout, argv[i])) {
					fprintf(stderr,"ipk-l4-scan: error: Unable to parse timeout argument\n");
					return EXIT_FAILURE;
				}

				opts |= F_TIMEOUT;
			}

			else if (is_opt(argv[i], "-l", "--rl")) {
				if (opts & F_RATE_LIMIT) { /* Duplicite parameter catch */
					fprintf(stderr, "ipk-l4-scan: error: Multiple [-l | --rl] parameters '%s' given!\n", argv[i]);
					return EXIT_FAILURE;
				}

				++i; /* Move to the additional argument */

				CHECK_PARAM(i, argc, argv, "Missing [-l | -- rl] [rate limit] (in milliseconds) argument!");

				if (parse_number(&cfg->rate_limit, argv[i])) {
					fprintf(stderr,"ipk-l4-scan: error: Unable to parse rate limit argument\n");
					return EXIT_FAILURE;					
				}

				opts |= F_RATE_LIMIT;
			}

			else if (is_opt(argv[i], "-r", "--rs")) {
				if (opts & F_RESEND) { /* Duplicite parameter catch */
					fprintf(stderr, "ipk-l4-scan: error: Multiple [-r | --rs] parameters '%s' given!\n", argv[i]);
					return EXIT_FAILURE;
				}

				++i; /* Move to the additional argument */

				CHECK_PARAM(i, argc, argv, "Missing [-r | -- resend] [number of packet retransmissions] argument!");

				if (parse_number(&cfg->retry, argv[i])) {
					fprintf(stderr,"ipk-l4-scan: error: Unable to parse resend argument\n");
					return EXIT_FAILURE;					
				}

				opts |= F_RESEND;
			}

			else if (is_opt(argv[i], "-v", "--verbose")) {
				if (opts & F_VERBOSE) { /* Duplicite parameter catch */
					fprintf(stderr, "ipk-l4-scan: error: Multiple [-v | --verbose] parameters '%s' given!\n", argv[i]);
					return EXIT_FAILURE;
				}

				cfg->verbose = 1; /* Verbose mode on */

				opts |= F_VERBOSE;
			}

			else if (is_opt(argv[i], "-h", "--help")) { /* @TODO: Help option, writes this message to stdout */
				printf("Execution\n\n"
						"./ipk-l4-scan \n\n"
						"Options:\n"
						"[-i interface | --interface interface] \n"
						"[--pu port-ranges | --pt port-ranges | -u port-ranges | -t port-ranges] \n"
						"{-w timeout} \n"
						"[domain-name | ip-address] \n"
						"[-h | --help] Show this message\n"
					);
			}

			else {
				fprintf(stderr, "ipk-l4-scan: error: Unrecognizable option (argument) '%s', cannot be parsed!\n", argv[i]);
				return EXIT_FAILURE;
			}
		}
		else {	/* domain-name | ip-address */
			if (opts & F_DN_IP) { /* Duplicite parameter catch */
				fprintf(stderr, "ipk-l4-scan: error: Multiple [domain-name | ip-address] parameters given!\n");
				return EXIT_FAILURE;
			}

			dn_ip = argv[i];
			cfg->dn_ip = dn_ip;

			opts |= F_DN_IP;
		}
	}

	/* Resolution of missing mandatory parameters.
	 * At this stage, the parameter selection must align with the ability
	 * to configure the scanner with the required parameters.
	 * 
	 * Rules:
	 * [1] (opts & (F_DN_IP | F_IFN)) != (F_DN_IP | F_IFN) ==> *Both* interface and domain-name/ip-address parameters MUST be specified.
	 * [2] (opts & (F_TCP | F_UDP)) == 0 ==> Atleast *one* (either TCP or UDP) protocol parameter MUST be specified.
	 */
	if ( ((opts & (F_DN_IP | F_IFN)) != (F_DN_IP | F_IFN)) || ((opts & (F_TCP | F_UDP)) == 0) ) {
		//fprintf(stderr, "ipk-l4-scan: error: Missing domain-name | IPv4 | IPv6 address of the host. (target)\n");
		fprintf(stderr, "ipk-l4-scan: error: Missing mandatory parameter\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

/* Parses port string */
int parse_ports(ports_t *ports, char *port_str) {
	uint16_t port_register[65536] = {0}; // Port register, serves for avoiding duplicite ports in list

	char *copy, *token, *found;

	/* Copy the string for further manipulation */
	if ((copy = malloc(strlen(port_str) + 1)) == NULL) {
		perror("ipk-l4-scan: error: malloc");
		fprintf(stderr, "ipk-l4-scan: error: Out of memory\n");
		return EXIT_FAILURE;
	}

	int i = 0, j = 0;
	/* Remove whitespace characters from the string copy */
	while (port_str[i]) {
		if (!isspace((unsigned char) port_str[i]))
			copy[j++] = port_str[i];

		++i;
	}

	copy[j] = '\0';

	unsigned int port_from = 1, port_to = 65536; // Temporary variables, serve as range

	/* Parse port(s) argument */
	if (strchr(copy, ',')) { /* Port sequence 53,80,120 */
		/* Initiate a list, only allocated here, otherwise not needed */
		if ((ports->port_list = malloc(sizeof(unsigned int) * ports->list_capacity)) == NULL) {
			perror("ipk-l4-scan: error: malloc");
			free(copy);
			return EXIT_FAILURE;
		}

		token = strtok(copy, ",");

		unsigned int port_value; // Temporary variable, works in pair with port register to avoid duplicite ports

		if (parse_number(&port_value, token)) {
			fprintf(stderr,"ipk-l4-scan: error: Unable to parse port sequence '%s'\n", port_str);
			free(copy);
			return EXIT_FAILURE;
		}

		/* Port legit check */
		if (port_value < 1 || port_value > 65536) {
			fprintf(stderr, "ipk-l4-scan: error: Invalid port %d\n", port_value);
			free(copy);
			return EXIT_FAILURE;
		}

		port_register[port_value] = port_value; // Log this port in the register array
		ports->port_list[ports->list_length++] = port_value; // Now put it in the list

		while((token = strtok(NULL, ",")) != NULL) {
			/* Reallocation if capacity <= length */
			if (ports->list_capacity <= ports->list_length) {
				size_t new_capacity = ports->list_length * 2;

				unsigned int *new = realloc(ports->port_list, sizeof(unsigned int) * new_capacity);

				if(new == NULL) {
					perror("ipk-l4-scan: error: realloc");
					free(copy);
					return EXIT_FAILURE;
				}

				ports->port_list = new;
				ports->list_capacity = new_capacity;
			}

			if (parse_number(&port_value, token)) {
				fprintf(stderr,"ipk-l4-scan: error: Unable to parse port sequence '%s'\n", port_str);
				free(copy);
				return EXIT_FAILURE;
			}

			/* Port legit check */
			if (port_value < 1 || port_value > 65536) {
				fprintf(stderr, "ipk-l4-scan: error: Invalid port %d\n", port_value);
				free(copy);
				return EXIT_FAILURE;
			}

			if (port_register[port_value] == 0) { /* Same as above, if not in the register, put it in register and list */
				port_register[port_value] = port_value;
				ports->port_list[ports->list_length++] = port_value;
			}
		}

		/* Setup */
		ports->access_type = P_LIST;
      /*printf("Capacity %ld, length %ld\n", ports->list_capacity, ports->list_length);
		for (unsigned int i = 0; i < ports->list_length; ++i)
		{
			printf("%d, ", ports->port_list[i]);
		}*/
	}
	else if ((found = strchr(copy, '-')) != NULL) { /* Port range: 53-80 | (1)-80 | 65530-(65536), the port numbers in round brackets are implicit */
		if (strchr(found + 1, '-')) {
			fprintf(stderr, "ipk-l4-scan: error: Invalid port range '%s'\n", port_str);	
			free(copy);
			return EXIT_FAILURE;
		}

		if (copy[0] == '-') { /* -80 case */
			if (parse_number(&port_to, copy + 1)) {
				fprintf(stderr,"ipk-l4-scan: error: Unable to parse port range '%s'\n", port_str);
				free(copy);
				return EXIT_FAILURE;
			}
		}
		else { 
			token = strtok(copy, "-");

			if (parse_number(&port_from, token)) {
				fprintf(stderr,"ipk-l4-scan: error: Unable to parse port range '%s'\n", port_str);
				free(copy);
				return EXIT_FAILURE;
			}

			token = strtok(NULL, "-");

			if (token != NULL) { /* 53-80 case, else 53- case */
				if (parse_number(&port_to, token)) {
					fprintf(stderr,"ipk-l4-scan: error: Unable to parse port range '%s'\n", port_str);
					free(copy);
					return EXIT_FAILURE;
				}
			}
		}	
		/* Setup */
		ports->access_type = P_RANGE;
		ports->range.from = port_from;
		ports->range.to = port_to;
		//printf("%d-%d\n",port_from, port_to); /* 53-80 case */
	}
	else if ((found = strstr(copy, "to")) != NULL) { /* Port range: 53 *to* 80 */
		if (strstr(found + 2, "to")) { /* Cant have more than one 'to' */
			fprintf(stderr, "ipk-l4-scan: error: Invalid port range '%s'\n", port_str);	
			free(copy);
			return EXIT_FAILURE;
		}

		token = strtok(copy, "to");
		
		if (token == NULL || parse_number(&port_from, token)) {
			fprintf(stderr,"ipk-l4-scan: error: Unable to parse port range '%s'\n", port_str);
			free(copy);
			return EXIT_FAILURE;
		}

		token = strtok(NULL, "to");

		if (token == NULL || parse_number(&port_to, token)) {
			fprintf(stderr,"ipk-l4-scan: error: Unable to parse port range '%s'\n", port_str);
			free(copy);
			return EXIT_FAILURE;
		}

		/* Setup */
		ports->access_type = P_RANGE;
		ports->range.from = port_from;
		ports->range.to = port_to;
		//printf("%d to %d", ports->range.from, ports->range.to);
	}
	else { /* Single port */
		unsigned int value;

		if (parse_number(&value, copy)) {
			fprintf(stderr,"ipk-l4-scan: error: Unable to parse port '%s'\n", port_str);
			free(copy);
			return EXIT_FAILURE;
		}

		/* Setup */
		ports->access_type = P_RANGE; // Can be range, since it is one value
		ports->range.from = value;
		ports->range.to = value;
		//printf("port: %d (%d)\n", ports->range.from, ports->range.to);
	}

	free(copy); // Copy can be freed here

	/* Range legit check */
	if (ports->range.from > ports->range.to || ports->range.from < 1 || ports->range.to > 65536) {
		fprintf(stderr, "ipk-l4-scan: error: Port(s) or range invalid\n");
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

/* String to uint32 conversion
 *
 * source: https://man7.org/linux/man-pages/man3/strtol.3.html
*/
int parse_number(unsigned int *target, char *str_val) {
	errno = 0;
	char *endptr;

	if (str_val == NULL) {
		fprintf(stderr, "ipk-l4-scan: error: NULL pointer, unable to parse number\n");
		return EXIT_FAILURE;
	}

	unsigned int value = strtoul(str_val, &endptr, 10);

	if (errno == ERANGE || errno == EINVAL || value > UINT_MAX) {
		perror("ipk-l4-scan: error: strtoul");
		return EXIT_FAILURE;
	}

	if (*endptr != '\0' || endptr == str_val) {
		fprintf(stderr, "ipk-l4-scan: error: Integer argument invalid format '%s'\n", str_val);
		return EXIT_FAILURE;
	}

	*target = value;

	return EXIT_SUCCESS;
}