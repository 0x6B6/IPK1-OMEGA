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

/* Project libraries */
#include "opts.h"
#include "net_utils.h"
#include "scan.h"

int main(int argc, char *argv[]) {
	/* L4 scan configuration */
	cfg_t cfg;
	init_cfg(&cfg);

	/* Fetch device interfaces LL */
	if (get_interfaces(&cfg)) {
		return EXIT_FAILURE;
	}

	if (argc == 1) { // Has no parameters, lists network interfaces and ends, frees resources
		return list_interfaces(cfg.ifaddr);
	}

	/* Parameter processing and parameter functions invocation */
	if (parse_opt(&cfg, argc, argv)) {
		fprintf(stderr, "ipk-l4-scan: error: Unable to parse given optional arguments\n");
		free_cfg(&cfg);
		return EXIT_FAILURE;
	}

	/* Starting point of the scanning process */
	if (start_scan(&cfg)) {
		fprintf(stderr, "ipk-l4-scan: error: scanner failure\n");
		free_cfg(&cfg);
		return EXIT_FAILURE;
	}

	/* Free remaining resources */
	free_cfg(&cfg); 

	return EXIT_SUCCESS;
}