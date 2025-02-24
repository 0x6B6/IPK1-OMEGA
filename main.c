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
/* CTRL + C Signal handle */
#include <signal.h>

/* Project libraries */
#include "opts.h"
#include "net_utils.h"
#include "scan.h"

/* <CTRL + C> Signal handler */
void INThandler(int sig) {
	printf("Terminating the program with interrupt signal - [%d]\n", sig);
}

int main(int argc, char *argv[]) {
	//signal(SIGINT, INThandler);
	/* L4 scan configuration */
	cfg_t cfg;
	init_cfg(&cfg);

	/* Fetch device interfaces LL */
	get_interfaces(&cfg);

	if (argc == 1) { // Has no parameters, lists network interfaces and ends
		return list_interfaces(cfg.ifaddr);
	}

	/* Parameter processing and parameter functions invocation */
	if (parse_opt(&cfg, argc, argv)) {
		fprintf(stderr, "ipk-l4-scan: error: Unable to parse given optional arguments\n");
		free_cfg(&cfg);
		return EXIT_FAILURE;
	}

	/* Starting point of the scanning process */
	start_scan(&cfg);

	/* Free remaining resources */
	free_cfg(&cfg); 

	return EXIT_SUCCESS;
}