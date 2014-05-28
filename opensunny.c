/*
 *  OpenSunny -- OpenSource communication with SMA Readers
 *
 *  Copyright (C) 2012 Christian Simon <simon@swine.de>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


/*
 * TODO: Configfile with ini and multi inverter support
 * TODO: Mode for analyzing sniff wireshark binfiles from  Sunny Explorer
 * TODO: Get historic data from inverter
 * TODO: DB Api for value storage
 * TODO: Autodetect Inverters
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>
#define __USE_XOPEN
#include <time.h>

#include "opensunny.h"

char arg_inverter_mac[20];
char arg_date_from[12];
char arg_date_to[12];
struct bluetooth_inverter inverters[MAX_INVERTERS];
int inverter_count = 0;

/*
 * Define Arguments
 */

static const struct option argv_parameters[] = {
	{ "help",		no_argument,		0,	'h' },
	{ "quiet",		no_argument,		0,	'q' },
	{ "verbose",	no_argument,		0,	'v' },
	{ "config",		required_argument,	0,	'c' },
	{ "mode",		required_argument,	0, 	'm' },
	{ "inverter",	required_argument,	0,	'i'	},
	{ "fromdate",	required_argument,	0,	'f'	},
	{ "todate",	    required_argument,	0,	't'	},
};

static const char *argv_help[] = {
	"Show help",
	"Be more quiet, repeatable",
	"Be more verbose, repeatable",
	"Config file",
	"Choose mode of opensunny" ,
	"Define inverter",
	"Define fromdate",	
	"Define todate",
};


void print_help() {

	char mode[128];
	int mode_max_len=0;

	fprintf(stderr,"OpenSunny HELP\n");


	/* Run two times to find max */
	int run = 0;
	while (run < 2){
		for (int arg_pos = 0; arg_pos < (sizeof(argv_parameters)/sizeof(struct option)); ++arg_pos) {
			if (argv_parameters[arg_pos].has_arg == no_argument){
				strncpy(mode,argv_parameters[arg_pos].name,sizeof(mode)-1);
			} else {
				snprintf(mode,sizeof(mode)-1,"%s=<%s>",argv_parameters[arg_pos].name,argv_parameters[arg_pos].name);
				int i;
				for (i = strlen(argv_parameters[arg_pos].name)+2; i < (2*strlen(argv_parameters[arg_pos].name)+2); ++i)
					mode[i]=toupper(mode[i]);
			}
			if (strlen(mode) > mode_max_len)
				mode_max_len = strlen(mode);

			if (run >0)
				fprintf(stderr,"  -%c, --%-*s %s \n", argv_parameters[arg_pos].val,mode_max_len+1,mode, argv_help[arg_pos]);

		}
		run++;
	}


}


int parse_args(int argc, char **argv) {

	int arg_verbosity = 0;

	int count;

	if (argc > 1) {
		for (count = 1; count < argc; count++) {
			log_debug("Argument received argv[%d] = %s", count, argv[count]);

			if (strcmp(argv[count], "-v") == 0) {
				arg_verbosity++;
			} else if (strcmp(argv[count], "-i") == 0) {
				count++;
				strncpy(arg_inverter_mac, argv[count], 19);
			} else if (strcmp(argv[count], "-f") == 0) {
				count++;
				strncpy(arg_date_from, argv[count], 10);
			}  else if (strcmp(argv[count], "-t") == 0) {
				count++;
				strncpy(arg_date_to, argv[count], 10);
			}
		}

		if (arg_verbosity == 1) {
			logging_set_loglevel(logger, ll_verbose);
		} else if (arg_verbosity == 2) {
			logging_set_loglevel(logger, ll_debug);
		}

		if (strlen(arg_inverter_mac) != 17) {
			printf("Wrong mac!\n\n");
			print_help();
			exit(EXIT_FAILURE);
		}

	} else {
		print_help();
		exit(EXIT_FAILURE);
	}

	return 0;

}

/* Main Routine smatool */
int main(int argc, char **argv) {

	/* Enable Logging */
	log_init();

//	/* Parsing Args */
	parse_args(argc, argv);

	/* Inizialize Bluetooth Inverter */
	struct bluetooth_inverter inv = { { 0 } };

	strcpy(inv.macaddr, arg_inverter_mac);

	memcpy(inv.password, "0000", 5);

	int attempts = 1, maxattempts = 20;
	do
	{
		log_info("[Value] Connecting to %s (%d/%d)\n", inv.macaddr, attempts, maxattempts);
		in_bluetooth_connect(&inv);
		attempts++;
	} while ((attempts <= maxattempts) && (inv.socket_status != 0));

	/* Setup Sma-connection */
	in_smadata2plus_connect(&inv);

	/* Setup Sma-login */
	in_smadata2plus_login(&inv);

	/* Get from & to timestamps */
	time_t day_start, day_end;
	struct tm *loctime;

	day_start = time (NULL);
	loctime = localtime (&day_start);
    strptime(arg_date_from, "%Y%m%d", loctime);
    loctime->tm_hour = 0;
    loctime->tm_min = 0;
    loctime->tm_sec = 0;
    day_start = mktime(loctime);
    strptime(arg_date_to, "%Y%m%d", loctime);
    loctime->tm_hour = 23;
    loctime->tm_min = 55;
    loctime->tm_sec = 0;
   	day_end = mktime(loctime);

	/* Get Day Values */   	
	in_smadata2plus_get_day_values(&inv,day_start,day_end);

	close(inv.socket_fd);

	exit(0);
}
