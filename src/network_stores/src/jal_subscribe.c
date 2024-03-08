/*
 * Copyright (C) 2023 The National Security Agency (NSA)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <JalSubscribe.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h> //sleep()
#include <stdlib.h>
#include <string.h>
#include <jalop/jal_status.h>

#include "jal_linux_seccomp.h"

static struct SubscriberConfig_t* process_options(int argc, char **argv);
void usage();

static int keep_running = 1;

static void sig_handler(int sig)
{
	(void)sig;
	keep_running = 0;
}

static int setup_signals(void)
{
	// setup action to trigger process termination
	struct sigaction action_on_sig;
	action_on_sig.sa_handler = &sig_handler;
	sigemptyset(&action_on_sig.sa_mask);
	action_on_sig.sa_flags = 0;

	if (0 != sigaction(SIGABRT, &action_on_sig, NULL))
	{
		fprintf(stderr, "failed to register SIGABRT.\n");
		return -1;
	}
	if (0 != sigaction(SIGTERM, &action_on_sig, NULL))
	{
		fprintf(stderr, "failed to register SIGTERM.\n");
		return -1;
	}
	if (0 != sigaction(SIGINT, &action_on_sig, NULL))
	{
		fprintf(stderr, "failed to register SIGINT.\n");
		return -1;
	}
	return 0;
}


int main(int argc, char** argv)
{
	if(argc == 1)
	{
		usage();
		return -1;
	}

	int rc = setup_signals();
	if(rc != 0)
	{
		printf("ERROR: Cannot set up signal handler.\n");
		return -1;
	}

	char* errBuf = NULL;
	struct SubscriberConfig_t* config = process_options(argc, argv);
	if(NULL == config)
	{
		return -1;
	}

	if(seccomp_config.enable_seccomp){
		if (configureInitialSeccomp()!=0){
			fprintf(stderr, "%s\n", "Cannot configureInitialSeccomp()");
			return -1;
		}
	}
	
	struct Subscriber_t* jsub = jal_subscriber_create(config, &errBuf);
	jal_subscriber_config_destroy(&config);
	
	if(NULL == jsub)
	{
		fprintf(stderr, "%s\n", errBuf);
		return -1;
	}

	if(seccomp_config.enable_seccomp){
		if (configureFinalSeccomp()!=0){
			fprintf(stderr, "%s\n", "Cannot configureFinalSeccomp()");
			return -1;
		}
	}

	while(keep_running)
	{
		sleep(1);
	}

	jal_subscriber_destroy(&jsub);

	return 0;
}


struct SubscriberConfig_t* process_options(int argc, char **argv)
{
	int opt = 0;
	int long_index = 0;
	char *conf = NULL;
	char *port = NULL;
	char *ipaddr = NULL;
	char *inmode = NULL;
	char *dbpath = NULL;
	int debug = 0;
	int disableTls = 0;
	char *digest_algorithms = NULL;
	// BerkelyDB
	int bdb = 0;
	// FileSystem
	int fs = 0;

	// Used in several functions to report additional error information
	char* errBuf = NULL;

	static const char *opt_string = "c:i:t:h:m:dsa:fb";

	static const struct option long_options[] =
	{
		{"config", required_argument, NULL, 'c'},
		{"port", required_argument, NULL, 't'},
		{"home", required_argument, NULL, 'h'},
		{"ipaddr", required_argument, NULL, 'i'},
		{"mode", required_argument, NULL, 'm'},
		{"debug", no_argument, NULL, 'd'},
		{"disable-tls", no_argument, NULL, 's'},
		{"digest-algorithms", required_argument, NULL, 'a'},
		{"fs", no_argument, NULL, 'f'},
		{"bdb", no_argument, NULL, 'b'},
		// Array must end with all NULL row
		{0, 0, 0, 0}
	};

	opt = getopt_long(argc, argv, opt_string, long_options, &long_index);

	while(opt != -1)
	{
		switch (opt)
		{
			case 'c':  // this is the only required option
				conf = optarg;
				break;

			case 't':
				port = optarg;
				break;

			case 'h':
				dbpath = optarg;
				break;

			case 'i':
				ipaddr = optarg;
				break;

			case 'm':
				inmode = optarg;
				break;

			case 'd':
				debug = 1;
				break;
				
			case 'a':
				digest_algorithms = optarg;
				break;

			case 's':
				disableTls = 1;
				break;

			case 'b':
				bdb = 1;
				break;

			case 'f':
				fs = 1;
				break;

			default:
				usage();
				fprintf(stderr, "Unrecognized flag: %c\n", (char)opt);
				return NULL;
		}
		opt = getopt_long(argc, argv, opt_string, long_options, &long_index);
	}

	if(conf == NULL)
	{
		usage();
		fprintf(stderr, "Config file is required\n");
		return NULL;
	}
	
	if(read_sc_config(conf)!=0){
		usage();
		fprintf(stderr, "SECCOMP Config file is corrupted");
	}
	
	struct SubscriberConfig_t* config = jal_subscriber_config_create(conf, &errBuf);
	if(NULL == config)
	{
		fprintf(stderr, "%s\n", errBuf);
		goto err_out;
	}

	if(port != NULL)
	{
		int portno;
		int portlen = strlen(port);
		int scanLen;
		int ret = sscanf(port, "%d%n", &portno, &scanLen);

		if(ret == 1 && portlen == scanLen) // no error
		{
			enum jal_status status = jal_subscriber_config_set_port(config, portno);
			if(JAL_OK != status)
			{
				fprintf(stderr, "Failed to configure port number: %s\n", port);
				goto err_out;
			}
		}
		else
		{
			fprintf(stderr, "Could not convert port number: %s to integral type\n", port);
			goto err_out;
		}
	}

	if(NULL != ipaddr)
	{
		enum jal_status status = jal_subscriber_config_set_server_ip(config, ipaddr);
		if(JAL_OK != status)
		{
			fprintf(stderr, "Could not set server ip address: %s\n", ipaddr);
			goto err_out;
		}
	}

	if(dbpath != NULL)
	{
		enum jal_status status = jal_subscriber_config_set_database_path(config, dbpath);
		if(JAL_OK != status)
		{
			fprintf(stderr, "Could not set dbpath: %s\n", dbpath);
			goto err_out;
		}
	}

	if(inmode != NULL)
	{
		enum jal_status status = jal_subscriber_config_set_mode(config, inmode);
		if(JAL_OK != status)
		{
			fprintf(stderr, "Could not set mode with mode string: %s\n", inmode);
			goto err_out;
		}
	}

	if(debug)
	{
		enum jal_status status = jal_subscriber_config_set_debug(config, 1);
		if(JAL_OK != status)
		{
			fprintf(stderr, "Could not enable debug\n");
			goto err_out;
		}
	}

	
	if(digest_algorithms)
	{
		enum jal_status status = jal_subscriber_config_set_digest_algorithms(
			config,
			digest_algorithms);
		if(JAL_OK != status)
		{
			fprintf(stderr, "Failed to set allowed digest algorithms with input: %s\n",
				digest_algorithms);
			goto err_out;
		}
	}

	if(disableTls)
	{
		enum jal_status status = jal_subscriber_config_set_tls(config, 0);
		if(JAL_OK != status)
		{
			fprintf(stderr, "Failed to disable TLS\n");
			goto err_out;
		}
	}

	if(bdb && fs)
	{
		fprintf(stderr, "Only one of [-f|-b] may be specified\n");
		goto err_out;
	}
	else if(bdb)
	{
		jal_subscriber_config_set_db_type(config, DB_TYPE_BDB);
	}
	else if(fs)
	{
		jal_subscriber_config_set_db_type(config, DB_TYPE_FS);
	}

	jal_subscriber_config_print_configuration(config);

	return config;
err_out:
	if(errBuf)
	{
		free(errBuf);
	}
	if(config)
	{
		jal_subscriber_config_destroy(&config);
	}
	return NULL;
}

void usage()
{
	static const char *usage =
	"Usage:\n\
	-c file, --config=file             REQUIRED: Specify the path to the configuration file.\n\
	-t port, --port=port               Port to listen on.\n\
	-m mode, --mode=mode               Mode to run on. Valid values are 'archive' or 'live'.\n\
	-h H, --home=H                     Specify the root fo the JALoP database.\n\
	-i IP Address, --ipaddr=IP Address Listen IP Address.\n\
	-d, --debug                        Enable debug output.\n\
	-s, --disable-tls                  Disable TLS authentication.\n\
	-a algs, --digest-algorithms=algs  Allowable digest algorithms\n\
	-b, --bdb                          Use BerkelyDB storage for received records\n\
	-f, --fs                           Use flat file system storage for received records\n";

	printf("%s\n", usage);
}

