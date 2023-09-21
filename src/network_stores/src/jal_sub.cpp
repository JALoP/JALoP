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
#include <string>
#include <vector>
#include <array>
#include <cstring>
#include <exception>
#include <fstream>
#include <unistd.h> // sleep()
#include <getopt.h>
#include <signal.h>

#include "jal_alloc.h"
#include <jalop/jal_digest.h>
#include <JalSubscribe.hpp>

static SubscriberConfig process_options(int argc, char **argv);
void usage();

static int keep_running = true;

static void sig_handler(int sig)
{
	(void)sig;
	keep_running = false;
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

	try
	{
		SubscriberConfig config = process_options(argc, argv);

		JalSubscriber jsub = JalSubscriber(config);

		while(keep_running)
		{
			sleep(1);
		}

	}
	catch(std::runtime_error &e)
	{
		printf("%s\n", e.what());
		return -1;
	}

	return 0;
}


SubscriberConfig process_options(int argc, char **argv)
{
	int opt = 0;
	int long_index = 0;
	char *conf = NULL;
	char *port = NULL;
	char *ipaddr = NULL;
	char *inmode = NULL;
	char *dbpath = NULL;
	bool debug = false;
	bool disableTls = false;
	char *digest_algorithms = NULL;
	// BerkeleyDB
	bool bdb = false;
	// FileSystem
	bool fs = false;

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
				debug = true;
				break;
				
			case 'a':
				digest_algorithms = optarg;
				break;

			case 's':
				disableTls = true;
				break;

			case 'b':
				bdb = true;
				break;

			case 'f':
				fs = true;
				break;

			default:
				usage();
				throw std::runtime_error("Unrecognized flag: " + std::to_string(opt));
		}
		opt = getopt_long(argc, argv, opt_string, long_options, &long_index);
	}

	if(conf == NULL)
	{
		usage();
		throw std::runtime_error("Config file is required");
	}

	SubscriberConfig config = SubscriberConfig(std::string(conf));

	if(port != NULL)
	{
		int portno;
		int portlen = strlen(port);
		int scanLen;
		int ret = sscanf(port, "%d%n", &portno, &scanLen);

		if(ret == 1 && portlen == scanLen) // no error
		{
			config.listenPort = portno;
		}
		else
		{
			throw std::runtime_error("Could not convert port number: " + std::string(port) + 
				" to integral type");
		}
	}

	if(NULL != ipaddr)
	{
		config.ipAddr = std::string(ipaddr);
	}

	if(dbpath != NULL)
	{
		config.databasePath = std::string(dbpath);
	}

	if(inmode != NULL)
	{
		// setMode may throw internally
		config.mode = modeTypeFromString(std::string(inmode));
	}

	config.debug = debug;
	
	if(digest_algorithms)
	{
		config.setDigestAlgorithms(std::string(digest_algorithms));
	}

	if(disableTls)
	{
		config.enableTls = false;
	}

	if(bdb && fs)
	{
		throw std::runtime_error("Only one of [-f|-b] may be specified");
	}
	else if(bdb)
	{
		config.dbType = DBType::BDB;
	}
	else if(fs)
	{
		config.dbType = DBType::FS;
	}

	config.printConfiguration();

	return config;
}

void usage()
{
	static const char *usage =
	"Usage:\n\
	-a algs, --digest-algorithms=algs  Supported digest algorithms\n\
	-b, --bdb                          Use BerkeleyDB storage for received records\n\
	-c file, --config=file             REQUIRED: Specify the path to the configuration file.\n\
	-d, --debug                        Enable debug output.\n\
	-f, --fs                           Use flat file system storage for received records\n\
	-h H, --home=H                     Specify the root of the JALoP database.\n\
	-i IP Address, --ipaddr=IP Address Listen IP Address.\n\
	-m mode, --mode=mode               Mode to run on. Valid values are 'archive' or 'live'.\n\
	-s, --disable-tls                  Disable TLS authentication.\n\
	-t port, --port=port               Port to listen on.\n";

	printf("%s\n", usage);
}

