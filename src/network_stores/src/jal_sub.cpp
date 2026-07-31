/**
 * @file
 *
 * @brief The JAL subscriber C++ CLI
 *
 * ### LICENSE
 *
 * Copyright (C) 2023 Concurrent Technologies Corporation.
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
#include <argp.h>
#include <sys/stat.h>
#include <signal.h>

#include "jal_alloc.h"
#include <jalop/jal_version.h>
#include <jalop/jal_digest.h>
#include <jalop/jal_seccomp_enforcer.hpp>
#include <JalSubscribe.hpp>
#include "jal_subscribe_config_context.h"


// In order to set up the initial seccomp policy as early as possible, we need to
// create the JalSeccmopEnforcer as soon as we have the config file, but retain the enforcer
// until we're ready to apply the final policy, so even though it's a little awkward,
// we're going to pass a unique_ptr reference into process options as an out-param
static SubscriberConfig process_options(
	int argc,
	char **argv,
	std::unique_ptr<JalSeccompEnforcer>& seccompEnforcer);

// argp
const char *argp_program_version = JAL_VERSION_AS_STR;
const char *argp_program_bug_address = 0;
static char args_doc[] = "--config config_file";
static char doc[] = "jal_sub_cpp - JALoPv2 Network Store that creates an http server to listen for connections from one or more remote JALoPv2 peers and subscribes for JALoP records.";
static struct argp_option options[] =
{
	{"digest-algorithms", 'a', "algs", 0, "Allowable digest algorithms", 0},
	{"config", 'c', "file", 0, "REQUIRED: Specify the path to the configuration file.", 0},
	{"mode", 'm', "mode", 0, "Mode to run on. Valid values are 'archive' or 'live'.", 0},
	{"home", 'h', "db-root", 0, "Specify the root of the JALoP database.", 0},
	{"ipaddr", 'i', "ip-address", 0, "IP Address to listen on.", 0},
	{"port", 't', "port", 0, "Port to listen on.", 0},
	{"debug", 'd', NULL, 0, "Enable debug output.", 0},
	{"disable-tls", 's', NULL, 0, "Disable TLS authentication.", 0},
	{"fs", 'f', NULL, 0, "Use flat file system storage for received records.", 0},
	{NULL, 0, NULL, 0, NULL, 0}
};
static struct argp argp = {options, jal_subscribe_parse_opt, args_doc, doc, NULL, NULL, NULL};
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
		fprintf(stderr, "ERROR: Not enough arguments. See --usage or --help.\n");
		return -1;
	}

	int rc = setup_signals();
	if(rc != 0)
	{
		fprintf(stderr, "ERROR: Cannot set up signal handler.\n");
		return -1;
	}

	try
	{
		std::unique_ptr<JalSeccompEnforcer> seccompEnforcerPtr = nullptr;
		SubscriberConfig config = process_options(argc, argv, seccompEnforcerPtr);

		seccompEnforcerPtr->applyInitial();

		JalSubscriber jsub = JalSubscriber(config);

		seccompEnforcerPtr->applyFinal();

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

static SubscriberConfig process_options(
	int argc,
	char **argv,
	std::unique_ptr<JalSeccompEnforcer>& seccompEnforcerPtr)
{
	struct jal_subscribe_config_context js_conf_ctx = {
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		0,
		0,
		NULL,
		0
	};
	// Guarantee the drop_config_memory function is called on js_conf_ctx
	// no matter how we leave this scope
	struct CtxWrapper
	{
		struct jal_subscribe_config_context& _ctx;
		~CtxWrapper() {jal_subscribe_config_drop_memory(&_ctx);}
	}ctxWrapper{js_conf_ctx};

	int err = argp_parse(&argp, argc, argv, 0, 0, &js_conf_ctx);
	if(0 != err) {
		throw std::runtime_error("ERROR: Cannot parse command line arguments.\n");
	}

	if(js_conf_ctx.conf == NULL)
	{
		throw std::runtime_error("Config file is required");
	}

	// let the constructor throw out to main if there's a failure
	seccompEnforcerPtr = std::make_unique<JalSeccompEnforcer>(js_conf_ctx.conf);

	SubscriberConfig config = SubscriberConfig(std::string(js_conf_ctx.conf));

	if(js_conf_ctx.port != NULL)
	{
		int portno;
		int portlen = strlen(js_conf_ctx.port); // nosemgrep - strlen is needed to get string length here
		int scanLen;
		int ret = sscanf(js_conf_ctx.port, "%d%n", &portno, &scanLen); // nosemgrep - sscanf is needed here and a dynamic length is being used, so can't specify fixed width

		if(ret == 1 && portlen == scanLen) // no error
		{
			config.listenPort = portno;
		}
		else
		{
			throw std::runtime_error("Could not convert port number: " + std::string(js_conf_ctx.port) +
				" to integral type");
		}
	}

	if(NULL != js_conf_ctx.ipaddr)
	{
		config.ipAddr = std::string(js_conf_ctx.ipaddr);
	}

	if(js_conf_ctx.dbpath != NULL)
	{
		//expands file path
		char *expanded_dbpath = jal_expand_path(js_conf_ctx.dbpath, "db_root");

		if (expanded_dbpath != NULL)
		{
			config.databasePath = std::string(expanded_dbpath);
			free(expanded_dbpath);
		}
		else
		{
			throw std::runtime_error("Failed to resolve db_root path in config file");
		}
	}

	if(js_conf_ctx.inmode != NULL)
	{
		// setMode may throw internally
		config.mode = modeTypeFromString(std::string(js_conf_ctx.inmode));
	}

	config.debug = js_conf_ctx.debug;

	if(js_conf_ctx.digest_algorithms)
	{
		config.setDigestAlgorithms(std::string(js_conf_ctx.digest_algorithms));
	}

	if(js_conf_ctx.disableTls)
	{
		config.enableTls = false;
	}

	//Overrides the database_type config setting with command line flag
	if(js_conf_ctx.fs)
	{
		config.dbType = DBType::FS;
	}

	config.printConfiguration();

	return config;
}

