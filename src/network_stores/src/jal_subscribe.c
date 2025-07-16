/**
 * @file
 *
 * @brief The JAL subscriber CLI
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

#include <JalSubscribe.h>
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h> //sleep()
#include <stdlib.h>
#include <string.h>
#include <jal_config.h>
#include <jalop/jal_status.h>
#include <jalop/jal_version.h>

#include <jalop/jal_seccomp_enforcer.h>
#include "jal_subscribe_config_context.h"

// In order to set up the initial seccomp policy as early as possible, we need to
// create the JalSeccmopEnforcer as soon as we have the config file, but retain the enforcer
// until we're ready to apply the final policy, so even though it's a little awkward,
// we're going to pass a pointer into process options as an out-param
static struct SubscriberConfig_t* process_options(
	int argc,
	char **argv,
	struct jal_seccomp_enforcer_t** seccomp_enforcer);

// argp
const char *argp_program_version = JAL_VERSION_AS_STR;
const char *argp_program_bug_address = 0;
static char args_doc[] = "--config config_file";
static char doc[] = "jal_subscribe - JALoPv2 Network Store that creates an http server to listen for connections from one or more remote JALoPv2 peers and subscribes for JALoP records.";
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
		fprintf(stderr, "ERROR: Not enough arguments. See --usage or --help.\n");
		return -1;
	}

	int rc = setup_signals();
	if(rc != 0)
	{
		fprintf(stderr, "ERROR: Cannot set up signal handler.\n");
		return -1;
	}

	char* errBuf = NULL;
	struct jal_seccomp_enforcer_t* seccomp_enforcer = NULL;
	struct SubscriberConfig_t* config = process_options(argc, argv, &seccomp_enforcer);
	if(NULL == config || NULL == seccomp_enforcer)
	{
		return -1;
	}

	if (0 != jal_seccomp_enforcer_apply_initial(seccomp_enforcer)){
		fprintf(stderr, "Failed to apply initial seccomp policy\n");
		goto out;
	}

	struct Subscriber_t* jsub = jal_subscriber_create(config, &errBuf);
	jal_subscriber_config_destroy(&config);

	if(NULL == jsub)
	{
		fprintf(stderr, "%s\n", errBuf);
		goto out;
	}

	if (0 != jal_seccomp_enforcer_apply_final(seccomp_enforcer)){
		fprintf(stderr, "Failed to apply final seccomp policy\n");
		goto out;
	}

	while(keep_running)
	{
		sleep(1);
	}

out:
	jal_subscriber_destroy(&jsub);
	jal_seccomp_enforcer_destroy(&seccomp_enforcer);
	free(errBuf);

	return 0;
}

static struct SubscriberConfig_t* process_options(
	int argc,
	char **argv,
	struct jal_seccomp_enforcer_t** seccomp_enforcer)
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

	char* errBuf = NULL;
	struct SubscriberConfig_t* config = NULL;

	int err = argp_parse(&argp, argc, argv, 0, 0, &js_conf_ctx);
	if(0 != err) {
		fprintf(stderr, "ERROR: Cannot parse command line arguments.\n");
		goto err_out;
	}
	// Used in several functions to report additional error information

	if(js_conf_ctx.conf == NULL)
	{
		fprintf(stderr, "Config file is required\n");
		goto err_out;
	}

	// Create a seccomp policy enforcer using the config file
	*seccomp_enforcer = jal_seccomp_enforcer_create(js_conf_ctx.conf);
	if(NULL == seccomp_enforcer){
		fprintf(stderr, "Failed to create seccomp enforcer\n");
		goto err_out;
	}

	config = jal_subscriber_config_create(js_conf_ctx.conf, &errBuf);
	if(NULL == config)
	{
		fprintf(stderr, "%s\n", errBuf);
		goto err_out;
	}

	if(js_conf_ctx.port != NULL)
	{
		int portno;
		int portlen = strlen(js_conf_ctx.port);
		int scanLen;
		int ret = sscanf(js_conf_ctx.port, "%d%n", &portno, &scanLen);

		if(ret == 1 && portlen == scanLen) // no error
		{
			enum jal_status status = jal_subscriber_config_set_port(config, portno);
			if(JAL_OK != status)
			{
				fprintf(stderr, "Failed to configure port number: %s\n", js_conf_ctx.port);
				goto err_out;
			}
		}
		else
		{
			fprintf(stderr, "Could not convert port number: %s to integral type\n", js_conf_ctx.port);
			goto err_out;
		}
	}

	if(NULL != js_conf_ctx.ipaddr)
	{
		enum jal_status status = jal_subscriber_config_set_server_ip(config, js_conf_ctx.ipaddr);
		if(JAL_OK != status)
		{
			fprintf(stderr, "Could not set server ip address: %s\n", js_conf_ctx.ipaddr);
			goto err_out;
		}
	}

	if(js_conf_ctx.dbpath != NULL)
	{
		//expands file path
		char *expanded_dbpath = jal_expand_path(js_conf_ctx.dbpath, "db_root");

		if (expanded_dbpath != NULL)
		{
			enum jal_status status = jal_subscriber_config_set_database_path(config, expanded_dbpath);
			if(JAL_OK != status)
			{
				fprintf(stderr, "Could not set dbpath: %s\n", expanded_dbpath);
				free(expanded_dbpath);
				goto err_out;
			}
			free(expanded_dbpath);
		}
		else
		{
			//Error displayed in method above
			goto err_out;
		}
	}

	if(js_conf_ctx.inmode != NULL)
	{
		enum jal_status status = jal_subscriber_config_set_mode(config, js_conf_ctx.inmode);
		if(JAL_OK != status)
		{
			fprintf(stderr, "Could not set mode with mode string: %s\n", js_conf_ctx.inmode);
			goto err_out;
		}
	}

	if(js_conf_ctx.debug)
	{
		enum jal_status status = jal_subscriber_config_set_debug(config, 1);
		if(JAL_OK != status)
		{
			fprintf(stderr, "Could not enable debug\n");
			goto err_out;
		}
	}

	if(js_conf_ctx.digest_algorithms)
	{
		enum jal_status status = jal_subscriber_config_set_digest_algorithms(
			config,
			js_conf_ctx.digest_algorithms);
		if(JAL_OK != status)
		{
			fprintf(stderr, "Failed to set allowed digest algorithms with input: %s\n",
				js_conf_ctx.digest_algorithms);
			goto err_out;
		}
	}

	if(js_conf_ctx.disableTls)
	{
		enum jal_status status = jal_subscriber_config_set_tls(config, 0);
		if(JAL_OK != status)
		{
			fprintf(stderr, "Failed to disable TLS\n");
			goto err_out;
		}
	}

	//Overrides the database_type config setting with command line flag
	if(js_conf_ctx.fs)
	{
		jal_subscriber_config_set_db_type(config, DB_TYPE_FS);
	}

	jal_subscriber_config_print_configuration(config);

	if(errBuf)
	{
		free(errBuf);
	}

	jal_subscribe_config_drop_memory(&js_conf_ctx);
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
	jal_subscribe_config_drop_memory(&js_conf_ctx);
	return NULL;
}

