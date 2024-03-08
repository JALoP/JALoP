/*
 * @file jal_linux_seccomp.c This file contains general utility functions.
 *
 * Copyright (C) 2022 The National Security Agency (NSA)
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "jal_linux_seccomp.h"

#include <seccomp.h>
#include <fcntl.h>
#include <linux/seccomp.h> 
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define dfprintf(...){if(seccomp_config.seccomp_debug==1){fprintf(__VA_ARGS__);}}
#define MAX_SYSCALLS 200
#define MAX_SYSCALL_LEN 32

static int configureDisallowSeccomp();
static void catchSeccompViolation(int sig, siginfo_t * si, void * void_context);
static int init_catchSeccompViolation();

char sc_msg[((MAX_SYSCALL_LEN + 12 + 2) * MAX_SYSCALLS) + 64];
char sc_num[12];

int configureInitialSeccomp()
{
	if (seccomp_config.seccomp_strace_mode == 1)
	{
		return 0;
	}
	if (init_catchSeccompViolation() != 0)
	{
		fprintf(stderr, "Could not intialize seccomp signal\n");
		return -1;
	}
	dfprintf(stderr, "configureInitialSeccomp \n");
	scmp_filter_ctx filter_ctx;
	filter_ctx = seccomp_init(SCMP_ACT_TRAP);
	strncpy(sc_msg, "initial syscalls\n[\n", 20);

	const config_setting_t * calls = seccomp_config.initial_syscalls;
	int count = 0;
	if (calls != NULL)
	{
		count = config_setting_length(calls);
	}
	if (count > MAX_SYSCALLS)
	{
		fprintf(stderr, "%i initial syscalls exceeds max syscalls of %i\n", count, MAX_SYSCALLS);
		return -1;
	}

	int call_number = 0;
	for (int x = 0; x < count; x++)
	{
		const char * call_name = config_setting_get_string_elem(calls, x);
		call_number = seccomp_syscall_resolve_name(call_name);
		strncat(sc_msg, call_name, MAX_SYSCALL_LEN);
		strncat(sc_msg, "-", 2);
		snprintf(sc_num, 12, "%d ", call_number);
		strncat(sc_msg, sc_num, 14);
		seccomp_rule_add(filter_ctx, SCMP_ACT_ALLOW, call_number, 0);
		if (seccomp_rule_add(filter_ctx, SCMP_ACT_ALLOW, call_number, 0))
		{
			fprintf(stderr, "configureInitialSeccomp seccomp_rule_add FAILED for %s %i\n", call_name, call_number);
			return -1;
		}
	}
	strncat(sc_msg, "\n]\n", 4);
	dfprintf(stderr, "%s", sc_msg);

	calls = seccomp_config.both_syscalls;
	count = 0;
	if (calls != NULL)
	{
		count = config_setting_length(calls);
	}
	if (count > MAX_SYSCALLS)
	{
		fprintf(stderr, "%i both syscalls exceeds max syscalls of %i\n", count, MAX_SYSCALLS);
		return -1;
	}
	call_number = 0;
	strncpy(sc_msg, "from both syscalls\n[\n", 22);
	for (int x = 0; x < count; x++)
	{
		const char * call_name = config_setting_get_string_elem(calls, x);
		call_number = seccomp_syscall_resolve_name(call_name);
		strncat(sc_msg, call_name, MAX_SYSCALL_LEN);
		strncat(sc_msg, "-", 2);
		snprintf(sc_num, 12, "%d ", call_number);
		strncat(sc_msg, sc_num, 14);
		if (seccomp_rule_add(filter_ctx, SCMP_ACT_ALLOW, call_number, 0))
		{
			fprintf(stderr, "configureInitialSeccomp seccomp_rule_add FAILED for %s %i\n", call_name, call_number);
			return -1;
		}
	}
	strncat(sc_msg, "\n]\n", 4);
	dfprintf(stderr, "%s", sc_msg);

	calls = seccomp_config.final_syscalls;
	count = 0;
	if (calls != NULL)
	{
		count = config_setting_length(calls);
	}
	if (count > MAX_SYSCALLS)
	{
		fprintf(stderr, "%i final syscalls exceeds max syscalls of %i\n", count, MAX_SYSCALLS);
		return -1;
	}
	call_number = 0;
	strncpy(sc_msg, "from final syscalls\n[\n", 23);
	for (int x = 0; x < count; x++)
	{
		const char * call_name = config_setting_get_string_elem(calls, x);
		call_number = seccomp_syscall_resolve_name(call_name);
		strncat(sc_msg, call_name, MAX_SYSCALL_LEN);
		strncat(sc_msg, "-", 2);
		snprintf(sc_num, 12, "%d ", call_number);
		strncat(sc_msg, sc_num, 14);
		if (seccomp_rule_add(filter_ctx, SCMP_ACT_ALLOW, call_number, 0))
		{
			fprintf(stderr, "configureInitialSeccomp seccomp_rule_add FAILED for %s %i\n", call_name, call_number);
			return -1;
		}
	}
	strncat(sc_msg, "\n]\n", 4);
	dfprintf(stderr, "%s", sc_msg);

	if (seccomp_load(filter_ctx) != 0)
	{
		fprintf(stderr, "configureInitialSeccomp seccomp_load FAILED\n");
		return -1;
	}

	dfprintf(stderr, "configureInitialSeccomp DONE \n");

	return 0;
}

int configureFinalSeccomp()
{
	if (seccomp_config.seccomp_strace_mode == 0)
	{
		if (seccomp_config.restrict_seccomp_F_SETFL == 1)
		{
			if (configureDisallowSeccomp() != 0)
			{
				return -1;
			}
		}
		else
		{
			dfprintf(stderr, "Not using restrict_seccomp_F_SETFL.\n");
		}
		dfprintf(stderr, "configureFinalSeccomp \n");
		scmp_filter_ctx filter_ctx;
		filter_ctx = seccomp_init(SCMP_ACT_TRAP);
		strncpy(sc_msg, "both syscalls\n[\n", 17);

		const config_setting_t * calls;

		calls = seccomp_config.both_syscalls;
		int count = 0;
		if (calls != NULL)
		{
			count = config_setting_length(calls);
		}
		if (count > MAX_SYSCALLS)
		{
			fprintf(stderr, "%i final syscalls exceeds max syscalls of %i\n", count, MAX_SYSCALLS);
			return -1;
		}
		int call_number = 0;
		for (int x = 0; x < count; x++)
		{
			const char * call_name = config_setting_get_string_elem(calls, x);
			call_number = seccomp_syscall_resolve_name(call_name);
			strncat(sc_msg, call_name, MAX_SYSCALL_LEN);
			strncat(sc_msg, "-", 2);
			snprintf(sc_num, 12, "%d ", call_number);
			strncat(sc_msg, sc_num, 14);
			if (seccomp_rule_add(filter_ctx, SCMP_ACT_ALLOW, call_number, 0))
			{
				fprintf(stderr, "configureFinalSeccomp seccomp_rule_add FAILED for %s %i\n", call_name, call_number);
				return -1;
			}
		}
		strncat(sc_msg, "\n]\n", 4);
		dfprintf(stderr, "%s", sc_msg);

		strncpy(sc_msg, "final syscalls\n[\n", 18);
		calls = seccomp_config.final_syscalls;
		count = 0;
		if (calls != NULL)
		{
			count = config_setting_length(calls);
		}
		if (count > MAX_SYSCALLS)
		{
			fprintf(stderr, "%i final syscalls exceeds max syscalls of %i\n", count, MAX_SYSCALLS);
			return -1;
		}
		call_number = 0;
		for (int x = 0; x < count; x++)
		{
			const char * call_name = config_setting_get_string_elem(calls, x);
			call_number = seccomp_syscall_resolve_name(call_name);
			strncat(sc_msg, call_name, MAX_SYSCALL_LEN);
			strncat(sc_msg, "-", 2);
			snprintf(sc_num, 12, "%d ", call_number);
			strncat(sc_msg, sc_num, 14);
			if (seccomp_rule_add(filter_ctx, SCMP_ACT_ALLOW, call_number, 0))
			{
				fprintf(stderr, "configureFinalSeccomp seccomp_rule_add FAILED for %s %i\n", call_name, call_number);
				return -1;
			}
		}
		strncat(sc_msg, "\n]\n", 4);
		dfprintf(stderr, "%s", sc_msg);

		if (seccomp_load(filter_ctx) != 0)
		{
			fprintf(stderr, "configureFinalSeccomp seccomp_load FAILED\n");
			return -1;
		}
		dfprintf(stderr, "configureFinalSeccomp DONE \n");
	}
	if(seccomp_config.seccomp_strace_mode==1){
		//When debugging and finding the system calls the process makes,
		//at this point is where the process is done its setup and continues
		//on to do its routine work. This mark will show in your strace output.
		FILE * test_file = fopen("SECCOMP_PROCESS_IS_DONE_SETTING_UP", "r");
		if (test_file){
			fclose(test_file);
			unlink("SECCOMP_PROCESS_IS_DONE_SETTING_UP");
		}
		fprintf(stderr, "Initial setup complete.\n");
	}

	return 0;
}

static int configureDisallowSeccomp()
{
	dfprintf(stderr, "configureDisallowSeccomp \n");
	scmp_filter_ctx filter_ctx;
	filter_ctx = seccomp_init(SCMP_ACT_ALLOW);
	dfprintf(stderr, "seccomp_rule_add(filter_ctx, SCMP_ACT_TRAP, SCMP_SYS(fcntl) , 1, SCMP_A1(SCMP_CMP_EQ, F_SETFL)); \n");

	if (seccomp_rule_add(filter_ctx, SCMP_ACT_TRAP, SCMP_SYS(fcntl), 1, SCMP_A1(SCMP_CMP_EQ, F_SETFL)) != 0)
	{
		fprintf(stderr, "configureDisallowSeccomp seccomp_rule_add FAILED\n");
		return -1;
	}

	if (seccomp_load(filter_ctx) != 0)
	{
		fprintf(stderr, "configureDisallowSeccomp seccomp_load FAILED\n");
		return -1;
	}
	dfprintf(stderr, "configureDisallowSeccomp DONE \n");
	return 0;
}

static void catchSeccompViolation(int sig, siginfo_t * si, void * void_context)
{
	(void) void_context;
	if (SIGSYS == sig)
	{
		if (si->si_code == 1)
		{ //SYS_SECCOMP
			fprintf(stderr, "Exiting. Disallowed system call: %i : %s.\n", si->si_syscall, seccomp_syscall_resolve_num_arch(si->si_arch, si->si_syscall));
			exit(2);
		}
	}
}

static int init_catchSeccompViolation()
{
	struct sigaction action_on_sig;
	action_on_sig.sa_flags = SA_SIGINFO;
	action_on_sig.sa_sigaction = &catchSeccompViolation;
	return sigaction(SIGSYS, &action_on_sig, NULL);
}

int read_sc_config(char * config_path)
{
	int rc = 0;
	config_init(&sc_config);

	if (config_path)
	{
		rc = config_read_file(&sc_config, config_path);
		if (rc == CONFIG_FALSE)
		{
			fprintf(stderr, "Failed to read SECCOMP config file: %s: (%d) %s!\n", config_path, config_error_line(&sc_config), config_error_text(&sc_config));
			return -1;
		}

		// Now get the SECCOMP settings
		rc = config_lookup_bool(&sc_config, "enable_seccomp", &seccomp_config.enable_seccomp);
		if (rc == CONFIG_TRUE)
		{
			// Read initial and final syscalls ONLY if enable_seccomp is non-zero
			if (seccomp_config.enable_seccomp)
			{
				rc = config_lookup_bool(&sc_config, "seccomp_debug", &seccomp_config.seccomp_debug);
				if (rc == CONFIG_FALSE)
				{
					seccomp_config.seccomp_debug = 0;
				}
				
				rc = config_lookup_bool(&sc_config, "seccomp_strace_mode", &seccomp_config.seccomp_strace_mode);
				if (rc == CONFIG_FALSE)
				{
					seccomp_config.seccomp_strace_mode = 0;
				}
				
				fprintf(stderr, "enable_seccomp: %i\n", seccomp_config.enable_seccomp);
				fprintf(stderr, "seccomp_debug: %i\n", seccomp_config.seccomp_debug);
				fprintf(stderr, "seccomp_strace_mode: %i\n", seccomp_config.seccomp_strace_mode);
				
				rc = config_lookup_bool(&sc_config, "restrict_seccomp_F_SETFL", &seccomp_config.restrict_seccomp_F_SETFL);
				if (rc != CONFIG_TRUE)
				{
					seccomp_config.restrict_seccomp_F_SETFL = 0;
				}
				seccomp_config.initial_syscalls = config_lookup(&sc_config, "initial_seccomp_rules");
				if (seccomp_config.initial_syscalls == NULL)
				{
					fprintf(stderr, "Initial syscalls not found in config file %s\n", config_path);
					return -1;
				}
				
				seccomp_config.both_syscalls = config_lookup(&sc_config, "both_seccomp_rules");
				
				seccomp_config.final_syscalls = config_lookup(&sc_config, "final_seccomp_rules");
				if (seccomp_config.final_syscalls == NULL)
				{
					fprintf(stderr, "Final syscalls not found in config file %s\n", config_path);
					return -1;
				}
			}
		}
		else
		{
			fprintf(stderr, "No SECCOMP settings in config file: %s\n", config_path);
			seccomp_config.enable_seccomp = 0;
			return 0;
		}
	}
	else
	{
		fprintf(stderr, "SECCOMP config path NULL\n");
		return -1;
	}

	return 0;
}

void drop_sc_config()
{
	config_destroy(&sc_config);
}
