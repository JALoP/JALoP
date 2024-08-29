/*
 * @file jal_seccomp_enforcer_impl.cpp This file contains the C++ implementation
 * for functions used to load and enforce seccomp policies
 *
 * Copyright (C) 2024 The National Security Agency (NSA)
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
#include <string>
#include <vector>
#include <libconfig.h>
#include <seccomp.h>
#include "jal_config.h"
#include <stdexcept>
#include <stdarg.h>
#include <jalop/jal_seccomp_enforcer.hpp>
#include <fcntl.h> // Sepcifically for F_SETFL and O_NONBLOCK constants
#include <sys/ioctl.h> // Sepcifically for FIONREAD constant

// File-local string constants
static const char SC_CFG_DEBUG[] = "seccomp_debug";
static const char SC_CFG_ENABLE[] =  "enable_seccomp";
static const char SC_CFG_INITIAL_SYSCALLS[] = "initial_seccomp_rules";
static const char SC_CFG_BOTH_SYSCALLS[] = "both_seccomp_rules";
static const char SC_CFG_FINAL_SYSCALLS[] = "final_seccomp_rules";

static void catchSeccompViolation(int sig, siginfo_t * si, void * void_context)
{
	(void) void_context;
	if (SIGSYS == sig)
	{
		if (si->si_code == 1)
		{ //SYS_SECCOMP
			fprintf(stderr,
				"Exiting. Disallowed system call: %i : %s.\n",
				si->si_syscall,
				seccomp_syscall_resolve_num_arch(si->si_arch, si->si_syscall));
			exit(2);
		}
	}
}

static int initCatchSeccompViolation()
{
	struct sigaction action_on_sig;
	action_on_sig.sa_flags = SA_SIGINFO;
	action_on_sig.sa_sigaction = &catchSeccompViolation;
	return sigaction(SIGSYS, &action_on_sig, NULL);
}

// Helper function to avoid repeating logic for extracting a libconfig list of strings
// and converting the contents into SeccompRule items
// Throws a runtime_error if any error occurs
static void addRules(
	config_setting_t* configRoot,
	const char* settingName,
	std::vector<SeccompRule>& rules,
	bool rulesetOptional)
{
	config_setting_t* setting = NULL;
	int numEntries = 0;
	if(JAL_CFG_SUCCESS != jal_config_lookup_list(configRoot,
		settingName,
		&setting,
		&numEntries,
		rulesetOptional ? JAL_CFG_OPTIONAL : JAL_CFG_REQUIRED)
		)
	{
		std::string errMsg = "Error: Unable to process: " + std::string(settingName)
			+ " configuration paramter";
			throw std::runtime_error(errMsg);
	}

	if(NULL != setting)
	{
		for(int i = 0; i < numEntries; i++)
		{
			char* syscallName = NULL;
			int rc = jal_config_get_elem_string(setting, i, &syscallName, settingName);
			if(JAL_CFG_SUCCESS != rc)
			{
				std::string errMsg = "Error: Unable to extract element: " + std::to_string(i) +
					" from setting: " + std::string(settingName);
				throw std::runtime_error(errMsg);
			}
			int callNumber = seccomp_syscall_resolve_name(syscallName);
			if(__NR_SCMP_ERROR == callNumber)
			{
				std::string errMsg = "Error: Unable to resolve syscall name: " +
					std::string(settingName) + ".";
				throw std::runtime_error(errMsg);
			}
			rules.push_back({std::string(syscallName), callNumber});
		}
	}
}


JalSeccompEnforcer::JalSeccompEnforcer(std::string configFile)
{
	config_t config;
	// Attempt to load config file
	if(JAL_CFG_SUCCESS != jal_config_init(&config))
	{
		throw std::runtime_error("Error: Unable to initialize config_t");
	}

	// Now that the config_t is initialized, create a tiny struct to guarantee destruction
	// of the config_t no matter how we exit this function
	struct ConfigWrapper
	{
		config_t& configRef;
		~ConfigWrapper() { config_destroy(&configRef); }
	} configWrapper{config};

	if(JAL_CFG_SUCCESS != jal_config_read_file(&config, configFile.c_str()))
	{
		std::string errMsg = "Error: Unable to read config file: " + configFile;
		throw std::runtime_error(errMsg);
	}

	// Extract root configuration setting
	config_setting_t *configRoot = config_root_setting(&config);

	// Extract enable_seccomp setting
	int enableSeccomp = 0;
	if(JAL_CFG_SUCCESS != jal_config_lookup_bool(
			configRoot,
			SC_CFG_ENABLE,
			&enableSeccomp,
			JAL_CFG_REQUIRED)
		)
	{
		std::string errMsg = "Error: Unable to process: " + std::string(SC_CFG_ENABLE) + 
			" configuration parameter";
		throw std::runtime_error(errMsg);
	}

	// If seccomp isn't enabled, we're done, bail out and ignore the rest of the settings
	if(0 == enableSeccomp)
	{
		this->seccompEnabled = false;
		return;
	}

	// Extract (optional) seccomp_debug setting and increase the logging level to DEBUG
	// if seccomp_debug is present and true
	int printDebug = 0;
	if(JAL_CFG_SUCCESS != jal_config_lookup_bool(
			configRoot,
			SC_CFG_DEBUG,
			&printDebug,
			JAL_CFG_OPTIONAL)
		)
	{
		std::string errMsg = "Error: Unable to process: " + std::string(SC_CFG_DEBUG) + 
			" configuration parameter";
		throw std::runtime_error(errMsg);
	}
	if(1 == printDebug)
	{
		this->logLevel = LogLevel::Debug;
	}

	// If debugging has been requested, print the enable/disable state
	output(
		LogLevel::Debug,
		stderr,
		"%s: %i\n",
		SC_CFG_ENABLE,
		printDebug);

	// Extract each list of rules and resolve to syscall ids
	addRules(configRoot, SC_CFG_INITIAL_SYSCALLS, this->initialRules, false);
	addRules(configRoot, SC_CFG_BOTH_SYSCALLS, this->bothRules, true);
	addRules(configRoot, SC_CFG_FINAL_SYSCALLS, this->finalRules, false);
}

// Helpler to consolidate logic for adding a set of SeccompRules to a given scmp_filter_ctx
// with appropriate logging.
// Not to be used for rules which specify arguments.
// Whitelist rules only
// Made a private class member so it can be logLevel aware and use the output function
void JalSeccompEnforcer::applyRules(
	scmp_filter_ctx& filter_ctx,
	std::vector<SeccompRule> rules)
{
	output(LogLevel::Debug, stderr, "[\n");
	for(const auto& rule : rules)
	{
		if(0 != seccomp_rule_add(filter_ctx, SCMP_ACT_ALLOW, rule.callNumber, 0))
		{
			std::string errMsg = "Error: seccomp_rule_add FAILED for " + rule.name
				+ "(" + std::to_string(rule.callNumber) + ")";
			throw std::runtime_error(errMsg);
		}
		output(LogLevel::Debug, stderr, "%s(%d) ", rule.name.c_str(), rule.callNumber);
	}
	output(LogLevel::Debug, stderr, "\n]\n");
}

void JalSeccompEnforcer::applyInitial()
{
	// Do nothing if seccomp isn't enabled by the config
	if(!(this->seccompEnabled)) {return;}

	if(this->initialRulesApplied)
	{
		// If a set of initial rules has already been applied, throw an error
		std::string errMsg = "Error: Initial Seccomp rules already applied";
		throw std::runtime_error(errMsg);
	}

	output(LogLevel::Debug, stderr, "configureInitialSeccomp \n");

	scmp_filter_ctx filter_ctx = seccomp_init(SCMP_ACT_TRAP);
	if(NULL == filter_ctx)
	{
		std::string errMsg = "Error: Failed to create scmp_filter_ctx";
		throw std::runtime_error(errMsg);
	}
	
	// Create a tiny struct to guarantee destrution of the scmp_filter_ctx
	// no matter how we exit the function
	struct FilterWrapper
	{
		scmp_filter_ctx& ctx;
		~FilterWrapper() {seccomp_release(ctx);}
	} filterWrapper{filter_ctx};

	// Set up a signal trap for a policy violation
	if(0 != initCatchSeccompViolation())
	{
		std::string errMsg = "Could not initialize seccomp signal";
		throw std::runtime_error(errMsg);
	}

	// Seccomp policies can't be un-applied, and anything not in our allow list
	// is considered illegal. Later filters will be evaluated IN ADDITION to, rather than
	// instead of this initial filter. So our "initial" ruleset must be a union of the
	// initial and final rulesets
	// Apply each rule
	output(LogLevel::Debug, stderr, "Applying initial ruleset\n");
	output(LogLevel::Debug, stderr, "From initial syscalls\n");
	applyRules(filter_ctx, this->initialRules);
	if(!(this->bothRules.empty()))
	{
		output(LogLevel::Debug, stderr, "From both syscalls\n");
		applyRules(filter_ctx, this->bothRules);
	}
	output(LogLevel::Debug, stderr, "From final syscalls\n");
	applyRules(filter_ctx, this->finalRules);

	// Now that all the rules have been applied to the filter, load the filter
	if(0 != seccomp_load(filter_ctx))
	{
		std::string errMsg = "Failed to apply filter with seccomp_load\n";
		throw std::runtime_error(errMsg);
	}
	output(LogLevel::Debug, stderr, "Applying initial ruleset DONE\n");

	// Finally, mark that initial rules have been applied so we don't do it again
	this->initialRulesApplied = true;
}

void JalSeccompEnforcer::applyFinal()
{
	// Do nothing if seccomp isn't enabled by the config
	if(!(this->seccompEnabled)) {return;}

	if(this->finalRulesApplied)
	{
		// If a set of final rules has already been applied, throw an error
		std::string errMsg = "Error: Final Seccomp rules already applied";
		throw std::runtime_error(errMsg);
	}

	if(!this->initialRulesApplied)
	{
		std::string errMsg = "Error: Final Seccomp rules must not be applied before"
			" Initial Seccomp rules. If a two-stage ruleset is not required, use only the initial"
			" ruleset.";
		throw std::runtime_error(errMsg);
	}

	output(LogLevel::Debug, stderr, "configureFinalSeccomp \n");

	scmp_filter_ctx filter_ctx = seccomp_init(SCMP_ACT_TRAP);
	if(NULL == filter_ctx)
	{
		std::string errMsg = "Error: Failed to create scmp_filter_ctx";
		throw std::runtime_error(errMsg);
	}
	
	// Create a tiny struct to guarantee destrution of the scmp_filter_ctx
	// no matter how we exit the function
	struct FilterWrapper
	{
		scmp_filter_ctx& ctx;
		~FilterWrapper() {seccomp_release(ctx);}
	} filterWrapper{filter_ctx};

	// Apply each rule
	output(LogLevel::Debug, stderr, "Applying Final ruleset\n");
	if(!(this->bothRules.empty()))
	{
		output(LogLevel::Debug, stderr, "From both syscalls\n");
		applyRules(filter_ctx, this->bothRules);
	}
	output(LogLevel::Debug, stderr, "From final syscalls\n");
	applyRules(filter_ctx, this->finalRules);

	// Now that all the rules have been applied to the filter, load the filter
	if(0 != seccomp_load(filter_ctx))
	{
		std::string errMsg = "Failed to apply filter with seccomp_load\n";
		throw std::runtime_error(errMsg);
	}
	output(LogLevel::Debug, stderr, "Applying final ruleset DONE\n");

	// Finally, mark that final rules have been applied so we don't do it again
	this->finalRulesApplied = true;
}

void JalSeccompEnforcer::output(LogLevel messageLevel, FILE* fd, const char* fmt, ...)
{
	// If the log level for this enforcer has been set to Debug or if the log level
	// for this message is Error, print. Otherwise do nothing
	if(LogLevel::Debug == this->logLevel ||
		LogLevel::Error == messageLevel)
	{
		va_list args;
		va_start(args, fmt);
		vfprintf(fd, fmt, args);
		va_end(args);
	}
}
