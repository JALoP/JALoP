/**
 * @file
 *
 * @brief This file contains the C++ definitions
 * used to load and enforcing seccomp policies
 *
 * Copyright (C) 2022 Concurrent Technologies Corporation.
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

#pragma once

#include <vector>
#include <string.h>
#include <libconfig.h>
#include <signal.h>
#include <seccomp.h>
#include "jal_config.h"

/**
 * Struct representing a seccomp rule
 */
struct SeccompRule
{
	/**
	 * Seccomp rule name
	 */
	std::string name;

	/**
	 * Seccomp call number
	 */
	int callNumber;
};

/**
 * LogLevel enum
 */
enum class LogLevel
{
	Debug,
	Error
};

/**
 * JalSeccompEnforcer class
 */
class JalSeccompEnforcer
{
	private:
	/**
	 * Log level
	 */
	LogLevel logLevel = LogLevel::Error;
	/**
	 * Seccomp enabled flag
	 */
	bool seccompEnabled = true;
	/**
	 * Initial seccomp rules applied flag
	 */
	bool initialRulesApplied = false;
	/**
	 * final seccomp rules applied flag
	 */
	bool finalRulesApplied = false;

	/**
	 * Initial seccomp rules
	 */
	std::vector<SeccompRule> initialRules;

	/**
	 * Both seccomp rules
	 */
	std::vector<SeccompRule> bothRules;

	/**
	 * Final seccomp rules
	 */
	std::vector<SeccompRule> finalRules;

	/**
	* Given a seccomp filter, apply a set of rules to that filter
	* Made a class function so it can take advantage of the output function and be
	* logLevel aware
	* @param [in] ctx The seccomp filter context
	* @param [in] rules The vector of seccomp rules to apply.
	*/
	void applyRules(scmp_filter_ctx& ctx, std::vector<SeccompRule> rules);

	/**
	* Seccomp output
	* @param [in] messageLevel The log message level.
	* @param [in] fd The log file.
	* @param [in] fmt The log format.
	*/
	void output(LogLevel messageLevel, FILE* fd, const char* fmt, ...)
		__attribute__((format(printf, 4, 5)));
	// This __attribute__ hints to the compiler that it can inspect the format string
	// // against the following arguments like it does for printf to help catch certain classes
	// // of type errors
	// Note that the parameter list is offset by one due to the implicit "this" parameter
	// of a class member function

	public:

	/**
	* JalSeccompEnforcer constructor
	*
	* @param [in] configFile The config file path
	*
	*/
	JalSeccompEnforcer(std::string configFile);

	/**
	* This function applies the initial seccomp rules
	*
	*/
	void applyInitial();

	/**
	* This function applies the final seccomp rules
	*
	*/
	void applyFinal();
};
