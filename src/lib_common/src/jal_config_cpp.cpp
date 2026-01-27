/**
 * @file
 *
 * @brief This file contains implementations for utility functions
 * for reading config files with a C++ compliant interface. Intended
 * to be an optional extension to the C interface, not a replacement.
 *
 * ### LICENSE
 *
 * Copyright (C) 2025 Concurrent Technologies Corporation.
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
#include <stdexcept>
#include <libconfig.h>
#include "jal_config.h"
#include "jal_config_cpp.hpp"

std::string jal_config_lookup_cpp_string(
	const config_setting_t* setting,
	const std::string name,
	const int required,
	const std::string default_value)
{
	return jal_config_lookup_cpp_string(setting, name.c_str(), required, default_value);
}

std::string jal_config_lookup_cpp_string(
	const config_setting_t* setting,
	const char* name,
	const int required,
	const std::string default_value)
{
	if(NULL == setting) {
		std::string msg = std::string("NULL setting passed to jal_config_lookup_cpp_string");
		throw std::runtime_error(msg);
	}
	if(NULL == name) {
		std::string msg = std::string("NULL name passed to jal_config_lookup_cpp_string");
		throw std::runtime_error(msg);
	}
	char* temp_str = NULL;
	if(JAL_CFG_SUCCESS != jal_config_lookup_string(
				setting,
				name,
				&temp_str,
				required)) {
		std::string msg = config_error_context(setting, name)
			+ std::string("Failed to extract string value");
		throw std::runtime_error(msg);
	}
	if(NULL != temp_str) {
		std::string rv = std::string(temp_str);
		free(temp_str);
		return std::string(rv);
	} else if(JAL_CFG_OPTIONAL == required) {
		return default_value;
	} else {
		std::string msg = config_error_context(setting, name)
			+  std::string("Extracted NULL values for: ") + name;
		throw std::runtime_error(msg);
	}
}

std::string jal_config_lookup_cpp_file_path(
	const config_setting_t* setting,
	const std::string name,
	const int required,
	const std::string default_value,
	const bool must_exist) {
	return jal_config_lookup_cpp_file_path(setting, name.c_str(), required, default_value, must_exist);
}

std::string jal_config_lookup_cpp_file_path(
	const config_setting_t* setting,
	const char* name,
	const int required,
	const std::string default_value,
	const bool must_exist) {
	if(NULL == setting) {
		std::string msg = std::string("NULL setting passed to jal_config_lookup_cpp_path");
		throw std::runtime_error(msg);
	}
	if(NULL == name) {
		std::string msg = std::string("NULL name passed to jal_config_lookup_cpp_path");
		throw std::runtime_error(msg);
	}
	std::string config_val = jal_config_lookup_cpp_string(setting, name, required, default_value);

	// If we didn't find the desired string, and the path is not required
	// return the default value.
	// This will also be triggered if we didn't find the desired string and the default_value
	// was set to ""
	if(JAL_CFG_OPTIONAL == required && config_val.empty()) {
		return default_value;
	}

	// Ensure the discovered string doesn't end with /
	if('/' == config_val.back()) {
		std::string msg = std::string("Discovered file path: ") + config_val
			+ std::string(" looks like a directory. Expected file.");
		throw std::runtime_error(msg);
	}

	// We have a string value of some kind
	// First expand home dir if ~/ exists at the start of the file path
	char *expanded_path = jal_expand_home_dir(config_val.c_str(), name);
	if(NULL == expanded_path) {
		std::string msg = std::string("Failed to expand file path: ") + config_val;
		throw std::runtime_error(msg);
	} else {
		config_val = std::string(expanded_path);
		free(expanded_path);
	}

	// If the file must exist, attempt to resolve the discovered file path to an absolute path
	if(must_exist) {
		char* expanded_str = jal_expand_path(config_val.c_str(), name);
		if (expanded_str == NULL)
		{
			//Error already displayed from method call above
			std::string msg = std::string("Failed to expand path: ")
				+ std::string(name)
				+ std::string(" with value: ") + config_val;
			throw std::runtime_error(msg);
		}
		std::string rv = std::string(expanded_str);
		free(expanded_str);
		return rv;
	}

	// Otherwise, split into dir_path and filename based on the last "/"
	// and attempt to resolve that to an absolute path to ensure the containing directory
	// exists
	size_t last_slash_pos = config_val.rfind("/");
	std::string dir_path;
	std::string filename;
	// If we don't find a slash, assume that the entire string is a filename in the local
	// directory
	if(last_slash_pos == std::string::npos) {
		filename = config_val;
		dir_path = std::string("./");
	} else {
		// We know that last_slash_pos + 1 is a valid string index because we checked
		// for a trailing / earlier, and an empty string would have exited this function
		// earlier
		filename = config_val.substr(last_slash_pos + 1);
		dir_path = config_val.substr(0, config_val.length() - filename.length());
	}

	// Attempt to resolve our dir_path as an absolute path
	char* expanded_str = jal_expand_path(dir_path.c_str(), name);
	if (expanded_str == NULL)
	{
		std::string msg = std::string("Failed to expand containing directory for: ")
			+ std::string(name)
			+ std::string(" with value: ") + dir_path;
		throw std::runtime_error(msg);
	}
	std::string expanded_dir_path = std::string(expanded_str);
	free(expanded_str);

	return expanded_dir_path + "/" + filename;
}


std::string jal_config_lookup_cpp_path(
	const config_setting_t* setting,
	const std::string name,
	const int required,
	const std::string default_value)
{
	return jal_config_lookup_cpp_path(setting, name.c_str(), required, default_value);
}

std::string jal_config_lookup_cpp_path(
	const config_setting_t* setting,
	const char* name,
	const int required,
	const std::string default_value)
{
	if(NULL == setting) {
		std::string msg = std::string("NULL setting passed to jal_config_lookup_cpp_path");
		throw std::runtime_error(msg);
	}
	if(NULL == name) {
		std::string msg = std::string("NULL name passed to jal_config_lookup_cpp_path");
		throw std::runtime_error(msg);
	}
	std::string config_val = jal_config_lookup_cpp_string(setting, name, required, default_value);

	// If we didn't find the desired string, and the path is not required
	// return the default value.
	// This will also be triggered if we didn't find the desired string and the default_value
	// was set to ""
	if(JAL_CFG_OPTIONAL == required && config_val.empty()) {
		return default_value;
	}

	char* expanded_str = jal_expand_path(config_val.c_str(), name);
	if (expanded_str == NULL)
	{
		//Error already displayed from method call above
		std::string msg = std::string("Failed to expand path: ")
			+ std::string(name)
			+ std::string(" with value: ") + config_val;
		throw std::runtime_error(msg);
	}
	std::string rv = std::string(expanded_str);
	free(expanded_str);
	return rv;
}

int jal_config_lookup_cpp_int(
	const config_setting_t* setting,
	const std::string name,
	const int required,
	const int default_value)
{
	return jal_config_lookup_cpp_int(setting, name.c_str(), required, default_value);
}

int jal_config_lookup_cpp_int(
	const config_setting_t* setting,
	const char* name,
	const int required,
	const int default_value)
{
	if(NULL == setting) {
		std::string msg = std::string("NULL setting passed to jal_config_lookup_cppint");
		throw std::runtime_error(msg);
	}
	if(NULL == name) {
		std::string msg = std::string("NULL name passed to jal_config_lookup_cpp_int");
		throw std::runtime_error(msg);
	}
	long long int temp_int = default_value;
	// Extract poll time
	if(JAL_CFG_SUCCESS != jal_config_lookup_int64(
		setting,
		name,
		&temp_int,
		required)) {
			// Error printed internally
			std::string msg = std::string("Failed to get: ") + std::string(name);
			throw std::runtime_error(msg);
	}
	return temp_int;
}

long long int jal_config_lookup_cpp_int64(
	const config_setting_t* setting,
	const std::string name,
	const int required,
	const long long default_value)
{
	return jal_config_lookup_cpp_int64(setting, name.c_str(), required, default_value);
}

long long int jal_config_lookup_cpp_int64(
	const config_setting_t* setting,
	const char* name,
	const int required,
	const long long int default_value)
{
	if(NULL == setting) {
		std::string msg = std::string("NULL setting passed to jal_config_lookup_cpp_int64");
		throw std::runtime_error(msg);
	}
	if(NULL == name) {
		std::string msg = std::string("NULL name passed to jal_config_lookup_cpp_int64");
		throw std::runtime_error(msg);
	}
	long long int temp_int = default_value;
	// Extract poll time
	if(JAL_CFG_SUCCESS != jal_config_lookup_int64(
		setting,
		name,
		&temp_int,
		required)) {
			// Error printed internally
			std::string msg = std::string("Failed to get: ") + std::string(name);
			throw std::runtime_error(msg);
	}
	return temp_int;
}

bool jal_config_lookup_cpp_bool(
	const config_setting_t* setting,
	const std::string name,
	const int required,
	const bool default_value)
{
	return jal_config_lookup_cpp_bool(setting, name.c_str(), required, default_value);
}

bool jal_config_lookup_cpp_bool(
	const config_setting_t* setting,
	const char* name,
	const int required,
	const bool default_value)
{
	if(NULL == setting) {
		std::string msg = std::string("NULL setting passed to jal_config_lookup_cpp_bool");
		throw std::runtime_error(msg);
	}
	if(NULL == name) {
		std::string msg = std::string("NULL name passed to jal_config_lookup_cpp_bool");
		throw std::runtime_error(msg);
	}
	int tmp_int = default_value;
	if(JAL_CFG_SUCCESS != jal_config_lookup_bool(
			setting,
			name,
			&tmp_int,
			required)
		)
	{
		std::string msg = std::string("Failed to get: ") + std::string(name);
		throw std::runtime_error(msg);
	}
	return (0 != tmp_int);
}

std::string config_error_context(const config_setting_t* setting, const char* name)
{
	if(NULL == name) {
		std::string msg = std::string("NULL name passed to config_error_context");
		throw std::runtime_error(msg);
	}
	return config_error_context(setting, std::string(name));
}

std::string config_error_context(const config_setting_t* setting, const std::string name)
{
	if(NULL == setting) {
		std::string msg = std::string("NULL setting passed to config_error_context");
		throw std::runtime_error(msg);
	}
	std::string line = std::to_string(config_setting_source_line(setting));
	std::string field = std::string(": field \"") + name + std::string("\" ");
	std::string msg = std::string("Config Error: line ") + line + field;
	return msg;
}
