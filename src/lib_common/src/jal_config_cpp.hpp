/**
 * @file
 *
 * @brief This file contains utility functions for reading config
 * files with a C++ compliant interface. Intended to be an optional
 * extension to the C interface, not a replacement.
 *
 * ### LICENSE
 *
 * Copyright (C) 2026 Concurrent Technologies Corporation.
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
#pragma once

#include <string>
#include <libconfig.h>

/**
 * Wraps jal_config_lookup_string to use C++ strings and throw
 * an exception in addition to printing the underlying error to stderr.
 *
 * @param [in]  setting  The parent setting of the field to lookup.
 * @param [in]  name     The name of the field.
 * @param [in]  required If set to JAL_CFG_REQUIRED, the function will fail if the
 *   field is not found, printing an error to stderr.
 *   If set to JAL_CFG_OPTIONAL, the function will return successfully and field will
 *   remain unchanged.
 * @param [in] default_value The value to use if required = JAL_CFG_OPTIONAL and no
 *   field called name is found.
 * @return The extracted string
 * @throws std::runtime_error
 */
std::string jal_config_lookup_cpp_string(
	const config_setting_t* setting,
	const char* name,
	const int required,
	const std::string default_value);

/**
 * Wraps jal_config_lookup_string to use C++ strings and throw
 * an exception in addition to printing the underlying error to stderr.
 *
 * @param [in]  setting  The parent setting of the field to lookup.
 * @param [in]  name     The name of the field.
 * @param [in]  required If set to JAL_CFG_REQUIRED, the function will fail if the
 *   field is not found, printing an error to stderr.
 *   If set to JAL_CFG_OPTIONAL, the function will return successfully and field will
 *   remain unchanged.
 * @param [in] default_value The value to use if required = JAL_CFG_OPTIONAL and no
 *   field called name is found.
 * @return The extracted string
 * @throws std::runtime_error
 */
std::string jal_config_lookup_cpp_string(
	const config_setting_t* setting,
	const std::string name,
	const int required,
	const std::string default_value);

/**
 * Wraps jal_config_lookup_string with additional logic to expand the
 * extracted string to an absolute path.
 *
 * @param [in]  setting  The parent setting of the field to lookup.
 * @param [in]  name     The name of the field.
 * @param [in]  required If set to JAL_CFG_REQUIRED, the function will fail if the
 *   field is not found, printing an error to stderr.
 *   If set to JAL_CFG_OPTIONAL, the function will return successfully and field will
 *   remain unchanged.
 * @param [in] default_value The value to use if required = JAL_CFG_OPTIONAL and no
 *   field called name is found.
 * @return The extracted path
 * @throws std::runtime_error
 */
std::string jal_config_lookup_cpp_path(
	const config_setting_t* setting,
	const char* name,
	const int required,
	const std::string default_value);

/**
 * Wraps jal_config_lookup_string with additional logic to expand the
 * extracted string to an absolute path.
 *
 * @param [in]  setting  The parent setting of the field to lookup.
 * @param [in]  name     The name of the field.
 * @param [in]  required If set to JAL_CFG_REQUIRED, the function will fail if the
 *   field is not found, printing an error to stderr.
 *   If set to JAL_CFG_OPTIONAL, the function will return successfully and field will
 *   remain unchanged.
 * @param [in] default_value The value to use if required = JAL_CFG_OPTIONAL and no
 *   field called name is found.
 * @return The extracted path
 * @throws std::runtime_error
 */
std::string jal_config_lookup_cpp_path(
	const config_setting_t* setting,
	const std::string name,
	const int required,
	const std::string default_value);

/**
 * Wraps jal_config_lookup_string with additional logic to expand the
 * extracted string to an absolute file path.
 *
 * @param [in]  setting  The parent setting of the field to lookup.
 * @param [in]  name     The name of the field.
 * @param [in]  required If set to JAL_CFG_REQUIRED, the function will fail if the
 *   field is not found, throwing a runtime exception
 * @param [in] default_value The value to use if required = JAL_CFG_OPTIONAL and no
 * @param [in] must_exist If true, will throw a runtime exception if the file does not exist
 *   If false, will allow for the file itself to not exist, but requires that the parent
 *   directory exists
 * @return The extracted file path
 * @throws std::runtime_error
 */
std::string jal_config_lookup_cpp_file_path(
	const config_setting_t* setting,
	std::string name,
	const int required,
	const std::string default_value,
	const bool must_exist);

/**
 * Wraps jal_config_lookup_string with additional logic to expand the
 * extracted string to an absolute file path.
 *
 * @param [in]  setting  The parent setting of the field to lookup.
 * @param [in]  name     The name of the field.
 * @param [in]  required If set to JAL_CFG_REQUIRED, the function will fail if the
 *   field is not found, throwing a runtime exception
 * @param [in] default_value The value to use if required = JAL_CFG_OPTIONAL and no
 * @param [in] must_exist If true, will throw a runtime exception if the file does not exist
 *   If false, will allow for the file itself to not exist, but requires that the parent
 *   directory exists
 * @return The extracted file path
 * @throws std::runtime_error
 */
std::string jal_config_lookup_cpp_file_path(
	const config_setting_t* setting,
	const char* name,
	const int required,
	const std::string default_value,
	const bool must_exist);

/**
 * Wraps jal_config_lookup_int to throw
 * an exception in addition to printing the underlying error to stderr.
 *
 * @param [in]  setting  The parent setting of the field to lookup.
 * @param [in]  name     The name of the field.
 * @param [in]  required If set to JAL_CFG_REQUIRED, the function will fail if the
 *   field is not found, printing an error to stderr.
 *   If set to JAL_CFG_OPTIONAL, the function will return successfully and field will
 *   remain unchanged.
 * @param [in] default_value The value to use if required = JAL_CFG_OPTIONAL and no
 *   field called name is found.
 * @return The extracted int
 * @throws std::runtime_error
 */
int jal_config_lookup_cpp_int(
	const config_setting_t* setting,
	const char* name,
	const int required,
	const int default_value);

/**
 * Wraps jal_config_lookup_int to throw
 * an exception in addition to printing the underlying error to stderr.
 *
 * @param [in]  setting  The parent setting of the field to lookup.
 * @param [in]  name     The name of the field.
 * @param [in]  required If set to JAL_CFG_REQUIRED, the function will fail if the
 *   field is not found, printing an error to stderr.
 *   If set to JAL_CFG_OPTIONAL, the function will return successfully and field will
 *   remain unchanged.
 * @param [in] default_value The value to use if required = JAL_CFG_OPTIONAL and no
 *   field called name is found.
 * @return The extracted int
 * @throws std::runtime_error
 */
int jal_config_lookup_cpp_int(
	const config_setting_t* setting,
	const std::string name,
	const int required,
	const long long int default_value);

/**
 * Wraps jal_config_lookup_int64 to throw
 * an exception in addition to printing the underlying error to stderr.
 *
 * @param [in]  setting  The parent setting of the field to lookup.
 * @param [in]  name     The name of the field.
 * @param [in]  required If set to JAL_CFG_REQUIRED, the function will fail if the
 *   field is not found, printing an error to stderr.
 *   If set to JAL_CFG_OPTIONAL, the function will return successfully and field will
 *   remain unchanged.
 * @param [in] default_value The value to use if required = JAL_CFG_OPTIONAL and no
 *   field called name is found.
 * @return The extracted long long int
 * @throws std::runtime_error
 */
long long int jal_config_lookup_cpp_int64(
	const config_setting_t* setting,
	const std::string name,
	const int required,
	const long long int default_value);

/**
 * Wraps jal_config_lookup_int64 to throw
 * an exception in addition to printing the underlying error to stderr.
 *
 * @param [in]  setting  The parent setting of the field to lookup.
 * @param [in]  name     The name of the field.
 * @param [in]  required If set to JAL_CFG_REQUIRED, the function will fail if the
 *   field is not found, printing an error to stderr.
 *   If set to JAL_CFG_OPTIONAL, the function will return successfully and field will
 *   remain unchanged.
 * @param [in] default_value The value to use if required = JAL_CFG_OPTIONAL and no
 *   field called name is found.
 * @return The extracted long long int
 * @throws std::runtime_error
 */
long long int jal_config_lookup_cpp_int64(
	const config_setting_t* setting,
	const char* name,
	const int required,
	const long long int default_value);

/**
 * Wraps jal_config_lookup_bool to throw
 * an exception in addition to printing the underlying error to stderr,
 * as well as converting to an actually boolean type.
 *
 * @param [in]  setting  The parent setting of the field to lookup.
 * @param [in]  name     The name of the field.
 * @param [in]  required If set to JAL_CFG_REQUIRED, the function will fail if the
 *   field is not found, printing an error to stderr.
 *   If set to JAL_CFG_OPTIONAL, the function will return successfully and field will
 *   remain unchanged.
 * @param [in] default_value The value to use if required = JAL_CFG_OPTIONAL and no
 *   field called name is found.
 * @return The extracted long long int
 * @throws std::runtime_error
 */
bool jal_config_lookup_cpp_bool(
	const config_setting_t* setting,
	const std::string name,
	const int required,
	const bool default_value);

/**
 * Wraps jal_config_lookup_bool to throw
 * an exception in addition to printing the underlying error to stderr,
 * as well as converting to an actually boolean type.
 *
 * @param [in]  setting  The parent setting of the field to lookup.
 * @param [in]  name     The name of the field.
 * @param [in]  required If set to JAL_CFG_REQUIRED, the function will fail if the
 *   field is not found, printing an error to stderr.
 *   If set to JAL_CFG_OPTIONAL, the function will return successfully and field will
 *   remain unchanged.
 * @param [in] default_value The value to use if required = JAL_CFG_OPTIONAL and no
 *   field called name is found.
 * @return The extracted long long int
 * @throws std::runtime_error
 */
bool jal_config_lookup_cpp_bool(
	const config_setting_t* setting,
	const char* name,
	const int required,
	const bool default_value);

/**
 * Implementation of CONFIG_ERROR which returns a string instead of printing
 * to stderr.
 *
 * @param [in]  setting  The parent setting of the field to lookup.
 * @param [in]  name     The name of the field.
 * @return The error context
 */
std::string config_error_context(const config_setting_t* setting, const std::string name);

/**
 * Implementation of CONFIG_ERROR which returns a string instead of printing
 * to stderr.
 *
 * @param [in]  setting  The parent setting of the field to lookup.
 * @param [in]  name     The name of the field.
 * @return The error context
 */
std::string config_error_context(const config_setting_t* setting, const char* name);
