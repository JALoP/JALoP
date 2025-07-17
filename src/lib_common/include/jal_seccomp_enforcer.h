/**
 * @file
 *
 * @brief This file contains a C-compliant interface
 * for helper functions to load and apply seccomp policies from a libconfig formatted
 * configuration file.
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

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * Opaque pointer representing the state required to load/manage seccomp policies
 */
struct jal_seccomp_enforcer_t;

/**
 * Create a jal_seccomp_enforcer_t given a path to a valid libconfig formatted
 * configuration file
 * @param[in] config_path The libconfig file containing the following configuration items
 * - enable_seccomp [true|false]
 * - seccomp_debug [true|false]
 * - initial_seccomp_rules
 * - both_seccomp_rules (optional)
 * - final_seccomp_rules
 *
 * Each rules item should contain a list of the following form:
 * *_rules = ["item1", "item2", ...];
 * Where the items are an allowlist of permissable system calls. It is acceptable and
 * expected to use the same jald.cfg, local_store.cfg, or jal_subscribe.cfg, but it is also
 * valid to put the seccomp configuration items in their own separate config file.
 *
 * This function will print to stderr in the case of failures, and will additionally
 * print diagnostic information to stderr if seccomp_debug is true
 *
 * @return NULL on error, else a valid jal_seccomp_enforcer_t*
 */
struct jal_seccomp_enforcer_t* jal_seccomp_enforcer_create(
	char* config_path);

/**
 * Destroy a jal_seccmop_enforcer_t, release the resources
 * This does not apply any filters or cause any applied filters to be rescinded
 * @param[in] enforcer The enforcer to be destroyed
 */
void jal_seccomp_enforcer_destroy(
	struct jal_seccomp_enforcer_t** enforcer);

/**
 * Apply the initial seccomp policy loaded by a jal_seccomp_enforcer_t
 * @param[in] enforcer A validly created jal_seccomp_enforcer_t
 * @return 0 on success, or -1 if the policy could not be applied
 * - Will always return -1 if the initial or final policy has already been applied
 *
 * This function will print the reason for failure to stderr, and additional diagnostic
 * information to stderr if the enforcer was created with seccomp_debug enabled
 */
int jal_seccomp_enforcer_apply_initial(
	struct jal_seccomp_enforcer_t* enforcer);

/**
 * Apply the final seccomp policy loaded by a jal_seccomp_enforcer_t
 * @param[in] enforcer A validly created jal_seccomp_enforcer_t
 * @return 0 on success, or -1 if the policy could not be applied
 * - Will always return -1 if the initial or final policy has already been applied
 *
 * This function will print the reason for failure to stderr, and additional diagnostic
 * information to stderr if the enforcer was created with seccomp_debug enabled
 */
int jal_seccomp_enforcer_apply_final(
	struct jal_seccomp_enforcer_t* enforcer);

#ifdef __cplusplus
}
#endif
