/*
 * @file jal_linux_seccomp.h This file contains general utility functions.
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

#ifndef JAL_LINUX_SECCOMP_H
#define JAL_LINUX_SECCOMP_H

#include <stdlib.h>
#include <libconfig.h>
#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

struct seccomp_config_t {
	int seccomp_debug;
	int enable_seccomp;
	int restrict_seccomp_F_SETFL;
	const config_setting_t *initial_syscalls;
	const config_setting_t *both_syscalls;
	const config_setting_t *final_syscalls;
};
struct seccomp_config_t seccomp_config = {0, 0, 0, NULL, NULL, NULL};
config_t sc_config;

/**
 * Use read_sc_config at first point the config_path is known. It will
 * read in the libconfig formatted file that holds the seccomp configuration
 *
 * @param[in] config_path file system path to the libconfig configuration file
 *
 * @return 0 on success
 */
int read_sc_config(char * config_path);

/**
 * Use configureInitialSeccomp immediately after 
 * read_sc_config.
 *
 * @return 0 on success
 */
int configureInitialSeccomp();

/**
 * Use configureFinalSeccomp immediately after your process has done its
 * setup work and right before your process goes into its routine.
 *
 * @return 0 on success
 */
int configureFinalSeccomp();

#ifdef __cplusplus
}
#endif

#endif /* JAL_LINUX_SECCOMP_H */

