/*
 * @file jal_linux_cap.h This file contains general utility functions.
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

#ifndef _JAL_LINUX_CAP_H_
#define _JAL_LINUX_CAP_H_

#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <cap-ng.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <grp.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/** TODO add comments for functions below
 */
int set_ambient_cap(int cap);
int modify_capability(cap_value_t cap, cap_flag_value_t on);
int enable_capability_raw(void);
int disable_capability_raw(void);
int enable_capability_admin(void);
int disable_capability_admin(void);
int enable_capability_dac_override(void);
int disable_capability_dac_override(void);
int enable_capability_chown(void);
int disable_capability_chown(void);
int enable_capability_fowner(void);
int disable_capability_fowner(void);
int enable_capability_kill(void);
int disable_capability_kill(void);
int enable_capability_setuid(void);
int disable_capability_setuid(void);

int performChmod(char* path, mode_t mode);
int performChown(char* path, uid_t uid, gid_t group);

int get_userid_from_username(char* username);
int get_groupid_from_groupname(char* groupname);

#ifdef __cplusplus
}
#endif

#endif // _JAL_LINUX_CAP_H_
