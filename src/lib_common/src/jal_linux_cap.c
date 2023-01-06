/*
 * @file jal_linux_cap.c This file contains general utility functions.
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

#include "jal_linux_cap.h"

int modify_capability(cap_value_t cap, cap_flag_value_t on)
{
    cap_t current_process_capabilities_context = cap_get_proc();
    cap_flag_value_t cap_ok;
    int rc = -1;
    if (!current_process_capabilities_context) {
        goto out;
    }
    cap_ok = CAP_CLEAR;
    cap_get_flag(current_process_capabilities_context, cap, CAP_PERMITTED, &cap_ok);
    if (cap_ok == CAP_CLEAR) {
        rc = on ? -1 : 0;
        goto out;
    }
    cap_set_flag(current_process_capabilities_context, CAP_EFFECTIVE, 1, &cap, on);
    if (cap_set_proc(current_process_capabilities_context) < 0) {
        goto out;
    }
    cap_free(current_process_capabilities_context);
    current_process_capabilities_context = NULL;
    rc = 0;
out:
if (current_process_capabilities_context)
    cap_free(current_process_capabilities_context);
return rc;
}

int enable_capability_raw(void)   { return modify_capability(CAP_NET_RAW, CAP_SET);  }
int disable_capability_raw(void)  { return modify_capability(CAP_NET_RAW, CAP_CLEAR); }
int enable_capability_admin(void) { return modify_capability(CAP_NET_ADMIN, CAP_SET); }
int disable_capability_admin(void)   { return modify_capability(CAP_NET_ADMIN, CAP_CLEAR); }
int enable_capability_dac_override(void)   { return modify_capability(CAP_DAC_OVERRIDE, CAP_SET); }
int disable_capability_dac_override(void)  { return modify_capability(CAP_DAC_OVERRIDE, CAP_CLEAR); }
int enable_capability_chown(void)   { return modify_capability(CAP_CHOWN, CAP_SET); }
int disable_capability_chown(void)  { return modify_capability(CAP_CHOWN, CAP_CLEAR); }
int enable_capability_fowner(void)  { return modify_capability(CAP_FOWNER, CAP_SET); }
int disable_capability_fowner(void) { return modify_capability(CAP_FOWNER, CAP_CLEAR); }
int enable_capability_kill(void)  { return modify_capability(CAP_KILL, CAP_SET); }
int disable_capability_kill(void) { return modify_capability(CAP_KILL, CAP_CLEAR); }
int enable_capability_setuid(void)  { return modify_capability(CAP_SETUID, CAP_SET); }
int disable_capability_setuid(void) { return modify_capability(CAP_SETUID, CAP_CLEAR); }

int set_ambient_cap(int cap)
{
    int rc;

    capng_get_caps_process();
    rc = capng_update(CAPNG_ADD, CAPNG_INHERITABLE, cap);
    if (rc) {
        printf("Cannot add inheritable cap\n");
        return -1;
    }
    capng_apply(CAPNG_SELECT_CAPS);

    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)) {
        perror("Cannot set cap");
        return -1;
    }

    return 0;
}
int performChown(char* path, uid_t uid, gid_t group)
{
    enable_capability_chown();
    enable_capability_dac_override();
    int chownResult = chown(path, uid, group);
    disable_capability_dac_override();
    disable_capability_chown();

    if (chownResult != 0)
    {
        return -1;
    }
    else
    {
        return 0;
    }
}
int performChmod(char* path, mode_t mode)
{ 
    int chmodResult = chmod((char*)path, mode);

    if (chmodResult != 0)
    {
        return -1;
    }
    else
    {
        return 0;
    }
}

int get_userid_from_username(char* username)
{
    int pw_uid = -1;   
    struct passwd *p;
    p = getpwnam(username);
    if(!p)
    { 
        return -1;
    }
    pw_uid =  p->pw_uid;
    return pw_uid;
}
int get_groupid_from_groupname(char* groupname)
{
    int grp_id = -1;
    struct group * gr = getgrnam(groupname);
    if(!gr)
    {
        return -1;
    }
    grp_id = gr->gr_gid;
    return grp_id;
}
