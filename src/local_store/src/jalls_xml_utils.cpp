/**
 * @file jalls_xml_utils.cpp This file contains functions to parse and
 * validate xml for the jalop local store.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012 Tresys Technology LLC, Columbia, Maryland, USA
 *
 * This software was developed by Tresys Technology LLC
 * with U.S. Government sponsorship.
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

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <stdio.h>
#include <string.h>

#include "jal_alloc.h"

#include "jalls_xml_utils.hpp"


// Returns a timestamp of the format YYYY-MM-DDTHH:MM:SS[+-]HH:MM
// TODO: Move this to common code, or remove it.
char *jalls_get_timestamp()
{
	char *ftime = (char*)jal_malloc(26);
	char *tz_offset = (char*)jal_malloc(7);
	time_t rawtime;
	struct tm *tm;
	time(&rawtime);
	tm = localtime(&rawtime);
	strftime(ftime, 26, "%Y-%m-%dT%H:%M:%S", tm);
	/* Timezone
	 * Inserts ':' into [+-]HHMM for [+-]HH:MM */
	strftime(tz_offset, 7, "%z", tm);
	tz_offset[6] = '\0';
	tz_offset[5] = tz_offset[4];
	tz_offset[4] = tz_offset[3];
	tz_offset[3] = ':';
	strcat(ftime, tz_offset);
	free(tz_offset);
	return ftime;

}
