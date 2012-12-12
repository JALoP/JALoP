/**
 * @file jaldb_datetime.c Implementation of utilties related to XML DateTime
 * strings within the JALoP DBs.
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

#include <libxml/xmlschemastypes.h>

#include <jalop/jal_status.h>

#include "jal_error_callback_internal.h"

#include "jaldb_datetime.h"

int jaldb_xml_datetime_compare(DB *db, const DBT *dbt1, const DBT *dbt2)
{
	int xml_ret;
	xmlSchemaValPtr dt1 = NULL;
	xmlSchemaValPtr dt2 = NULL;
	xmlSchemaTypePtr xs_datetime = NULL;

	xs_datetime = xmlSchemaGetBuiltInType(XML_SCHEMAS_DATETIME);
	if (NULL == xs_datetime) {
		jal_error_handler(JAL_E_UNINITIALIZED);
	}

	xml_ret = xmlSchemaValidatePredefinedType(xs_datetime, (const xmlChar*) dbt1->data, &dt1);
	if (0 != xml_ret) {
		jal_error_handler(JAL_E_XML_PARSE);
	}

	xml_ret = xmlSchemaValidatePredefinedType(xs_datetime, (const xmlChar*) dbt2->data, &dt2);
	if (0 != xml_ret) {
		jal_error_handler(JAL_E_XML_PARSE);
	}

	xml_ret = xmlSchemaCompareValues(dt1, dt2);
	xmlSchemaFreeValue(dt1);
	xmlSchemaFreeValue(dt2);

	switch(xml_ret) {
	case -1:
	case 0:
	case 1:
		return xml_ret;
	default:
		jal_error_handler(JAL_E_INVAL);
	}

	// This really never get here because of the jal_error_handler() call,
	// but need to do something or else the compiler complains.
	return 0;
}

