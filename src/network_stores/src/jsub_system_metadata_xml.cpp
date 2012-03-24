/**
 * @file jsub_system_metadata_xml.cpp This file defines functions to deal with
 * creating system metadata DOMDocuments.
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

#include <xercesc/dom/DOM.hpp>
#include <openssl/pem.h>
#include <uuid/uuid.h>

#ifdef __HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

#include <jalop/jal_status.h>
#include <jalop/jal_namespaces.h>

#include "jal_alloc.h"
#include "jal_xml_utils.h"
#include "jal_asprintf_internal.h"
#include "jsub_system_metadata_xml.hpp"

#define JALLS_UUID_LEN 36

static const XMLCh JALLS_XML_CORE[] = {
	chLatin_C, chLatin_o, chLatin_r, chLatin_e, chNull };
static const XMLCh JALLS_XML_JALRECORD[] = {
	chLatin_J, chLatin_A, chLatin_L, chLatin_R, chLatin_e, chLatin_c, chLatin_o, chLatin_r, chLatin_d, chNull };
static const XMLCh JALLS_XML_JALDATATYPE[] = {
	chLatin_J, chLatin_A, chLatin_L, chLatin_D, chLatin_a, chLatin_t, chLatin_a, chLatin_T, chLatin_y, chLatin_p,
	chLatin_e, chNull };
static const XMLCh JALLS_XML_JALDATATYPE_JOURNAL[] = {
	chLatin_j, chLatin_o, chLatin_u, chLatin_r, chLatin_n, chLatin_a, chLatin_l, chNull };
static const XMLCh JALLS_XML_JALDATATYPE_AUDIT[] = {
	chLatin_a, chLatin_u, chLatin_d, chLatin_i, chLatin_t, chNull };
static const XMLCh JALLS_XML_JALDATATYPE_LOG[] = {
	chLatin_l, chLatin_o, chLatin_g, chNull };
static const XMLCh JALLS_XML_RECORDID[] = {
	chLatin_R, chLatin_e, chLatin_c, chLatin_o, chLatin_r, chLatin_d, chLatin_I, chLatin_D, chNull };
static const XMLCh JALLS_XML_HOSTNAME[] = {
	chLatin_H, chLatin_o, chLatin_s, chLatin_t, chLatin_n, chLatin_a, chLatin_m, chLatin_e, chNull };
static const XMLCh JALLS_XML_HOSTUUID[] = {
	chLatin_H, chLatin_o, chLatin_s, chLatin_t, chLatin_U, chLatin_U, chLatin_I, chLatin_D, chNull };
static const XMLCh JALLS_XML_TIMESTAMP[] = {
	chLatin_T, chLatin_i, chLatin_m, chLatin_e, chLatin_s, chLatin_t, chLatin_a, chLatin_m, chLatin_p, chNull };
static const XMLCh JALLS_XML_PROCESSID[] = {
	chLatin_P, chLatin_r, chLatin_o, chLatin_c, chLatin_e, chLatin_s, chLatin_s, chLatin_I, chLatin_D, chNull };
static const XMLCh JALLS_XML_USER[] = {
	chLatin_U, chLatin_s, chLatin_e, chLatin_r, chNull };
static const XMLCh JALLS_XML_USER_NAME[] = {
	chLatin_n, chLatin_a, chLatin_m, chLatin_e, chNull };
static const XMLCh JALLS_XML_SECURITYLABEL[] = {
	chLatin_S, chLatin_e, chLatin_c, chLatin_u, chLatin_r, chLatin_i, chLatin_t, chLatin_y, chLatin_L, chLatin_a,
	chLatin_b, chLatin_e, chLatin_l, chNull };
static const XMLCh JALLS_XML_JID[] = {
	chLatin_J, chLatin_I, chLatin_D, chNull };

static const char *UUIDDASH = "UUID-";

XERCES_CPP_NAMESPACE_USE

//extern "C"
int jsub_create_system_metadata(enum jsub_data_type data_type, const char *hostname, const char *host_uuid,
	int user_fd, pid_t app_pid, uid_t app_uid, DOMDocument **doc)
{
	if (!hostname || !host_uuid || app_pid < 0 || user_fd < 0 || !doc || *doc) {
		return -1;
	}

	int ret = -1;
	XMLCh *namespace_uri = XMLString::transcode(JAL_SYS_META_NAMESPACE_URI);

	DOMImplementation *impl = DOMImplementationRegistry::getDOMImplementation(JALLS_XML_CORE);
	DOMDocument *new_doc = impl->createDocument();

	char *pwd_buf = NULL;

	char *str_jid = NULL;

	//create_JALRecord element
	DOMElement *jalrecord_elt = new_doc->createElementNS(namespace_uri, JALLS_XML_JALRECORD);
	new_doc->appendChild(jalrecord_elt);

	//add JALDataType element
	XMLCh *data_type_xml = NULL;
	switch (data_type) {
		case JSUB_JOURNAL:
			data_type_xml = XMLString::replicate(JALLS_XML_JALDATATYPE_JOURNAL);
			break;
		case JSUB_AUDIT:
			data_type_xml = XMLString::replicate(JALLS_XML_JALDATATYPE_AUDIT);
			break;
		case JSUB_LOG:
			data_type_xml = XMLString::replicate(JALLS_XML_JALDATATYPE_LOG);
			break;
		default:
			goto cleanup;
	}
	DOMElement *data_type_elt;
	data_type_elt = new_doc->createElementNS(namespace_uri, JALLS_XML_JALDATATYPE);
	data_type_elt->setTextContent(data_type_xml);
	XMLString::release(&data_type_xml);
	jalrecord_elt->appendChild(data_type_elt);

	//generate uuid and add RecordID element
	uuid_t recordid_uuid;
	uuid_generate(recordid_uuid);
	char recordid_str[JALLS_UUID_LEN + 1];
	uuid_unparse(recordid_uuid, recordid_str);
	XMLCh *recordid_xml;
	recordid_xml = XMLString::transcode(recordid_str);
	DOMElement *recordid_elt;
	recordid_elt = new_doc->createElementNS(namespace_uri, JALLS_XML_RECORDID);
	recordid_elt->setTextContent(recordid_xml);
	XMLString::release(&recordid_xml);
	jalrecord_elt->appendChild(recordid_elt);

	//add the Hostname element
	XMLCh *hostname_xml;
	hostname_xml = XMLString::transcode(hostname);
	DOMElement *hostname_elt;
	hostname_elt = new_doc->createElementNS(namespace_uri, JALLS_XML_HOSTNAME);
	hostname_elt->setTextContent(hostname_xml);
	XMLString::release(&hostname_xml);
	jalrecord_elt->appendChild(hostname_elt);

	//add the HostUUID element
	XMLCh *hostuuid_xml;
	hostuuid_xml = XMLString::transcode(host_uuid);
	DOMElement *hostuuid_elt;
	hostuuid_elt = new_doc->createElementNS(namespace_uri, JALLS_XML_HOSTUUID);
	hostuuid_elt->setTextContent(hostuuid_xml);
	XMLString::release(&hostuuid_xml);
	jalrecord_elt->appendChild(hostuuid_elt);

	///add the Timestamp element
	char *timestamp_str;
	timestamp_str = jal_get_timestamp();
	XMLCh *timestamp_xml;
	timestamp_xml = XMLString::transcode(timestamp_str);
	DOMElement *timestamp_elt;
	timestamp_elt = new_doc->createElementNS(namespace_uri, JALLS_XML_TIMESTAMP);
	timestamp_elt->setTextContent(timestamp_xml);
	free(timestamp_str);
	XMLString::release(&timestamp_xml);
	jalrecord_elt->appendChild(timestamp_elt);

	//add the ProcessID element
	char *pid_str;
	int tmp_ret;
	tmp_ret = jal_asprintf(&pid_str, "%d", app_pid);
	if (tmp_ret < 0) {
		goto cleanup;
	}
	XMLCh *pid_xml;
	pid_xml = XMLString::transcode(pid_str);
	DOMElement *processid_elt;
	processid_elt = new_doc->createElementNS(namespace_uri, JALLS_XML_PROCESSID);
	processid_elt->setTextContent(pid_xml);
	free(pid_str);
	XMLString::release(&pid_xml);
	jalrecord_elt->appendChild(processid_elt);

	//add the user element
	struct passwd *user_pwd_ptr;
	struct passwd user_pwd;
	memset(&user_pwd, 0, sizeof(user_pwd));
	long pwd_buf_size;
	pwd_buf_size = sysconf(_SC_GETPW_R_SIZE_MAX);
	pwd_buf = (char *)jal_calloc(1, pwd_buf_size);
	tmp_ret = getpwuid_r(app_uid, &user_pwd, pwd_buf, pwd_buf_size, &user_pwd_ptr);
	if (tmp_ret < 0) {
		goto cleanup;
	}
	char *uid_str;
	tmp_ret = jal_asprintf(&uid_str, "%u", app_uid);
	if (tmp_ret < 0) {
		goto cleanup;
	}
	XMLCh* uid_xml;
	uid_xml = XMLString::transcode(uid_str);
	XMLCh* uname_xml;
	uname_xml = XMLString::transcode(user_pwd_ptr->pw_name);
	DOMElement *user_elt;
	user_elt = new_doc->createElementNS(namespace_uri, JALLS_XML_USER);
	free(uid_str);
	user_elt->setTextContent(uid_xml);
	user_elt->setAttribute(JALLS_XML_USER_NAME, uname_xml);
	XMLString::release(&uid_xml);
	XMLString::release(&uname_xml);
	jalrecord_elt->appendChild(user_elt);

	//add the SecurityLabel element
	XMLCh* con_xml;
	con_xml = NULL;
#ifdef __HAVE_SELINUX
	security_context_t tmp_sec_con;
	tmp_ret = getpeercon(user_fd, &tmp_sec_con);
	if (tmp_ret < 0) {
		goto cleanup;
	}
	con_xml = XMLString::transcode(tmp_sec_con);
	freecon(tmp_sec_con);
	DOMElement *security_elt;
	security_elt = new_doc->createElementNS(namespace_uri, JALLS_XML_SECURITYLABEL);
	security_elt->setTextContent(con_xml);
	XMLString::release(&con_xml);
	jalrecord_elt->appendChild(security_elt);
#endif //__HAVE_SELINUX

	//set the jid attribute (same uuid as recordid)
	jal_asprintf(&str_jid, "%s%s", UUIDDASH, recordid_str);
	XMLCh *xml_jid;
	xml_jid = XMLString::transcode(str_jid);
	jalrecord_elt->setAttribute(JALLS_XML_JID, xml_jid);
	jalrecord_elt->setIdAttribute(JALLS_XML_JID, true);
	XMLString::release(&xml_jid);

	*doc = new_doc;
	ret = 0;
cleanup:
	free(str_jid);
	XMLString::release(&namespace_uri);
	free(pwd_buf);
	return ret;
}
