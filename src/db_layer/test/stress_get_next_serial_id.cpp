/**
 * @file stress_get_next_serial_id.cpp Small program to stress test a function
 * for acquiring and updated the serial ID.
 *
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2011 Tresys Technology LLC, Columbia, Maryland, USA
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
#include <cstdio>
#include <cstdlib>
#include <string.h>
#include "jaldb_serial_id.hpp"
#include "jaldb_strings.h"
using namespace DbXml;
using namespace std;

struct thread_ctx {
	int id;
	XmlManager mgr;
	XmlContainer cont;
};
// Main thread execution loop
//void *main_loop(struct thread_ctx *ctx);
void *main_loop(void*);
// wrapper around jaldb_get_next_serial_id that performs the exception
// handling, etc.
int wrapped_get_next_serial_id(XmlManager &mgr, XmlContainer &cont, int id);
// Simple program to stress test acquiring (and incrementing) the 'next'
// serial id. It expects a single command line argument, which is used in the
// print statements. The intent is to execute this program multiple times from
// the command line 
int main(int argc, char **argv) {
	if (argc != 2) {
		printf("usage: stress_get_next_serial_id <num> where num is the number of instances to spawn\n");
		exit(1);
	}
	int cnt = atoi(argv[1]);
	if (cnt < 1) {
		printf("<num> must be >= 1\n");
		exit(1);
	}
	uint32_t env_flags = DB_CREATE |
				DB_INIT_LOCK |
				DB_INIT_LOG |
				DB_INIT_MPOOL |
				DB_INIT_TXN | DB_THREAD |
				DB_AUTO_COMMIT;
	DB_ENV *env = NULL;
	db_env_create(&env, 0);
	int dberr;
	dberr = env->set_lk_detect(env, DB_LOCK_YOUNGEST);
	if (dberr) {
		std::cerr << "Failed to enable the lock detector" << std::endl;
		if (env) {
			env->close(env, 0);
		}
		exit(1);
	}
	dberr = env->open(env, "./testEnv", env_flags, 0);
	if (dberr) {
		std::cerr << "Failed to open the Environment" << std::endl;
		if (env) {
			env->close(env, 0);
		}
		exit(1);
	}
	XmlContainerConfig cfg;
	cfg.setThreaded(true);
	cfg.setTransactional(true);

	struct thread_ctx ctx;
	ctx.mgr = XmlManager(env, DBXML_ADOPT_DBENV);
	XmlTransaction txn = ctx.mgr.createTransaction();
	try {
		ctx.cont = ctx.mgr.openContainer(txn, JALDB_AUDIT_SYS_META_CONT_NAME, cfg);
	} catch(...) {
		try {
			printf("creating new container...\n");
			ctx.cont = ctx.mgr.createContainer(txn, JALDB_AUDIT_SYS_META_CONT_NAME, cfg);
			XmlUpdateContext uc = ctx.mgr.createUpdateContext();
			XmlDocument doc = ctx.mgr.createDocument();
			doc.setName(JALDB_SERIAL_ID_DOC_NAME);
			XmlValue attrVal(XmlValue::STRING, "1");
			doc.setMetaData(JALDB_NS, JALDB_SERIAL_ID_NAME, attrVal);
			ctx.cont.putDocument(doc, uc, 0);
		} catch (...) {
			printf("bad\n");
		}
	}

	pthread_t *threads = (pthread_t*)calloc(cnt, sizeof(*threads));
	for (int i = 0; i < cnt; i++) {
		struct thread_ctx *aCtx = (struct thread_ctx*) malloc(sizeof(*aCtx));
		memcpy(aCtx, &ctx, sizeof(*aCtx));
		aCtx->id = i;
		pthread_create(threads + i, NULL, main_loop, aCtx);
	}
	for (int i = 0; i < cnt; i++) {
		void *ret;
		pthread_join(threads[i], &ret);
	}
}

void *main_loop(void *v) {
	struct thread_ctx *ctx = (struct thread_ctx*) v;
	int *ret = (int*) malloc(sizeof(*ret));
	for (int i = 0; i < 100; i++) {
		*ret = wrapped_get_next_serial_id(ctx->mgr, ctx->cont, ctx->id);
		if (*ret != 0) {
			break;
		}
	}
	free(ctx);
	return ret;
}
int wrapped_get_next_serial_id(XmlManager &mgr, XmlContainer &cont, int id)
{
	string sid;
	int ret = 0;
	for (;;) {
		DbXml::XmlTransaction txn  = mgr.createTransaction();
		XmlUpdateContext uc = mgr.createUpdateContext();
		try {
			if (jaldb_get_next_serial_id(txn, uc, cont, sid) == JALDB_OK) {
				printf("%10d:sid:%10s\n", id, sid.c_str());
				txn.commit();
				break;
			} else {
				printf("failed to get next sid\n");
				txn.abort();
				ret = -1;
				break;
			}
		} catch (XmlException &e) {
			txn.abort();
			// retry the transaction if it was a
			// DB_LOCK_DEADLOCK, otherwise exit();
			if (e.getExceptionCode() != XmlException::DATABASE_ERROR ||
					e.getDbErrno() != DB_LOCK_DEADLOCK) {
				printf("Got unexpectected exception when trying to increment the serial_id (%s)\n",
						e.what());
				ret = -1;
				break;
			}
		} catch (exception &e) {
			printf("Got unexpectected exception when trying to increment the serial_id (%s)\n", 
				e.what());
			ret = -1;
			break;
		} catch (...) {
			printf("Got unexpectected exception when trying to increment the serial_id\n");
			ret = -1;
			break;
		}
	}
	return ret;
}

