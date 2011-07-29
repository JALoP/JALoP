#ifndef _JAL_TEST_APP_META_H_
#define _JAL_TEST_APP_META_H_

#include <libconfig.h>

#include <jalop/jal_status.h>
#include <jalop/jalp_app_metadata.h>

int generate_app_metadata(const char *app_meta_path, struct jalp_app_metadata **app_metadata,
	char **hostname, char **appname);

#endif //_JAL_TEST_APP_META_H_
