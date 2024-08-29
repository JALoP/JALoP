#include <stdlib.h>
#include <sys/stat.h>
#include <argp.h>
#include <string.h>
#include "jal_subscribe_config_context.h"

error_t jal_subscribe_parse_opt(int key, char *arg, struct argp_state *state)
{
	struct jal_subscribe_config_context * conf_ctx =
		(struct jal_subscribe_config_context *)(state->input);

	switch (key)
	{
		case 'c':  // this is the only required option
			conf_ctx->conf = strdup(arg);
			break;
		case 't':
			conf_ctx->port = strdup(arg);
			break;
		case 'h':
			conf_ctx->dbpath = strdup(arg);
			break;
		case 'i':
			conf_ctx->ipaddr = strdup(arg);
			break;
		case 'm':
			conf_ctx->inmode = strdup(arg);
			break;
		case 'w':
			conf_ctx->window_size = strdup(arg);
			break;
		case 'd':
			conf_ctx->debug = 1;
			break;
		case 'a':
			conf_ctx->digest_algorithms = strdup(arg);
			break;
		case 's':
			conf_ctx->disableTls = 1;
			break;
		case ARGP_KEY_FINI:
			if(!conf_ctx->conf)
			{
				argp_failure(state, 1, 0, "required -c");
				argp_usage(state);
			}
			else
			{
				struct stat config_stat;
				int ret = stat(conf_ctx->conf, &config_stat);
				if(ret<0)
				{
					argp_failure(state, 1, 0, "Cannot stat config path: %s", conf_ctx->conf);
					argp_usage(state);
				}
			}
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

void jal_subscribe_config_drop_memory(struct jal_subscribe_config_context* ctx)
{
	if(NULL == ctx)
	{
		return;
	}
	free(ctx->conf);
	free(ctx->port);
	free(ctx->ipaddr);
	free(ctx->inmode);
	free(ctx->dbpath);
	free(ctx->window_size);
	free(ctx->digest_algorithms);
}