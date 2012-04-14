#include <list>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>

#include <jalop/jal_version.h>
#include "jaldb_context.hpp"
#include "jaldb_status.h"
#include "jaldb_strings.h"

static void parse_cmdline(int argc, char **argv, char **db_root, char **schemas);
static void print_usage();
static void print_error(enum jaldb_status error);
static void print_list_stdout(const list<string> &list);

int main(int argc, char **argv)
{
	int ret;
	char *dbroot = NULL;
	char *schemas = NULL;
	list<string> *journal_list = NULL;
	list<string> *audit_list = NULL;
	list<string> *log_list = NULL;

	parse_cmdline(argc, argv, &dbroot, &schemas);

	printf("DB-ROOT: %s\nSCHEMAS: %s\n", dbroot, schemas);

	enum jaldb_status jaldb_ret = JALDB_OK;

	jaldb_context *ctx = jaldb_context_create();
	jaldb_ret = jaldb_context_init(ctx, dbroot, schemas, 1);

	if (jaldb_ret != JALDB_OK) {
		printf("\nContext could not be made.\n");
		print_error(jaldb_ret);
		goto err_out;
	}

	jaldb_ret = jaldb_get_journal_document_list(ctx, &journal_list);
	if (jaldb_ret != JALDB_OK) {
		printf("\nContext could not be made.\n");
		print_error(jaldb_ret);
		goto err_out;
	}
	jaldb_ret = jaldb_get_audit_document_list(ctx, &audit_list);
	if (jaldb_ret != JALDB_OK) {
		printf("\nFailed to get audit document list.\n");
		print_error(jaldb_ret);
		goto err_out;
	}
	jaldb_ret = jaldb_get_log_document_list(ctx, &log_list);
	if (jaldb_ret != JALDB_OK) {
		printf("\nFailed to get log document list.\n");
		print_error(jaldb_ret);
		goto err_out;
	}

	journal_list->remove(JALDB_SERIAL_ID_DOC_NAME);
	audit_list->remove(JALDB_SERIAL_ID_DOC_NAME);
	log_list->remove(JALDB_SERIAL_ID_DOC_NAME);

	printf("BEGIN JOURNAL-LIST\n");
	print_list_stdout(*journal_list);
	printf("END JOURNAL-LIST\n");
	printf("BEGIN AUDIT-LIST\n");
	print_list_stdout(*audit_list);
	printf("END AUDIT-LIST\n");
	printf("BEGIN LOG-LIST\n");
	print_list_stdout(*log_list);
	printf("END LOG-LIST\n");

	ret = 0;
	goto out;

err_out:
	ret = -1;
	printf("An error ocurred, closing!\n");
out:
	free(dbroot);
	free(schemas);

	if (ctx) {
		jaldb_context_destroy(&ctx);
	}
	return ret;
}

static void parse_cmdline(int argc, char **argv, char **db_root, char **schemas)
{
	static const char *optstring = "h:s:";
	static const struct option long_options[] = {{"home", 1, 0, 'h'},
						{"schemas", 1, 0, 's'},
						{"version", 0, 0, 'v'},
						{0,0,0,0}};
	int ret_opt;
	while (EOF != (ret_opt = getopt_long(argc, argv, optstring,
				long_options, NULL)))
	{
		switch (ret_opt) {
			case 'h':
				if (NULL == optarg) {
					printf("Optarg was null. Home directory defaulting.\n");
					*db_root = NULL;
				} else {
					*db_root = strdup(optarg);
				}
				break;
			case 's':
				if (NULL == optarg) {
					printf("Optarg was null. Schema directory defaulting.\n");
					*schemas = NULL;
				} else {
					*schemas = strdup(optarg);
				}
				break;
			case 'v':
				goto version_out;
			default:
				printf("Invalid argument!\n\n");
				goto err_usage;
		}
	}
	return;
err_usage:
	print_usage();
	exit(-1);

version_out:
	printf("%s", jal_version_as_string());
	exit(0);
}

static void print_usage()
{
	static const char *usage =
	"Usage:\n\
	-h, --home=H	Specify the root of the JALoP database,\n\
			defaults to /var/lib/jalop/db.\n \
	-s, --schema=S	Specify the root of the JALoP schema directory,\n\
			defaults to <prefix>/share/jalop-v1.0/schemas.\n\
	--version	Output version information and exit.\n\n";
	printf("%s", usage);
}

static void print_error(enum jaldb_status error)
{
	switch (error) {
		case JALDB_E_INVAL:
			printf("JALDB_E_INVAL");
			break;
		case JALDB_E_UNKNOWN:
			printf("JALDB_E_UNKNOWN");
			break;
		case JALDB_E_DB:
			printf("JALDB_E_DB");
			break;
		case JALDB_E_ALREADY_CONFED:
			printf("JALDB_E_ALREADY_CONFED");
			break;
		case JALDB_E_NO_MEM:
			printf("JALDB_E_NO_MEM");
			break;
		case JALDB_E_UNINITIALIZED:
			printf("JALDB_E_UNINITIALIZED");
			break;
		case JALDB_E_INTERNAL_ERROR:
			printf("JALDB_E_INTERNAL_ERROR");
			break;
		case JALDB_E_INITIALIZED:
			printf("JALDB_E_INITIALIZED");
			break;
		case JALDB_E_CORRUPTED:
			printf("JALDB_E_CORRUPTED");
			break;
		case JALDB_E_SID:
			printf("JALDB_E_SID");
			break;
		case JALDB_E_NOT_FOUND:
			printf("JALDB_E_NOT_FOUND");
			break;
		case JALDB_OK:
			break;
		default:
			printf("UNKNOWN_ERROR");
			break;
	}
	printf("\n");
}

static void print_list_stdout(const list<string> &p_list)
{
	list<string>::const_iterator i;
	for(i=p_list.begin(); i != p_list.end(); ++i) {
		std::string name = (string) *i;
		printf("\t%s\n", name.c_str());
	}
	if (0 == p_list.size()) {
		printf("\t--none--\n");
	}
}
