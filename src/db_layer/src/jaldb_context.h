#ifndef _JALDB_CONTEXT_H_
#define _JALDB_CONTEXT_H_

typedef struct jaldb_context_t jaldb_context;
/**
 * Creates an empty jaldb_context_t object.
 */
struct jaldb_context_t *jaldb_ctx_create();
/**
 * Initialize a jaldb_context object.
 * @param [in] ctx The context to initialize
 * @param [in] db_root The path to the root of the DB Layer's files. If
 * db_root is NULL, the default is: /var/lib/jalop/db.
 * @param schemas_root The path to the directory containing JALoP related
 * schemas. If schemas_root is NULL, the default is: /usr/share/jalop/schemas
 */
enum jal_status jaldb_init(struct jaldb_context_t *ctx, const char *db_root, const char *schemas_root);
/**
 * Destroy a DB context.
 * Release all resources associated with this context.
 * This should remove any temporary databases that were created
 *
 * @param ctx[in,out] the context to destroy. *ctx will be set to NULL.
 */
void jaldb_destroy(struct jaldb_context_t **ctx);

/**
 * Insert an audit record.
 * @param ctx[in] the context
 * @param source [in] the source of the record (if NULL, this is set to the
 * @param audit_buf [in] A buffer containing the audit data
 * @param audit_len [in] The size (in bytes) of audit data
 * @param sys_meta_buf [in] A buffer containing the system metadata.
 * @param sys_meta_len [in] The size (in bytes) of sys_meta_buf
 * @param app_meta_buf [in] A buffer containing the application metadata.
 * @param app_meta_len [in] The size (in bytes) of app_meta_buf
 */
enum jal_status jaldb_insert_audit(struct jaldb_context_t **ctx,
		const char *source,
		const uint8_t *audit_buf, const size_t audit_len,
		const uint8_t *sys_meta_buf, const size_t sys_meta_len,
		const uint8_t *app_meta_buf, const size_t app_meta_buf_len);

/**
 * Insert an audit record.
 * @param ctx[in] the context
 * @param db_name[in] A name to associate with the containers.
 * @param audit_buf [in] A buffer containing the audit data
 * @param audit_len [in] The size (in bytes) of audit data
 * @param sys_meta_buf [in] A buffer containing the system metadata.
 * @param sys_meta_len [in] The size (in bytes) of sys_meta_buf
 * @param app_meta_buf [in] A buffer containing the application metadata.
 * @param app_meta_len [in] The size (in bytes) of app_meta_buf
 */
enum jal_status jaldb_insert_audit_into_temp(struct jaldb_context_t **ctx,
		char *db_name,
		const uint8_t *audit_buf, const size_t audit_len,
		const uint8_t *sys_meta_buf, const size_t sys_meta_len,
		const uint8_t *app_meta_buf, const size_t app_meta_buf_len);

/**
 * Insert a log record
 * @param ctx[in] the context
 * @param source [in] the source of the record (if NULL, this is set to the
 * string 'localhost')
 * @param log_buf [in] A buffer containing the audit data
 * @param log_len [in] The size (in bytes) of audit data
 * @param sys_meta_buf [in] A buffer containing the system metadata.
 * @param sys_meta_len [in] The size (in bytes) of sys_meta_buf
 * @param app_meta_buf [in] A buffer containing the application metadata.
 * @param app_meta_len [in] The size (in bytes) of app_meta_buf
 */
enum jal_status jaldb_insert_log(struct jaldb_context_t **ctx,
		const char *source,
		const uint8_t *log_buf, const size_t log_len,
		const uint8_t *sys_meta_buf, const size_t sys_meta_len,
		const uint8_t *app_meta_buf, const size_t app_meta_buf_len);

/**
 * Create a file in the DB layer to store Journal data.
 * @param ctx[in] the context;
 * @param path[out] The path (relative to the db_root) of the new file.
 * @param fd[out] An open file for the new file. It is the caller's
 * responsibility to close the descriptor.
 */
enum jal_status jaldb_create_journal(struct jaldb_context_t **ctx, char **path, int *fd);
/**
 * Insert a journal record.
 * @param ctx[in] the context
 * @param source [in] the source of the record (if NULL, this is set to the
 * @param path[in] the path of the file that is journal data, this should be
 * obtained via a call to jaldb_create_journal.
 * @param sys_meta_buf [in] A buffer containing the system metadata.
 * @param sys_meta_len [in] The size (in bytes) of sys_meta_buf
 * @param app_meta_buf [in] A buffer containing the application metadata.
 * @param app_meta_len [in] The size (in bytes) of app_meta_buf
 */
enum jal_status jaldb_insert_journal(struct jaldb_context_t **ctx,
		const char *source, const char *path,
		const uint8_t *sys_meta_buf, const size_t sys_meta_len,
		const uint8_t *app_meta_buf, const size_t app_meta_buf_len);

/**
 * Retrieve a journal record by serialID.
 *
 * @param ctx the context
 * @param sid The serial ID to retrieve
 * @param app_meta
 * @param app_meta_len
 * @param sys_meta
 * @param sys_meta_len
 */
enum jal_status jaldb_get_journal(struct jaldb_context_t *ctx,
		const char *sid,
		char **path);
		uint8_t **app_meta,
		size_t *app_meta_len,
		uint8_t **sys_meta,
		size_t *sys_meta_len,

enum jal_status jaldb_get_audit(struct jaldb_context_t *ctx,
		const char *sid,
		uint8_t **audit,
		size_t *audit_len,
		uint8_t **app_meta,
		size_t *app_meta_len,
		uint8_t **sys_meta,
		size_t *sys_meta_len);

enum jal_status jaldb_get_log(struct jaldb_context_t *ctx,
		const char *sid,
		uint8_t **audit,
		size_t *audit_len,
		uint8_t **app_meta,
		size_t *app_meta_len,
		uint8_t **sys_meta,
		size_t *sys_meta_len);

#ifdef __cplusplus

struct jaldb_context {
	XmlManager *manager; //<! The manager associated with the context
	char *audit_container; //<! The path to container for audit XML
	char *audit_app_meta_container; //<! The path to the container for audit application metadata
	char *audit_sys_meta_container; //<! The path for the audit system metadata

	char *journal_root; //<! The path for to root of the journal records
	char *journal_app_meta_container;
	char *journal_sys_meta_container;

	char *log_db; //<! The path of the Berkeley DB used for log entries
	char *log_app_meta_container;
	char *log_sys_meta_container;
}
#endif // __cplusplus

#endif 
