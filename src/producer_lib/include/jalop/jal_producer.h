#ifndef JAL_PRODUCER_H
#define JAL_PRODUCER_H
enum jal_return {
	JAL_E_XML_PARSE = ,
	JAL_E_XML_SCHEMA,
	JAL_E_NOT_CONNECTED,
	JAL_E_INVAL,
	JAL_E_NO_MEM,
	JAL_OK = 0,
};


/**
 * The jal_ctx holds information about the connection to the JALoP Local Store.
 * The jal_context is not thread safe. Applictions should either create
 * seperate logging contexts for each thread, or properly guard the jal_ctx.
 *
 * Because each connection requires resources in the JAL Local Store, a
 * massively threaded process should avoid creating a context for each thread.
 */
struct jal_ctx {
	int socket; /**< The socket used to communicate with the JALoP Local Store */
	char *path; /**< The path that was originally used to connect to the socket */
	char *hostname; /**< The hostname to use when generating the application metadata sections */
	char *app_name; /**< The application name to use when generating the application metadata sections */
};

/**
 * Create a jal_ctx.
 * @param path[in] The name of the socket to connect to. If this is NULL, the
 * default path defined in JAL_SOCKET_NAME is used.
 *
 * In most cases, it is safe pass NULL as the path. For testing purposes, or
 * when the path to the domain socket in the producer process is different
 * from the path in the JALoP Local Store, the caller may specify a different
 * path.
 *
 * @return a jal_ctx, or JAL_NO_MEM
 */
struct jal_ctx jal_ctx_create(char* path, char *hostname, char *app_name);

/**
 * Connect to the JALoP Local Store. It is safe to call this repeatedly, even
 * after a connection was made.
 *
 * @param ctx the context to connect
 * @return JAL_OK if the connection is complete.
 */
jal_return jal_ctx_connect(struct jal_ctx *ctx);
/*
 * Disconect from a JAL Local Store
 * @param ctx the context to disconnect.
 */
jal_return jal_ctx_disconnect(struct jal_ctx *ctx);
/**
 * Disconnect (if needed) and destroy the context.
 *
 * @param ctx[in,out] The jal_ctx to destroy. On return, this will be set to
 * NULL.
 */
void jal_ctx_destroy(struct jal_ctx **ctx);

/**
 * Send a log message to the JALoP Local Store
 *
 * @param app_metadata[in] An XML document conforming to the application metadata
 * schema.
 * @param log_string[in] A preformatted string to send to the JALoP Local Store
 * @return JAL_OK on sucess.
 *         JAL_XML_PARSE_ERROR if app_metadata fails to parse
 *         JAL_XML_SCHEMA_ERROR if app_metadata fails to pass schema validation
 *         JAL_EINVAL if both paramters are NULL.
 *         JAL_NOT_CONNECTED if a connection to the JALoP Local Store couldn't
 *         be made
 *
 * The entire log_string (including the NULL terminator) is sent to the JALoP
 * Local Store. An application that includes a digest of the log_string in
 * their metadata should be aware of this. If an application calculates the
 * digest without the NULL terminator, they should either change their digest
 * calculations, or they should use jal_log_buffer(char*, uint8_t*, uint64_t*)
 * to truncate the buffer.
 *
 * The ctx will be connected if it isn't already.
 *
 * app_meta or log_string may be NULL, but not both.
 * */
jal_return jal_log(struct jal_ctx *ctx, struct jal_app_metadata *app_meta, char* log_string);

/**
 * Send a log message to the JALoP Local Store
 *
 * @param app_metadata[in] An XML document conforming to the application metadata
 * schema.
 * @param log_buffer[in] A byte buffer
 * @return JAL_OK on sucess.
 *         JAL_XML_PARSE_ERROR if app_metadata fails to parse
 *         JAL_XML_SCHEMA_ERROR if app_metadata fails to pass schema validation
 *         JAL_XML_EINVAL if there is something wrong with the parameters
 *         JAL_NOT_CONNECTED if a connection to the JALoP Local Store couldn't
 *         be made
 *
 * If app_meta is NULL, log_buffer must be non-NULL and log_buffer_size must
 * be > 0. If app_meta is non-NULL, log_buffer may be NULL. If log_buffer is
 * NULL, log_buffer_size must be 0.
 *
 * The ctx will be connected if it isn't already.
 */
jal_return jal_log_buffer(struct jal_ctx *ctx, struct jal_app_metadata *app_meta, char *app_metadata, uint8_t *log_buffer, uint64_t log_buffer_size);

/**
 * Send a log message to the JALoP Local Store
 *
 * @param app_metadata[in] An XML document conforming to the application metadata
 * schema.
 * @param log_string[in] A preformatted string to send to the JALoP Local Store
 * @return JAL_OK on sucess.
 *         JAL_XML_PARSE_ERROR if app_metadata fails to parse
 *         JAL_XML_SCHEMA_ERROR if app_metadata fails to pass schema validation
 *         JAL_EINVAL if both paramters are NULL.
 *         JAL_NOT_CONNECTED if a connection to the JALoP Local Store couldn't
 *         be made
 *
 * Sends the entire contents of journal_string to the JALoP Local Store,
 * including the NULL terminator. Applications that include digests of the
 * journal data should include the NULL terminator in their digest
 * calculations or use jal_journal_buffer(char*, uint8_t*, uint64_t);
 *
 * The ctx will be connected if it isn't already.
 */
jal_return jal_journal(struct jal_ctx *ctx, struct jal_app_metadata *app_meta, char *journal_string);

/**
 * Send a journal data to the JALoP Local Store
 *
 * @param app_metadata[in] An XML document conforming to the application metadata
 * schema.
 * @param journal_buffer[in] A byte buffer that contains the full contents of
 * a journal entry.
 * @return JAL_OK on sucess.
 *         JAL_XML_PARSE_ERROR if app_metadata fails to parse
 *         JAL_XML_SCHEMA_ERROR if app_metadata fails to pass schema validation
 *         JAL_EINVAL If the parameters are incorrect.
 *         JAL_NOT_CONNECTED if a connection to the JALoP Local Store couldn't
 *         be made
 *
 * The ctx will be connected if it isn't already.
 */
jal_return jal_journal_buffer(struct jal_ctx *ctx, struct jal_app_metadata *app_meta, uint8_t * journal_buffer, uint64_t journal_buffer_size);

/**
 * Send an audit record to the JALoP Local Store
 *
 * @param app_metadata[in] An XML document conforming to the application metadata
 * schema.
 * @param audit_string[in] An audit document conforming to the MITRE CEE event.xsd document.
 * @return JAL_OK on sucess.
 *         JAL_XML_PARSE_ERROR if one of the documents failed to parse
 *         JAL_XML_SCHEMA_ERROR if one of the documents failed schema
 *         validation.
 *         JAL_EINVAL if both paramters are NULL.
 *         JAL_NOT_CONNECTED if a connection to the JALoP Local Store couldn't
 *         be made
 *
 * Send the audit record to the the JALoP Local Store. Both the app_metadata
 * and the audit_record are validated against the appropriate schemas. The
 * entire audit record, including the NULL terminator, is sent to the JALoP
 * Local Store. Applications that include a digest of the audit record as part
 * of the app_metadata should include the NULL terminator or use
 * jal_audit_buffer(struct jal_ctx*, char*, uint8_t*, uint64_t);
 *
 * The ctx will be connected if it isn't already.
 */
jal_return jal_audit(struct jal_ctx *ctx, struct jal_app_metadata *app_meta, char *audit_string);

/**
 * Send an audit record to the JALoP Local Store
 *
 * @param app_metadata[in] An XML document conforming to the application metadata
 * schema.
 * @param journal_buffer[in] A byte buffer that contains the full contents of
 * a journal entry.
 * @return JAL_OK on sucess.
 *         JAL_XML_PARSE_ERROR if app_metadata fails to parse
 *         JAL_XML_SCHEMA_ERROR if app_metadata fails to pass schema validation
 *         JAL_EINVAL If the parameters are incorrect.
 *         JAL_NOT_CONNECTED if a connection to the JALoP Local Store couldn't
 *         be made
 *
 * The ctx will be connected if it isn't already.
 */
jal_return jal_audit_buffer(struct jal_ctx *ctx,
			    struct jal_app_metadata *app_meta,
			    uint8_t *audit_buffer,
			    uint64_t audit_buffer_size);

/**
 * The syslog_metadata structure should be filled in if an application wishes
 * to generate events that contain data similar to what syslog produces.
 *
 * These correspond to the elments in the JAL application metadata schema
 * (applicationMetadata.xsd).
 *
 * The hostname and application name are taken from the the jal_context, while
 * the process ID (PID) is generated automatically. Timestamps are generated
 * automatically if the timestamp field is NULL.
 */
struct syslog_metadata {
	/**
	 * The time that should be logged for this record. If NULL, the JAL
	 * library will generate a timestamp itself.
	 */
	char *timestamp;
	/**
	 * The message ID may be used to identify the 'type' of the log
	 * message. See the MSGID field in RFC 5424.
	 */
	char *messageId;
	/**
	 * A linked list of structured data elmeents. If NULL, no elements are
	 * added.
	 */
	struct jal_structured_data *sd_head;
	/** 
	 * The faclity, must be between 0 and 23. Value of -1 indicates it should be ignored. 
	 * The numeric values of the facility have the same meanings as for
	 * syslog.*/
	int8_t facility;
	/**
	 * The severity indicates the level a log messages is grouped in. The
	 * severity must be between 0 and 7. A value of -1 indicates the
	 * severity was never set.
	 */
	int8_t severity;
}
/**
 * A linked list of structured data elements. Structured data provides a
 * mechanism to list extra key/value pairs. The elements are namespaced using
 * the sd_id field. This corresponds to the Structured Data section of the
 * syslog RFC (RFC 5424, section 6.3)
 */
struct jal_structured_data {
	/**
	 * The sd_id essentially namespaces each element. 2 structured data
	 * elements with the same name, but different sd_ids may have
	 * completely different meanings.
	 */
	char *sd_id;
	/**
	 * The name of the elmement
	 */
	char *name;
	/**
	 * The value of this element.
	 */
	char *value;
	/**
	 * The next element in the list.
	 */
	struct jal_structured_data *next;
}
/**
 * Create a jal_structured_data element.
 *
 * @param prev The location in a list to add the element. If prev is not the
 * end of the list, then the new node is created as the next element of prev,
 * and prev->next becomes the new node's next element.
 * This function may be used to add elements to the end, or middle
 * of a list.
 * @param sd_id[in] The sd_id to use for the new element
 * @param name[in] The name of this element
 * @param value[in] The value of this element.
 *
 * @return a newly created jal_structred_data pointer. This must be freed with
 * jal_destroy_structured_data_list(struct jal_structured_data*).
 *
 * sd_id, name, and value are copied to allocated buffers.
 */
struct jal_structured_data *jal_create_structured_data(struct jal_structured_data *prev, 
						       char *sd_id, 
						       char *name, 
						       char *value);
/**
 *
 * Destroy an entire list. This must only be called on the head of the list. If
 * called anywhere else, memory leaks will occur.
 *
 * @param head[in,out] The head of the list to free.
 */
void jal_destroy_structured_data_list(struct jal_structured_data **head);


struct logger_metadata {
}

struct jal_app_metadata {
	int type;
	char *eventId;
	union {
		struct syslog_metadata;
		struct logger_metadata;
		char *custom; /**< a block of XML data. It may conform to any schema,
			       * or none at all, but must be valid XML. Only UTF-8 is
			       * supported at this time.
			       */
	}
};
struct payload_metadata;
#endif /* JAL_PRODUCER_H */
