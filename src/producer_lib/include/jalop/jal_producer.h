#ifndef jalp_PRODUCER_H
#define jalp_PRODUCER_H
#include <stdint.h>
#include <stdlib.h>
enum jal_status {
	jalp_E_XML_PARSE = -1024,
	jalp_E_XML_SCHEMA,
	jalp_E_NOT_CONNECTED,
	jalp_E_INVAL,
	jalp_E_NO_MEM,
	JAL_OK = 0,
};


/**
 * The jalp_connection holds information about the connection to the JALoP Local Store.
 * The jalp_connection is not thread safe. Applictions should either create
 * seperate logging connections for each thread, or properly guard the jalp_connection.
 *
 * Because each connection requires resources in the JAL Local Store, a
 * massively threaded process should avoid creating a connection for each thread.
 */
struct jalp_connection_t {
	int socket; /**< The socket used to communicate with the JALoP Local Store */
	char *path; /**< The path that was originally used to connect to the socket */
	char *hostname; /**< The hostname to use when generating the application metadata sections */
	char *app_name; /**< The application name to use when generating the application metadata sections */
};

/**
 * A linked list of structured data elements. Structured data provides a
 * mechanism to list extra key/value pairs. The elements are namespaced using
 * the sd_id field. This corresponds to the Structured Data section of the
 * syslog RFC (RFC 5424, section 6.3)
 */
struct jalp_structured_data_param {
	/**
	 * The key for this param
	 */
	char *key;
	/**
	 * The value of this element.
	 */
	char *value;
	/**
	 * The next element in the list.
	 */
	struct jalp_structured_data_param *next;
};
/**
 * Represents a set of structured data elements. Applications should use an ID
 * containing an '@' unless using one of the registered IDs.
 * @see rfc5424
 */
struct jalp_structured_data {
	/**
	 * The SD-ID for all param elements in \p param_list.
	 */
	char *sd_id;
	/**
	 * A list of params
	 */
	struct jalp_structured_data_param *param_list;
};
/**
 * The syslog_metadata structure should be filled in if an application wishes
 * to generate events that contain data similar to what syslog produces.
 *
 * These correspond to the elments in the JAL application metadata schema
 * (applicationMetadata.xsd).
 *
 * The hostname and application name are taken from the the jalp_connection, while
 * the process ID (PID) is generated automatically. Timestamps are generated
 * automatically if the timestamp field is NULL.
 */
struct syslog_metadata {
	/**
	 * The time that should be logged for this record. If NULL, the JAL
	 * library will generate a timestamp itself. The timestamp must confrom
	 * to the XML Schema dataTime format.
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
	struct jalp_structured_data *sd_head;
	/** 
	 * The faclity, must be between 0 and 23. Value of -1 indicates it should be ignored. 
	 * The numeric values of the facility have the same meanings as for
	 * syslog.
	 */
	int8_t facility;
	/**
	 * The severity indicates the level a log messages is grouped in. The
	 * severity must be between 0 and 7. A value of -1 indicates the
	 * severity should be ignored.
	 */
	int8_t severity;
};

/**
 * Represents one entry in a stack frame.  All fields are optional and may be
 * set to NULL. Line Numbers are assumed to start counting at 1, so a value of
 * 0 for \p line_number will suppress the filed.
 * If an application is providing multiple levels of stack information, they
 * should list the stack frames from the bottom up. That is, the first
 * stack_frame in the list should be the one where the log actuallyer happened.
 *
 * The depth should be filled in to indicate the level in the stack trace. A
 * value of -1 indicates the depth for this frame should not be included. The
 * frame with depth 0 is considered the inner most (i.e. where the log took
 * place) frame.
 *
 * The JPL does not verify that the depths follow any particular order.
 */
struct stack_frame {
	/** The caller's name */
	char *caller_name;
	/** The filename where the log message was generated */
	char *file_name;
	/** The line number in the source file */
	uint64_t line_number;
	/** The class name that generated the log **/
	char *class_name;
	/** The method/function where the log was generated */
	char *method_name;
	/** The 'depth' of this stack frame */
	int depth;
	/** The next (parent) stack frame. */
	struct stack_frame *next;
};

/**
 * Structure to represent the 'logger' type data in the application metadata.
 *
 * All fields are optional, except the loggerName.
 */
struct logger_metadata {
	/** The name of this logger*/
	char *loggerName;
	/** The severity of this log entry */
	struct severity *severity;
	/**
	 * The timestamp of this log entry. If NULL, the JPL will generate the
	 * a timestamp. This must conform to the XML Schema dateTime type.
	 */
	char *timestamp;
	/** The thread ID. */
	char *threadId;
	/** The Log message to include */
	char *message;
	/** The nested diagnostic context, checkout Log4J for a description */
	char *nested_diagnostic_context;
	/** The mapped diagnostic context, checkout Log4J for a description */
	char *mapped_diagnostic_context;
	/** A stack trace */
	struct stack_frame *stack;
	/** An extended list of metadata. */
	struct structured_data *sd;
};

/**
 * Structure that represents a App Metadata document.
 */
struct jalp_app_metadata {
	/**
	 * indicates what type of data this contains, syslog metadata,
	 * logger metadata, or some custom format
	 */
	int type;
	/**
	 * An application defined event ID. This can be used to correlate
	 * multiple entries, or be NULL. It's has no meaning to JALoP.
	 */
	char *eventId;
	/**
	 * holds the sys, log, or custom sub-element.
	 */
	union {
		struct syslog_metadata sys;
		struct logger_metadata log;
		/**
		 * a block of XML data. It may conform to any schema,
		 * or none at all. This may be a complete document, or just a
		 * snippet.
		 */
		char *custom;
	};
};

/**
 * Structure that represents the payload section of an application metadata
 * document.
 */
struct jalp_payload_metadata {
	/** foo */
	int foo;
};

/**
 * opaque pointer for a connection to the JAL local store
 */
typedef struct jalp_connection_t* jalp_connection;

/**
 * Create a jalp_connection.
 * @param[in] path The name of the socket to connect to. If this is NULL, the
 * default path defined in jalp_SOCKET_NAME is used.
 *
 * In most cases, it is safe pass NULL as the path. For testing purposes, or
 * when the path to the domain socket in the producer process is different
 * from the path in the JALoP Local Store, the caller may specify a different
 * path.
 *
 * @param[in] hostname A string to use when filling out metadata sections. If
 * this is set to NULL or the empty string, the JPL will try to generate a suitable
 * hostname (i.e. by calling gethostname() on POSIX systems).
 * @param[in] app_name A string to use when filling out metadata sections. If
 * this is set to NULL o the empty string, the JPL will try to generate a
 * suitable process name.
 *
 * @param[out] conn A pointer that will receive the address of the newly created
 * jalp_connection, or NULL.
 *
 * @return JAL_OK on success, or an error code.
 */
enum jal_status jalp_connection_create(char* path, char *hostname, char *app_name, jalp_connection *conn);

/**
 * Connect to the JALoP Local Store. It is safe to call this repeatedly, even
 * after a connection was made. This call will block until the connection is
 * established.
 *
 * @param[in] conn the #jalp_connection to connect
 * @return JAL_OK if the connection is complete.
 */
enum jal_status jalp_connection_connect(jalp_connection conn);
/*
 * Disconect from a JAL Local Store
 * @param[in] conn the connection to disconnect.
 */
enum jal_status jalp_connection_disconnect(jalp_connection conn);
/**
 * Disconnect (if needed) and destroy the connection.
 *
 * @param[in,out] conn The #jalp_connection to destroy. On return, this will be set to
 * NULL.
 */
void jalp_connection_destroy(jalp_connection *conn);

/**
 * Send a log message to the JALoP Local Store
 *
 * @param[in] conn The connection to send the data over
 * @param[in] The 
 * @param[in] app_metadata An XML document conforming to the application metadata
 * schema.
 * @param[in] log_string A preformatted string to send to the JALoP Local Store
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
 * calculations, or they should use #jalp_log_buffer to truncate the buffer.
 *
 * The conn will be connected if it isn't already.
 *
 * app_meta or log_string may be NULL, but not both.
 * */
enum jal_status jalp_log(jalp_connection conn, struct jalp_app_metadata *app_meta, char* log_string);

/**
 * Send a log message to the JALoP Local Store
 *
 * @param[in] conn The connection to send the data over
 * @param[in] app_metadata[in] An XML document conforming to the application metadata
 * schema.
 * @param[in] log_buffer[in] A byte buffer
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
 * The conn will be connected if it isn't already.
 */
enum jal_status jalp_log_buffer(jalp_connection conn, struct jalp_app_metadata *app_meta, char *app_metadata, uint8_t *log_buffer, size_t log_buffer_size);

/**
 * Send a journal entry to the JALoP Local Store
 *
 * @param[in] conn The connection to send the data over
 * @param[in] app_metadata[in] Metedata about the journal data.
 * @param[in] log_string[in] A preformatted string to send to the JALoP Local Store
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
 * calculations or use jalp_journal_buffer(char*, uint8_t*, uint64_t);
 *
 * The conn will be connected if it isn't already.
 */
enum jal_status jalp_journal(jalp_connection conn, struct jalp_app_metadata *app_meta, char *journal_string);

/**
 * Send a journal data to the JALoP Local Store
 *
 * @param[in] app_metadata[in] An XML document conforming to the application metadata
 * schema.
 * @param[in] journal_buffer[in] A byte buffer that contains the full contents of
 * a journal entry.
 * @return JAL_OK on sucess.
 *         JAL_XML_PARSE_ERROR if app_metadata fails to parse
 *         JAL_XML_SCHEMA_ERROR if app_metadata fails to pass schema validation
 *         JAL_EINVAL If the parameters are incorrect.
 *         JAL_NOT_CONNECTED if a connection to the JALoP Local Store couldn't
 *         be made
 *
 * The conn will be connected if it isn't already.
 */
enum jal_status jalp_journal_buffer(jalp_connection conn, struct jalp_app_metadata *app_meta, uint8_t * journal_buffer, uint64_t journal_buffer_size);

/**
 * Send an open file descriptor to the JAL Local Store. The caller must not
 * write to the file identified by \p fd after making this call, or else the
 * JAL local store may receive incorrect data. This call works by sending just
 * the file descriptor and is not availble on all platforms. You can check for
 * it's existence by checking for JALP_CAN_SEND_FDS, example:
 * @code
 * #ifdef JALP_CAN_SEND_FDS
 * \/\* do something *\/
 * #endif
 * @endcode
 *
 * @param[in] conn The connection to send the record over.
 * @param[in] app_meta the application provided metadata (or null);
 * @param[in] fd The file descriptor of the journal.
 *
 * @note would it be better to fake this call if sending the file descriptor is
 * impossible? Considering that would make this call extremely slow on
 * platforms that don't have SCM_RIGHTS, I don't think it's a good idea to do that.
 * Could be done in a seperate worker thread, but that could still cause confusing 
 * behaviour since the sending thread here would need to prevent the app from
 * exiting while it's sending the data to the JNL....
 */
enum jal_status jalp_journal_fd(jalp_connection conn, 
		struct jalp_app_metadata *app_meta, 
		int fd);

/**
 * Open the file at \p path and send it the JAL local store. Internally, this
 * uses the #jalp_journal_fd call to send a file descriptor. The application
 * should never write to the file after calling this method, but is free to
 * unlink it.
 *
 * Applications should provide both the \p app_meta adn \p path paramters.
 * One of these paramaters may be NULL, but not both.
 *
 * @param[in] conn The connection to send the journal over.
 * @param[in] app_metadata The application provided metadata about the journal
 * entry.
 * @param[in] path The path to the file to journal.
 *
 * @return JAL_OK if the JPL was successful at opening the file and sending the
 * descriptor to the JAL local store.
 *
 * @note same comment as for #jalp_journal_fd, should we emulate this?
 *
 */
enum jal_status jalp_journal_path(jalp_connection conn, 
		struct jalp_app_metadata *app_meta,
		uint8_t * journal_buffer, 
		uint64_t journal_buffer_size);
/**
 * Send an audit record to the JALoP Local Store
 *
 * @param[in] conn The connection to send the data over
 * @param app_metadata[in] An XML document conforming to the application metadata
 * schema.
 * @param[in] audit_string[in] An audit document conforming to the MITRE CEE event.xsd document.
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
 * #jalp_audit_buffer()
 *
 * \p conn will be connected if it isn't already.
 */
enum jal_status jalp_audit(jalp_connection conn, 
		struct jalp_app_metadata *app_meta, 
		char *audit_string);

/**
 * Send an audit record to the JALoP Local Store
 *
 * @param[in] conn The connection to send the data over
 * @param[in] app_metadata Metadata about the audit entry.
 * @param[in] audit_buffer A byte buffer that contains the full contents of
 * a audit entry.
 * @return JAL_OK on sucess.
 *         JAL_XML_PARSE_ERROR if app_metadata fails to parse
 *         JAL_XML_SCHEMA_ERROR if app_metadata fails to pass schema validation
 *         JAL_EINVAL If the parameters are incorrect.
 *         JAL_NOT_CONNECTED if a connection to the JALoP Local Store couldn't
 *         be made
 *
 * \p conn will be connected if it isn't already.
 */
enum jal_status jalp_audit_buffer(jalp_connection conn,
			    struct jalp_app_metadata *app_meta,
			    uint8_t *audit_buffer,
			    size_t audit_buffer_size);

/**
 * Create a jalp_structured_data element.
 *
 * @param[in] prev The location in a list to add the element. If prev is not the
 * end of the list, then the new node is created as the next element of prev,
 * and prev->next becomes the new node's next element.
 * This function may be used to add elements to the end, or middle
 * of a list.
 * @param[in] sd_id The sd_id to use for the new element
 * @param[in] name The name of this element
 * @param value The value of this element.
 *
 * @return a newly created jalp_structred_data pointer. This must be freed with
 * jalp_destroy_structured_data_list(struct jalp_structured_data*).
 *
 * sd_id, name, and value are copied to allocated buffers.
 */
struct jalp_structured_data *jalp_create_structured_data(struct jalp_structured_data *prev, 
						       char *sd_id);
/**
 * Insert a new param element in \p group. If there are already elements in the
 * list, this will insert this param at the head of the list.
 * @see #jalp_structured_data_param_insert
 *
 * @param[in] group the SD element to add to.
 * @param[in] key The key of this param.
 * @param[in] value The value of this param.
 *
 * @return the newly created param
 */
struct jalp_structured_data_param *jalp_structured_data_insert_param(struct jalp_structured_data *group,
						       char *name, 
						       char *value);
/**
 * Create a new structured_data element as the next element in the list. If
 * #prev already has elements, this is inserted between the 2 existing
 * elements.
 * @param[in] prev The list to add to.
 * @param[in] key The key of this param.
 * @param[in] value The value of this param.
 *
 * @return the newly created param
 */
struct jalp_structured_data_param *jalp_structured_data_param_insert(struct jalp_structured_data_param *group,
						       char *name, 
						       char *value);
/**
 * Release all memory associated with this structured data list. This frees all
 * params of #group and all #jalp_structured_data elements.
 * @param[in,out] group The SD group to destory
 */
void jalp_free_structured_data_list(struct jalp_structured_data **group);
/**
 *
 * Destroy an entire list. This must only be called on the head of the list. If
 * called anywhere else, memory leaks will occur.
 *
 * @param head[in,out] The head of the list to free.
 */
void jalp_destroy_structured_data_list(struct jalp_structured_data **head);


#endif /* jalp_PRODUCER_H */
