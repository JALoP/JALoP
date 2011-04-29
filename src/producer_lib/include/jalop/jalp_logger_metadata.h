/**
 * @file jalp_logger_metadata.h This file defines structures related to 'logger'
 * metadata.
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
#ifndef JALP_LOGGOR_METADATA_H
#define JALP_LOGGOR_METADATA_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jalop/jalp_structured_data.h>
/**
 * @addtogroup AppMetadata
 * @{
 * @defgroup LoggerMetadata Logger Metadata
 * Structures and functions specific to generating
 * metadata for loggers (i.e. log4j, log4cxx, etc).
 * @{
 */

/**
 * Structure the encapsulates a severity level. The severity for a log may be
 * described by both an integer and a string. These values only have meaning to
 * the application.
 *
 * Applications must allocate and destroy this structure using
 * jalp_log_severity_create and jalp_log_severity_destroy.
 */
struct jalp_log_severity {
	/** indicates the numeric level */
	int level_val;
	/** an optional, human readable string */
	char *level_str;
};
/**
 * @ingroup LoggerMetadata
 * Create and initialize a jalp_log_severity object
 * @return The newly allocated log_severity object.
 *
 * @returns JAL_OK on success.
 */
struct jalp_log_severity *jalp_log_severity_create(void);
/**
 * @ingroup LoggerMetadata
 * destroy a jalp_log_severity object and any members.
 * @param[in,out] log_severity The object to destroy. This will be set to NULL.
 */
void jalp_log_severity_destroy(struct jalp_log_severity** log_severity);

/**
 * Structure to represent the 'logger' type data in the application meta-data.
 *
 * All fields are optional, except the logger_name.
 * The jalp_logger_metada object assumes ownership of all pointers.
 */
struct jalp_logger_metadata {
	/** The name of this logger*/
	char *logger_name;
	/** The severity of this log entry */
	struct jalp_log_severity *severity;
	/**
	 * The timestamp of this log entry. If NULL, the JPL will generate the
	 * timestamp. This must conform to the XML Schema dateTime type.
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
	/** An extended list of meta-data. */
	struct structured_data *sd;
};
/**
 * Create a logger metadata structure
 * @return the newly craeted jalp_logger_metadata object
 */
struct jalp_logger_metadata *jalp_logger_metadata_create(void);
/**
 * Release all memory related to a jalp_logger_metadata object. This calls the
 * appropriate "*_destroy()" functions and "free()" as needed.
 * @param[in] logger_meta The object to destroy, this will be set to NULL.
 */
void jalp_logger_metadata_destroy(struct jalp_logger_metadata **logger_meta);

/**
 * @defgroup StackFrame Stack Frames
 * @{
 * Logger applications often have additional information pertaining to the
 * runtime state of the sytem, such as the stack. The structures and functions
 * here provide a mechanism for logger libraries to include stack information
 * as part of the metadata included with a log entry.
 * @{
 */
/**
 * Represents one entry in a stack frame.  All fields are optional and may be
 * set to NULL. Line Numbers are assumed to start counting at 1, so a value of
 * 0 for \p line_number will suppress the filed.
 * If an application is providing multiple levels of stack information, they
 * should list the stack frames from the bottom up. That is, the first
 * stack_frame in the list should be the one where the log actually happened.
 *
 * The depth should be filled in to indicate the level in the stack trace. A
 * value of -1 indicates the depth for this frame should not be included. The
 * frame with depth 0 is considered the inner most (i.e. where the log took
 * place) frame.
 *
 * The JPL does not verify that the depths follow any particular order.
 *
 * Applications must create/destroy jalp_stack_frame objects using
 * jalp_stack_frame_create() and jalp_stack_frame_destory(). The
 * jalp_stack_frame assumes ownership of all memory it references.
 */
struct jalp_stack_frame {
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
	struct jalp_stack_frame *next;
};
/**
 * Create a new stack frame and add it to the list. If \p prev already points
 * somewhere, the new jalp_stack_frame is inserted between prev and prev->next.
 *
 * The application must fill in the remaining fields.
 * @param[in] prev The stack frame that will come before the new one. If NULL,
 * this creates a new list.
 *
 * @return The new jalp_stack_frame
 */
struct jalp_stack_frame *jalp_stack_frame_append(struct jalp_stack_frame* prev);

/**
 * Release all memory associated with a stack frame. This will release all 
 * associated memory using the appropriate "*_destroy()" function or "free()".
 * This releases jalp_stack_frame objects in the list.
 *
 * @param[in,out] stack_frame The stack frame to release. This will be set to NULL.
 */
void jalp_stack_frame_destroy(struct jalp_stack_frame **stack_frame);

/** @} */
/** @} */

#ifdef __cplusplus
}
#endif

#endif // JALP_LOGGOR_METADATA_H

