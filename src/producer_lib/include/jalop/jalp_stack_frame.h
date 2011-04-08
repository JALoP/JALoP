/**
 * @file jal_stack_frame.h This file defines the structure and functions use to
 * create a stack frame entry in the application metadata.
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
#ifndef JALP_STACK_FRAME_H
#define JALP_STACK_FRAME_H
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
 * Create a new stack frame and add it to the list. If #prev already points
 * somewhere, the new jalp_stack_frame is inserted between prev and prev->next.
 * 
 * The application must fill in the remaining fields.
 *
 * @return The new jalp_stack_frame
 */
struct jalp_stack_frame *jalp_stack_frame_append(struct jalp_stack_frame* prev);

/**
 * Release all memory associated with a stack frame. This will release all 
 * associated memory using the appropriate "*_destroy()" function or "free()".
 * This releases jalp_stack_frame objects in the list.
 *
 * @param[in,out] The stack frame to release. This will be set to NULL.
 */
void jalp_stack_frame_destroy(struct jalp_stack_frame **stack_frame);

#endif // JALP_STACK_FRAME_H

