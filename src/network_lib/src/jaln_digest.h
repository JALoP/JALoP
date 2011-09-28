/**
 * @file This file contains function declarations for code related
 * to the digest used during JALoP communications.
 *
 * @section LICENSE
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
#ifndef _JALN_DIGEST_INTERNAL_H_
#define _JALN_DIGEST_INTERNAL_H_
#include <axl.h>
#include <jalop/jal_digest.h>
#include <jalop/jaln_network.h>
#include <jalop/jaln_network_types.h>

/**
 * Utility function used to destroy jal_digest_ctx objects stored in an
 * axlList. This is a very thin wrapper around jal_digset_ctx_destroy();
 *
 * @param[in] ptr;
 */
void jaln_digest_list_destroy(axlPointer ptr);

/**
 * Utility function used to compare 2 jal_digest_ctx objects stored in an
 * axlList. This function does a case-insensitive string comparison of
 * 'algorithm_uri' member.
 * @param[in] a The first jal_digest_ctx in the comparison
 * @param[in] b The second jal_digest_ctx in the comparison
 * @returns
 *  - 0 if the strings are equals
 *  - a negative value if a is '<' b
 *  - a positive value if b is '<' a
 */
int jaln_digest_list_equal_func(axlPointer a, axlPointer b);

#endif // _JALN_DIGEST_INTERNAL_H_
