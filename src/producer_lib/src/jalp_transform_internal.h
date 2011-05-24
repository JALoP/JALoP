/**
 * @file jalp_transform_internal.h This file defines the private apis and helper
 * functions for the transform structure.
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
#ifndef _JALP_TRANSFORM_INTERNAL_H_
#define _JALP_TRANSFORM_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Release all memory associated with one #jalp_transform object. This calls 
 * free for every data member in the list.
 *
 * @param[in] transform the #jalp_transform to destroy to destroy.
 */
void jalp_transform_destroy_one(struct jalp_transform *transform);

#ifdef __cplusplus
}
#endif

#endif //_JALP_TRANSFORM_INTERNAL_H_

