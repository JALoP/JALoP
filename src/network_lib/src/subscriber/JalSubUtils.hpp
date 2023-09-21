/*
 * Copyright (C) 2023 The National Security Agency (NSA)
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
#ifndef __JAL__SUB__UTILS__H__
#define __JAL__SUB__UTILS__H__

#include "JalSubEnumTypes.hpp"

#include <string>

bool createDir(std::string path);
bool dirExists(std::string path);
void debugOutput(bool shouldPrint, FILE* fd, const char* fmt, ...)
	__attribute__((format(printf, 3, 4)));
// This __attribute__ hints to the compiler that it can inspect the format string
// against the following arguments like it does for printf to help catch certain classes
// of type errors
std::string getPayloadFileName(
	std::string tempFilePath,
	std::string publisherId,
	ReceiveMessageType messageType,
	std::string jalId);

#endif
