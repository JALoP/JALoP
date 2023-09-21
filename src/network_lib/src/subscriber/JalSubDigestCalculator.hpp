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
#ifndef __JAL__SUB__DIGEST__CALCULATOR__H__
#define __JAL__SUB__DIGEST__CALCULATOR__H__

#include <stdexcept>
#include <string>

#include <jalop/jal_digest.h>
#include "jal_base64_internal.h"

class DigestCalculator
{
	private:
	void* instance;
	jal_digest_ctx* digestContext;
	enum jal_digest_algorithm digestAlgorithm;

	void initialize(enum jal_digest_algorithm type)
	{
		digestAlgorithm = type;
		// Initialize to safe values
		instance = NULL;
		digestContext = NULL;

		digestContext = jal_digest_ctx_create(type);

		// Set up the ocntext
		if(!digestContext)
		{
			throw std::runtime_error("Failed to initialize DigestCalculatorFactory");
		}

		instance = digestContext->create();
		if(!instance)
		{
			jal_digest_ctx_destroy(&digestContext);
			throw std::runtime_error("Failed to create digest instance");
		}
		enum jal_status ret = digestContext->init(instance);
		if(JAL_OK != ret)
		{
			digestContext->destroy(instance);
			jal_digest_ctx_destroy(&digestContext);
			throw std::runtime_error("Failed to initialize digest instance");
		}
	}

	void uninitialize()
	{
		if(instance)
		{
			digestContext->destroy(instance);
		}
		if(digestContext)
		{
			jal_digest_ctx_destroy(&digestContext);
		}
	}

	public:
	DigestCalculator(enum jal_digest_algorithm type)
	{
		initialize(type);
	}

	void changeAlgorithm(enum jal_digest_algorithm newAlgorithm)
	{
		uninitialize();
		initialize(newAlgorithm);
	}

	void addData(const std::vector<uint8_t>& data)
	{
		enum jal_status ret = digestContext->update(instance, data.data(), data.size());
		if(JAL_OK != ret)
		{
			throw std::runtime_error("Failed to add data to digest");
		}
	}

	void addData(const uint8_t* data, size_t len)
	{
		enum jal_status ret = digestContext->update(instance, data, len);
		if(JAL_OK != ret)
		{
			throw std::runtime_error("Failed to add data to digest");
		}
	}

	std::string finalizeDigest()
	{
		size_t digestLen = digestContext->len;
		uint8_t* digest = (uint8_t*)malloc(digestLen);
		enum jal_status ret = digestContext->final(instance, digest, &digestLen);
		if(JAL_OK != ret)
		{
			throw std::runtime_error("Failed to finalize digest");
		}

		// Each byte will be represented by 2 hex digits
		char* hexArray = (char*)malloc(sizeof(char)*digestLen*2 + 1);

		for(size_t i = 0; i < digestLen; i++)
		{
			sprintf(hexArray + 2*i, "%02x", digest[i]);
		}
		std::string hexStr(hexArray);
		free(hexArray);

		// TODO: Only calculate for DEBUG
		char* b64 = jal_base64_enc(digest, digestLen);
		printf("computed digest(b64): %s\n", b64);
		free(b64);
		free(digest);
		return hexStr;
	}

	~DigestCalculator()
	{
		uninitialize();
	}
};

#endif
