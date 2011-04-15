/**
 * @file jalp_journal_metadata.h This file defines structures and functions for
 * building the "journalMetadata" section of the application metadata.
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
#ifndef JALP_JOURNAL_METADATA_H
#define JALP_JOURNAL_METADATA_H
#include <jalp_file_info.h>
#include <jalp_journal_transforms.h>
/**
 * @defgroup JournalMetadata Journal Metadata
 * This contains additional structures and functions to generate information
 * about journal data. Journal Data is typically large, binary files and the
 * APIs in this section allow applications to attach information such as the
 * filename, original file size, or threat level (jalp_threat_level).
 *
 * JALoP (and this library) make no attempt to compress, encrypt or otherwise
 * transform files. Applications may wish to perform any number of transforms
 * before sending the file to the JAL local store, though they should describe
 * any transforms applied by filling approprate jalp_transform structures.
 * @{
 */
/**
 * Enum to restrict AES keysizes
 */
enum jalp_aes_key_size {
	/** Indicates a 128 bit (16 byte) key */
	JALP_AES128,
	/** Indicates a 192 bit (24 byte) key */
	JALP_AES192,
	/** Indicates a 256 bit (32 byte) key */
	JALP_AES256,
};
/**
 * Structure to describe transforms applied to an entry
 */
struct jalp_transform {
	/** the URI for this transform */
	char *uri;
	/** (optional) snippet of XML code to add as a child of the transform element. */
	char *xml;
	/** The next transform in the sequence, or NULL */
	struct jalp_transform *next;
};

/**
 * Create another transform in the chain.
 *
 * @param[in] prev The transform that should come directly before the new
 * transform. If \p prev already points somewhere for \p next, the new
 * transform is inserted into the list.
 * @param[in] uri A URI for the transform.
 * @param[in] xml_snippet XML for the body of the transform. This must be valid
 * XML.
 * @return A pointer to the newly created transform
 */
struct jalp_transform *jalp_transform_append(struct jalp_transform *prev,
		char *uri,
		char *xml_snippet);
/**
 * Release all memory associated with a #jalp_transform object. This frees all
 * #jalp_transform objects in the list and calls free for every data member.
 * @param[in] transform the list to destroy.
 */
void jalp_transform_destroy(struct jalp_transform **transform);

/**
 * Create an XOR transform in the chain.
 *
 * @param[in] prev The transform that should come directly before the new
 * transform. If \p prev already points somewhere for \p next, the new
 * transform is inserted into the list.
 * @param[in] key The 4 byte XOR key that was applied to the data, this must
 * not be the bytestring 0x00000000.
 * @return a pointer to the newly created transform
 */

struct jalp_transform *jalp_transform_append_xor(struct jalp_transform *prev,
		uint32_t key);

/**
 * Create a deflate transform in the chain.
 *
 * @param[in] prev The transform that should come directly before the new
 * transform. If \p prev already points somewhere for \p next, the new
 * transform is inserted into the list.
 * @return a pointer to the newly created transform.
 */
struct jalp_transform *jalp_transform_append_deflate(struct jalp_transform *prev);


/**
 * Create an AES transform in the chain. This should only be used for AES
 * transforms as described in the JALoP-v1.0 specification. The key and IV are
 * not required, but are recommended since the intent is not to provide data
 * security, but protection from accidental execution of malicious code.
 *
 * @param[in] prev The transform that should come directly before the new
 * transform. If \p prev already points somewhere for \p next, the new
 * transform is inserted into the list.
 * @param[in] key_size The key size. The length of \p key is determined by \p
 * key_sizefor example, if \p key_size is #JALP_AES192, the \p key array is
 * assumed to be 24 bytes in length.
 * @param[in] key The AES key, or NULL, the length of this array is determined
 * by \p key_size.
 * @param[in] iv The initialization vector, or NULL. If the IV is provided, it
 * is assumed to contain a 128 bit (16 byte) IV.
 * @return a pointer to the newly created transform
 */
struct jalp_transform *jalp_transform_append_aes(struct jalp_transform *prev,
		enum jalp_aes_key_size key_size,
		uint8_t *key,
		uint8_t *iv);
/**
 * Structure to provide metadata about the payload, typically only used for
 * journal entries.
 */
struct jalp_journal_metadata {
	/**
	 * Generic metadata about the file.
	 */
	struct jalp_file_info *file_info;
	/**
	 * List of transforms that the application applied before submitting
	 * the entry to the JAL local store
	 */
	struct jalp_journal_transform *transforms;
};
/**
 * Create and initialize a jalp_journal_metadata object
 * @return a newly created journal_metadata entry.
 */
struct jalp_journal_metadata *jalp_journal_metadata_create(void);
/**
 * @ingroup jalp_journal_metadata
 * Release all memory associated with a jalp_journal_metadata object. This
 * calls the appropriate "*_destroy()" functions and "free()" on all members.
 * @param[in,out] journal_meta the object to destroy, this will be set to NULL.
 */
void jalp_journal_metadata_destroy(struct jalp_journal_metadata **journal_meta)

/** @} */
#endif //JALP_JOURNAL_METADATA_H

