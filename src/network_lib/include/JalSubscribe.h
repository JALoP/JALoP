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

// This file represents a conversion layer between a C caller and the C++ implementation
// and so contains all functions a C user of the JalSubscriber should need to interact
// with the JalSubscriber class

#ifndef __C__JAL__SUBSCRIBE__H__
#define __C__JAL__SUBSCRIBE__H__


#ifdef __cplusplus
extern "C"
{
#endif
/**
 * C-style enum for easy mapping to internal types
 */
enum DB_Type
{
	DB_TYPE_BDB,
	DB_TYPE_FS
};
/**
 * Represents the configuration parameters required by the JalSubscriber
 */
struct SubscriberConfig_t;

/**
 * Represents a single subscriber and manages the lifetime of connections
 */
struct Subscriber_t;

/**
 * Create a Subscriber_t given a SubscriberConfig_t
 * Immediately begins listening for incoming http messages
 * Must be destroyed with jal_subscriber_destroy
 * @param[in] config The settings to use for this subscriber
 * @param[in/out] If errBuf is non-NULL and an error occurrs, a description of that error will
 * be allocated and placed at *errBuf. The caller is responsible for freeing this buffer
 * If no error occurrs *errBuf will be set to NULL.
 *
 * @return NULL on error, else a valid Subscriber_t*
 */
struct Subscriber_t* jal_subscriber_create(const struct SubscriberConfig_t*, char** errBuf);

/**
 * Waits for any currently-running threads to close (generally extremely fast) then
 * halts the http server and destroys all resources
 * @param[in] subscriber The subscriber object to destroy
 */
void jal_subscriber_destroy(struct Subscriber_t** subscriber);

/**
 * Create a SubscriberConfig with the settings given in the provided configFile
 * The caller is responsible for calling jal_subscriber_config_destory on the returned pointer
 * unless that pointer is NULL
 * @param[in] configFile Path to the config file
 * @param[in/out] If errBuf is non-NULL and an error occurrs, a description of that error will
 * be allocated and placed at *errBuf. The caller is responsible for freeing this buffer
 * If no error occurrs *errBuf will be set to NULL.
 *
 * @return Null on failure, otherwise a valid SubscriberConfig_t
 */
struct SubscriberConfig_t* jal_subscriber_config_create(
	const char* configFile,
	char** errBuf);

/**
 * Frees the memory associated with a SubscriberConfig_t.
 * @param[in] subscriberConfig The SubscriberConfig_t to be destroyed
 */
void jal_subscriber_config_destroy(
	struct SubscriberConfig_t**);

/**
 * Print the current settings of a SubscriberConfig_t to stdout
 * @param[in] The configuration to print
 */
void jal_subscriber_config_print_configuration(
	const struct SubscriberConfig_t*);

/**
 * Configure the port the http server listen on for incoming connections
 * @param[in] config The configuration object to modify
 * @param[in] portno The new port number to use
 * @return JAL_E_INVAL if the passed in config object is NULL or otherwise invalid
 * else JAL_OK
 */
enum jal_status jal_subscriber_config_set_port(
	struct SubscriberConfig_t* config,
	const int portno);

/**
 * Configure the database path where incoming records should be stored.
 * @param[in] config The configuration object to modify
 * @param[in] databasePath The new path to use
 * @return JAL_E_INVAL if the passed in config object is NULL or otherwise invalid
 * else JAL_OK
 */
enum jal_status jal_subscriber_config_set_database_path(
	struct SubscriberConfig_t* config,
	const char* databasePath);

/**
 * Configure the debug mode
 * @param[in] config The configuration object to modify
 * @param[in] debug The new debug setting. 0 disables debug output, any other value
 * enables debug output
 * @return JAL_E_INVAL if the passed in config object is NULL or otherwise invalid
 * else JAL_OK
 */
enum jal_status jal_subscriber_config_set_debug(
	struct SubscriberConfig_t* config,
	const int debug);

/**
 * Configure the database path where incoming records should be stored.
 * @param[in] config The configuration object to modify
 * @param[in] modeStr The new path to use
 * @return JAL_E_INVAL if the passed in config object is NULL or otherwise invalid
 * also returns JAL_E_INVAL if the modeStr isn't one of [archive|archival|live]
 * else returns JAL_OK
 */
enum jal_status jal_subscriber_config_set_mode(
	struct SubscriberConfig_t* config,
	const char* modeStr);

/**
 * Configure the allowed set of digest algorithms
 * @param[in] config The configuration object to modify
 * @param[in] digest_algorithms A space separated string of digest algorithms from the set
 * [sha_256|sha_384|sha_512]
 * @return JAL_E_INVAL if the passed in config object is NULL or otherwise invalid
 * also returns JAL_E_INVAL if the digest_algorithms string is empty or contains illegal
 * symbols. else returns JAL_OK
 */
enum jal_status jal_subscriber_config_set_digest_algorithms(
	struct SubscriberConfig_t* config,
	const char* modeStr);

/**
 * Configures the use of TLS when setting up the http server
 * @param[in] The config to modify
 * @param[in] Indicate whether TLS should be enabled or disabled
 * 0 - Disables TLS
 * Non-0 - Enables TLS
 * @return JAL_E_INVAL if the passed in config object is NULL or otherwise invalid
 * else returns JAL_OK
 */
enum jal_status jal_subscriber_config_set_tls(
	struct SubscriberConfig_t* config,
	const int tlsSetting);

/**
 * Configures the database format with which to store incoming records
 * @param[in] config The config to modify
 * @param[in] dbType The type of database to use
 * @return JAL_E_INVAL if the passed in config object is NULL or otherwise invalid
 * also returns JAL_E_INVAL if the dbType enum is not set to a valid value
 * else returns JAL_OK
 */
enum jal_status jal_subscriber_config_set_db_type(
	struct SubscriberConfig_t* config,
	enum DB_Type);

/**
 * Configure the subscriber to bind to a specific ip address.
 * @param[in] config The config to modify
 * @param[in] addr An ipv4 struct sockadd_in
 * @return JAL_OK
 */
enum jal_status jal_subscriber_config_set_server_ip(
	struct SubscriberConfig_t* config,
	const char* addr);

#ifdef __cplusplus
}
#endif

#endif
