/**
 * @file
 *
 * @brief This file contains functions to test
 * the libconfig wrapper functions
 *
 * ### LICENSE
 *
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

#include <stdlib.h>
#include <string.h>
#include <test-dept.h>

#include "jal_config.h"

config_t config_file = { };
config_setting_t retval;
char *config_string_val;
config_setting_t root = { .name = "Root", };
char *setting_name = "stub";

static int DEFAULT_INT_VAL = 0;
static int CHANGED_INT_VAL = 1;
static long long DEFAULT_INT64_VAL = 0;
static long long CHANGED_INT64_VAL = 1;
static char *DEFAULT_STR_VAL = NULL;
static char *CHANGED_STR_VAL = "Test String Value";
static char *FIRST_LIST_STR = "First";
static char *SECOND_LIST_STR = "Second";
static char *THIRD_LIST_STR = "Third";
static int NUM_LIST_ITEMS = 3;

// Because the length is dynamically calculated, -1 won't work as an obvious invalid number
static int NUM_LIST_ITEMS_BAD = 0;

// Mock fprintf function - this prints config errors to stderr in the jal_config functions we are testing.
// If we don't mock this function, hit an error case, and try to print, we get a segfault.
int mock_fprintf(__attribute__((unused)) FILE *__restrict__ __stream, __attribute__((unused)) const char *__restrict__ __format, ...)
{
  // Do nothing
  return 1;
}

// Mock fwrite function - this is what gets called when we fprintf a string with no var_args
// If we don't mock this function, hit an error case, and try to print, we get a segfault.
size_t mock_fwrite(__attribute__((unused)) const void *__restrict __ptr,__attribute__((unused)) size_t __size, __attribute__((unused)) size_t __n, __attribute__((unused)) FILE *__restrict __s)
{
  // Do nothing
  return 1;
}

// Mock fputc function - this is what gets called if you fprintf a single char
// If we don't mock this function, hit an error case, and try to print, we get a segfault
int mock_fputc(__attribute__((unused)) int c, __attribute__((unused)) FILE *fp)
{
  // Do nothing
  return 1;
}

int mock_config_read_file(__attribute__((unused)) config_t *config, __attribute__((unused)) const char *filename)
{
  return CONFIG_TRUE;
}

int mock_config_read_file_bad(__attribute__((unused)) config_t *config, __attribute__((unused)) const char *filename)
{
  return CONFIG_FALSE;
}

// Create a mocked bool setting to return like we read it from a config file. Note that this is only a partial
// struct and only contain the fields that are checked/used in jal_config.
config_setting_t *mock_config_setting_get_member_bool(__attribute__((unused)) const config_setting_t *setting, __attribute__((unused)) const char *name)
{
  retval = (config_setting_t)
  {
    .name = setting_name,
    .type = CONFIG_TYPE_BOOL,
    .line = 1
  };

  return &retval;
}

// Act like we are returning the value from a bool setting.
int mock_config_setting_get_bool(__attribute__((unused)) const config_setting_t *setting)
{
  return CHANGED_INT_VAL;
}

// Create a mocked int setting to return like we read it from a config file. Note that this is only a partial
// struct and only contain the fields that are checked/used in jal_config.
config_setting_t *mock_config_setting_get_member_int(__attribute__((unused)) const config_setting_t *setting, __attribute__((unused)) const char *name)
{
  retval = (config_setting_t)
  {
    .name = setting_name,
    .type = CONFIG_TYPE_INT,
    .line = 1
  };

  return &retval;
}

// Act like we are returning the value from an int setting.
int mock_config_setting_get_int(__attribute__((unused)) const config_setting_t *setting)
{
  return CHANGED_INT_VAL;
}

// Create a mocked int64 setting to return like we read it from a config file. Note that this is only a partial
// struct and only contain the fields that are checked/used in jal_config.
config_setting_t *mock_config_setting_get_member_int64(__attribute__((unused)) const config_setting_t *setting, __attribute__((unused)) const char *name)
{
  retval = (config_setting_t)
  {
    .name = setting_name,
    .type = CONFIG_TYPE_INT64,
    .line = 1
  };

  return &retval;
}

// Act like we are returning the value from an int64 setting.
long long mock_config_setting_get_int64(__attribute__((unused)) const config_setting_t *setting)
{
  return CHANGED_INT64_VAL;
}

// Create a mocked string setting to return like we read it from a config file. Note that this is only a partial
// struct and only contain the fields that are checked/used in jal_config.
config_setting_t *mock_config_setting_get_member_string(__attribute__((unused)) const config_setting_t *setting, __attribute__((unused)) const char *name)
{
  retval = (config_setting_t)
  {
    .name = setting_name,
    .type = CONFIG_TYPE_STRING,
    .line = 1
  };

  return &retval;
}

// Act like we are returning the value from a string setting.
const char *mock_config_setting_get_string(__attribute__((unused)) const config_setting_t *setting)
{
  return CHANGED_STR_VAL;
}

// Act like we could not find the value for a string setting.
const char *mock_config_setting_get_string_null(__attribute__((unused)) const config_setting_t *setting)
{
  // The purpose of this is to test some conditions in jal_config_setting_get_string, even if this
  // may not be realistic.
  return NULL;
}

// Return a mocked list with 3 elements to return
config_setting_t *mock_config_setting_get_list(__attribute__((unused)) const config_setting_t *setting, __attribute__((unused)) const char *name)
{
  retval = (config_setting_t)
  {
    .name = setting_name,
    .type = CONFIG_TYPE_LIST,
    .line = 1
  };

  // Negative index means to add item to the end of the list
  config_setting_set_string_elem(&retval, -1, FIRST_LIST_STR);
  config_setting_set_string_elem(&retval, -1, SECOND_LIST_STR);
  config_setting_set_string_elem(&retval, -1, THIRD_LIST_STR);

  return &retval;
}

// Return an empty list
config_setting_t *mock_config_setting_get_list_bad_length(__attribute__((unused)) const config_setting_t *setting, __attribute__((unused)) const char *name)
{
  retval = (config_setting_t)
  {
    .name = setting_name,
    .type = CONFIG_TYPE_LIST,
    .line = 1
  };

  return &retval;
}

// Return a config_setting_t with the GROUP type
config_setting_t *mock_config_setting_get_elem_group(__attribute__((unused)) const config_setting_t *setting, __attribute__((unused)) unsigned int idx)
{
  retval = (config_setting_t)
  {
    .name = setting_name,
    .type = CONFIG_TYPE_GROUP,
    .line = 1
  };

  return &retval;
}

// Return a config_setting_t with the STRING type when GROUP is expected
config_setting_t *mock_config_setting_get_elem_group_wrong_type(__attribute__((unused)) const config_setting_t *setting, __attribute__((unused)) unsigned int idx)
{
  retval = (config_setting_t)
  {
    .name = setting_name,
    .type = CONFIG_TYPE_STRING,
    .line = 1
  };

  return &retval;
}

// Return a mocked string member of a group/list
config_setting_t *mock_config_setting_get_elem_string(const config_setting_t *setting, __attribute__((unused)) unsigned int idx)
{
  return mock_config_setting_get_member_string(setting, setting_name);
}

// Return a mocked integer member of a group/list where a string member is expected
config_setting_t *mock_config_setting_get_elem_string_wrong_type(const config_setting_t *setting, __attribute__((unused)) unsigned int idx)
{
  return mock_config_setting_get_member_int(setting, setting_name);
}

// Return NULL as a member of a group/list when a non-NULL member is expected
config_setting_t *mock_config_setting_get_member_null(__attribute__((unused)) const config_setting_t *setting, __attribute__((unused)) const char *name)
{
  return NULL;
}

// Return a mocked integer member of a group/list
config_setting_t *mock_config_setting_get_elem_int(const config_setting_t *setting, __attribute__((unused)) unsigned int idx)
{
  return mock_config_setting_get_member_int(setting, setting_name);
}

// Return a mocked bool member of a group/list where an integer member is expected
config_setting_t *mock_config_setting_get_elem_int_wrong_type(const config_setting_t *setting, __attribute__((unused)) unsigned int idx)
{
  return mock_config_setting_get_member_bool(setting, setting_name);
}

void setup()
{
  replace_function(&fprintf, &mock_fprintf);
  replace_function(&fwrite, &mock_fwrite);
  replace_function(&fputc, &mock_fputc);
}

void teardown()
{
  restore_function(&fprintf);
  restore_function(&fwrite);
  restore_function(&fputc);
}

/*
 * No reason to test jal_config_init as long as it only wraps config_init
 * and returns JAL_CFG_SUCCESS.
 *
 * Verify that jal_config_read_file returns the expected value based on the
 * result of config_read_file.
 */
void test_config_read_file()
{
  replace_function(&config_read_file, &mock_config_read_file);
  assert_equals(JAL_CFG_SUCCESS, jal_config_read_file(&config_file, ""));
  restore_function(config_read_file);
}

void test_config_read_file_bad()
{
  replace_function(&config_read_file, &mock_config_read_file_bad);
  assert_equals(JAL_CFG_FAILURE, jal_config_read_file(&config_file, ""));
  restore_function(config_read_file);
}

/*
 * For each of the types { bool, int, int64, string }, do the following tests:
 *   - Verify that the value changes when a valid value is read from the config when the parameter is required/optional
 *   - Verify that an error is handled when a required parameter is missing from the config
 *   - Verify that the value remains unchanged when an optional parameter is missing from the config
 *   - Verify that an error is handled when the wrong type is found when the parameter is required/optional
 *
 * For the string type only, do the following tests:
 *   - Verify that an error is handled when a NULL string is returned when retrieving the value when the parameter is required
 *   - Verify that the value remains unchanged when a NULL string is returned when retrieving the value when the parameter is optional
 */

void test_bool_good_required()
{
  int config_val = DEFAULT_INT_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_bool);
  replace_function(&config_setting_get_bool, &mock_config_setting_get_bool);
  assert_equals(JAL_CFG_SUCCESS, jal_config_lookup_bool(&root, setting_name, &config_val, JAL_CFG_REQUIRED));
  assert_equals(CHANGED_INT_VAL, config_val);
  restore_function(&config_setting_get_member);
  restore_function(&config_setting_get_bool);
}

void test_bool_good_optional()
{
  int config_val = DEFAULT_INT_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_bool);
  replace_function(&config_setting_get_bool, &mock_config_setting_get_bool);
  assert_equals(JAL_CFG_SUCCESS, jal_config_lookup_bool(&root, setting_name, &config_val, JAL_CFG_OPTIONAL));
  assert_equals(CHANGED_INT_VAL, config_val);
  restore_function(&config_setting_get_member);
  restore_function(&config_setting_get_bool);
}

void test_bool_missing_required()
{
  int config_val = DEFAULT_INT_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_null);
  replace_function(&config_setting_get_bool, &mock_config_setting_get_bool);
  assert_equals(JAL_CFG_FAILURE, jal_config_lookup_bool(&root, setting_name, &config_val, JAL_CFG_REQUIRED));
  assert_equals(DEFAULT_INT_VAL, config_val);
  restore_function(&config_setting_get_member);
  restore_function(&config_setting_get_bool);
}

void test_bool_missing_optional()
{
  int config_val = DEFAULT_INT_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_null);
  replace_function(&config_setting_get_bool, &mock_config_setting_get_bool);
  assert_equals(JAL_CFG_SUCCESS, jal_config_lookup_bool(&root, setting_name, &config_val, JAL_CFG_OPTIONAL));
  assert_equals(DEFAULT_INT_VAL, config_val);
  restore_function(&config_setting_get_member);
  restore_function(&config_setting_get_bool);
}

void test_bool_wrong_type_required()
{
  int config_val = DEFAULT_INT_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_int);
  replace_function(&config_setting_get_bool, &mock_config_setting_get_bool);
  assert_equals(JAL_CFG_FAILURE, jal_config_lookup_bool(&root, setting_name, &config_val, JAL_CFG_REQUIRED));
  assert_equals(DEFAULT_INT_VAL, config_val);
  restore_function(&config_setting_get_member);
  restore_function(&config_setting_get_bool);
}

void test_bool_wrong_type_optional()
{
  int config_val = DEFAULT_INT_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_int);
  replace_function(&config_setting_get_bool, &mock_config_setting_get_bool);
  assert_equals(JAL_CFG_FAILURE, jal_config_lookup_bool(&root, setting_name, &config_val, JAL_CFG_OPTIONAL));
  assert_equals(DEFAULT_INT_VAL, config_val);
  restore_function(&config_setting_get_member);
  restore_function(&config_setting_get_bool);
}

void test_int_good_required()
{
  int config_val = DEFAULT_INT_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_int);
  replace_function(&config_setting_get_int, &mock_config_setting_get_int);
  assert_equals(JAL_CFG_SUCCESS, jal_config_lookup_int(&root, setting_name, &config_val, JAL_CFG_REQUIRED));
  assert_equals(CHANGED_INT_VAL, config_val);
  restore_function(&config_setting_get_member);
  restore_function(&config_setting_get_int);
}

void test_int_good_optional()
{
  int config_val = DEFAULT_INT_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_int);
  replace_function(&config_setting_get_int, &mock_config_setting_get_int);
  assert_equals(JAL_CFG_SUCCESS, jal_config_lookup_int(&root, setting_name, &config_val, JAL_CFG_OPTIONAL));
  assert_equals(CHANGED_INT_VAL, config_val);
  restore_function(&config_setting_get_member);
  restore_function(&config_setting_get_int);
}

void test_int_missing_required()
{
  int config_val = DEFAULT_INT_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_null);
  replace_function(&config_setting_get_int, &mock_config_setting_get_int);
  assert_equals(JAL_CFG_FAILURE, jal_config_lookup_int(&root, setting_name, &config_val, JAL_CFG_REQUIRED));
  assert_equals(DEFAULT_INT_VAL, config_val);
  restore_function(&config_setting_get_member);
  restore_function(&config_setting_get_int);
}

void test_int_missing_optional()
{
  int config_val = DEFAULT_INT_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_null);
  replace_function(&config_setting_get_int, &mock_config_setting_get_int);
  assert_equals(JAL_CFG_SUCCESS, jal_config_lookup_int(&root, setting_name, &config_val, JAL_CFG_OPTIONAL));
  assert_equals(DEFAULT_INT_VAL, config_val);
  restore_function(&config_setting_get_member);
  restore_function(&config_setting_get_int);
}

void test_int_wrong_type_required()
{
  int config_val = DEFAULT_INT_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_int64);
  replace_function(&config_setting_get_int, &mock_config_setting_get_int);
  assert_equals(JAL_CFG_FAILURE, jal_config_lookup_int(&root, setting_name, &config_val, JAL_CFG_REQUIRED));
  assert_equals(DEFAULT_INT_VAL, config_val);
  restore_function(&config_setting_get_member);
  restore_function(&config_setting_get_int);
}

void test_int_wrong_type_optional()
{
  int config_val = DEFAULT_INT_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_int64);
  replace_function(&config_setting_get_int, &mock_config_setting_get_int);
  assert_equals(JAL_CFG_FAILURE, jal_config_lookup_int(&root, setting_name, &config_val, JAL_CFG_OPTIONAL));
  assert_equals(DEFAULT_INT_VAL, config_val);
  restore_function(&config_setting_get_member);
  restore_function(&config_setting_get_int);
}

void test_int64_good_required()
{
  long long config_val = DEFAULT_INT64_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_int64);
  replace_function(&config_setting_get_int64, &mock_config_setting_get_int64);
  assert_equals(JAL_CFG_SUCCESS, jal_config_lookup_int64(&root, setting_name, &config_val, JAL_CFG_REQUIRED));
  assert_equals(CHANGED_INT64_VAL, config_val);
  restore_function(&config_setting_get_member);
  restore_function(&config_setting_get_int64);
}

void test_int64_good_optional()
{
  long long config_val = DEFAULT_INT64_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_int64);
  replace_function(&config_setting_get_int64, &mock_config_setting_get_int64);
  assert_equals(JAL_CFG_SUCCESS, jal_config_lookup_int64(&root, setting_name, &config_val, JAL_CFG_OPTIONAL));
  assert_equals(CHANGED_INT64_VAL, config_val);
  restore_function(&config_setting_get_member);
  restore_function(&config_setting_get_int64);
}

void test_int64_missing_required()
{
  long long config_val = DEFAULT_INT64_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_null);
  replace_function(&config_setting_get_int64, &mock_config_setting_get_int64);
  assert_equals(JAL_CFG_FAILURE, jal_config_lookup_int64(&root, setting_name, &config_val, JAL_CFG_REQUIRED));
  assert_equals(DEFAULT_INT64_VAL, config_val);
  restore_function(&config_setting_get_member);
  restore_function(&config_setting_get_int64);
}

void test_int64_missing_optional()
{
  long long config_val = DEFAULT_INT64_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_null);
  replace_function(&config_setting_get_int64, &mock_config_setting_get_int64);
  assert_equals(JAL_CFG_SUCCESS, jal_config_lookup_int64(&root, setting_name, &config_val, JAL_CFG_OPTIONAL));
  assert_equals(DEFAULT_INT64_VAL, config_val);
  restore_function(&config_setting_get_member);
  restore_function(&config_setting_get_int64);
}

void test_int64_wrong_type_required()
{
  long long config_val = DEFAULT_INT64_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_bool);
  replace_function(&config_setting_get_int64, &mock_config_setting_get_int64);
  assert_equals(JAL_CFG_FAILURE, jal_config_lookup_int64(&root, setting_name, &config_val, JAL_CFG_REQUIRED));
  assert_equals(DEFAULT_INT64_VAL, config_val);
  restore_function(&config_setting_get_member);
  restore_function(&config_setting_get_int64);
}

void test_int64_wrong_type_optional()
{
  long long config_val = DEFAULT_INT64_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_bool);
  replace_function(&config_setting_get_int64, &mock_config_setting_get_int64);
  assert_equals(JAL_CFG_FAILURE, jal_config_lookup_int64(&root, setting_name, &config_val, JAL_CFG_OPTIONAL));
  assert_equals(DEFAULT_INT64_VAL, config_val);
  restore_function(&config_setting_get_member);
  restore_function(&config_setting_get_int64);
}

void test_string_good_required()
{
  char *config_val = DEFAULT_STR_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_string);
  replace_function(&config_setting_get_string, &mock_config_setting_get_string);
  assert_equals(JAL_CFG_SUCCESS, jal_config_lookup_string(&root, setting_name, &config_val, JAL_CFG_REQUIRED));
  assert_string_equals(CHANGED_STR_VAL, config_val);
  restore_function(config_setting_get_member);
  restore_function(config_setting_get_string);

  // Free memory malloc'd by strdup
  free(config_val);
}

void test_string_good_optional()
{
  char *config_val = DEFAULT_STR_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_string);
  replace_function(&config_setting_get_string, &mock_config_setting_get_string);
  assert_equals(JAL_CFG_SUCCESS, jal_config_lookup_string(&root, setting_name, &config_val, JAL_CFG_OPTIONAL));
  assert_string_equals(CHANGED_STR_VAL, config_val);
  restore_function(config_setting_get_member);
  restore_function(config_setting_get_string);

  // Free memory malloc'd by strdup
  free(config_val);
}

void test_string_missing_required()
{
  char *config_val = DEFAULT_STR_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_null);
  replace_function(&config_setting_get_string, &mock_config_setting_get_string);
  assert_equals(JAL_CFG_FAILURE, jal_config_lookup_string(&root, setting_name, &config_val, JAL_CFG_REQUIRED));
  assert_equals(DEFAULT_STR_VAL, config_val);
  restore_function(config_setting_get_member);
  restore_function(config_setting_get_string);
}

void test_string_missing_optional()
{
  char *config_val = DEFAULT_STR_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_null);
  replace_function(&config_setting_get_string, &mock_config_setting_get_string);
  assert_equals(JAL_CFG_SUCCESS, jal_config_lookup_string(&root, setting_name, &config_val, JAL_CFG_OPTIONAL));
  assert_equals(DEFAULT_STR_VAL, config_val);
  restore_function(config_setting_get_member);
  restore_function(config_setting_get_string);
}

void test_string_wrong_type_required()
{
  char *config_val = DEFAULT_STR_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_int);
  replace_function(&config_setting_get_string, &mock_config_setting_get_string);
  assert_equals(JAL_CFG_FAILURE, jal_config_lookup_string(&root, setting_name, &config_val, JAL_CFG_REQUIRED));
  assert_equals(DEFAULT_STR_VAL, config_val);
  restore_function(config_setting_get_member);
  restore_function(config_setting_get_string);
}

void test_string_wrong_type_optional()
{
  char *config_val = DEFAULT_STR_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_int);
  replace_function(&config_setting_get_string, &mock_config_setting_get_string);
  assert_equals(JAL_CFG_FAILURE, jal_config_lookup_string(&root, setting_name, &config_val, JAL_CFG_OPTIONAL));
  assert_equals(DEFAULT_STR_VAL, config_val);
  restore_function(config_setting_get_member);
  restore_function(config_setting_get_string);
}

void test_string_empty_required()
{
  char *config_val = DEFAULT_STR_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_string);
  replace_function(&config_setting_get_string, &mock_config_setting_get_string_null);
  assert_equals(JAL_CFG_FAILURE, jal_config_lookup_string(&root, setting_name, &config_val, JAL_CFG_REQUIRED));
  assert_equals(DEFAULT_STR_VAL, config_val);
  restore_function(config_setting_get_member);
  restore_function(config_setting_get_string);
}

void test_string_empty_optional()
{
  char *config_val = DEFAULT_STR_VAL;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_string);
  replace_function(&config_setting_get_string, &mock_config_setting_get_string_null);
  assert_equals(JAL_CFG_SUCCESS, jal_config_lookup_string(&root, setting_name, &config_val, JAL_CFG_OPTIONAL));
  assert_equals(DEFAULT_STR_VAL, config_val);
  restore_function(config_setting_get_member);
  restore_function(config_setting_get_string);
}

/*
 * For a list, do the following tests when the list is both required/optional:
 *   - Verify that the return code is correct when a valid list is returned
 *   - Verify that the return code is correct when an expected list is missing
 *   - Verify that the return code is correct when an empty list is found
 */
void test_list_good_required()
{
  config_setting_t *list = NULL;
  int list_length;
  replace_function(&config_setting_get_member, &mock_config_setting_get_list);
  assert_equals(JAL_CFG_SUCCESS, jal_config_lookup_list(&root, setting_name, &list, &list_length, JAL_CFG_REQUIRED));
  assert_equals(NUM_LIST_ITEMS, list_length);
  restore_function(config_setting_get_member);
}

void test_list_good_optional()
{
  config_setting_t *list = NULL;
  int list_length;
  replace_function(&config_setting_get_member, &mock_config_setting_get_list);
  assert_equals(JAL_CFG_SUCCESS, jal_config_lookup_list(&root, setting_name, &list, &list_length, JAL_CFG_OPTIONAL));
  assert_equals(NUM_LIST_ITEMS, list_length);
  restore_function(config_setting_get_member);
}

void test_list_missing_required()
{
  config_setting_t *list = NULL;
  int list_length;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_null);
  assert_equals(JAL_CFG_FAILURE, jal_config_lookup_list(&root, setting_name, &list, &list_length, JAL_CFG_REQUIRED));
  restore_function(config_setting_get_member);
}

void test_list_missing_optional()
{
  config_setting_t *list = NULL;
  int list_length;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_null);
  assert_equals(JAL_CFG_SUCCESS, jal_config_lookup_list(&root, setting_name, &list, &list_length, JAL_CFG_OPTIONAL));
  restore_function(config_setting_get_member);
}

void test_list_bad_length_required()
{
  config_setting_t *list = NULL;
  int list_length;
  replace_function(&config_setting_get_member, &mock_config_setting_get_list_bad_length);
  assert_equals(JAL_CFG_FAILURE, jal_config_lookup_list(&root, setting_name, &list, &list_length, JAL_CFG_REQUIRED));
  assert_equals(NUM_LIST_ITEMS_BAD, list_length);
  restore_function(config_setting_get_member);
}

void test_list_bad_length_optional()
{
  config_setting_t *list = NULL;
  int list_length;
  replace_function(&config_setting_get_member, &mock_config_setting_get_list_bad_length);
  assert_equals(JAL_CFG_FAILURE, jal_config_lookup_list(&root, setting_name, &list, &list_length, JAL_CFG_OPTIONAL));
  assert_equals(NUM_LIST_ITEMS_BAD, list_length);
  restore_function(config_setting_get_member);
}

void test_list_wrong_type_required()
{
  config_setting_t *list = NULL;
  int list_length;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_string);
  assert_equals(JAL_CFG_FAILURE, jal_config_lookup_list(&root, setting_name, &list, &list_length, JAL_CFG_REQUIRED));
  restore_function(config_setting_get_member);
}

void test_list_wrong_type_optional()
{
  config_setting_t *list = NULL;
  int list_length;
  replace_function(&config_setting_get_member, &mock_config_setting_get_member_string);
  assert_equals(JAL_CFG_FAILURE, jal_config_lookup_list(&root, setting_name, &list, &list_length, JAL_CFG_OPTIONAL));
  restore_function(config_setting_get_member);
}

/*
 * For a group, do the following tests:
 *   - Verify that the return code is correct when a valid group is found
 *   - Verify that the return code is correct when a non-group is found
 */
void test_elem_group_good()
{
  config_setting_t *group = NULL;
  replace_function(&config_setting_get_elem, &mock_config_setting_get_elem_group);
  assert_equals(JAL_CFG_SUCCESS, jal_config_get_elem_group(&root, 0, &group, setting_name));
  restore_function(config_setting_get_elem);
}

void test_elem_group_wrong_type()
{
  config_setting_t *group = NULL;
  replace_function(&config_setting_get_elem, &mock_config_setting_get_elem_group_wrong_type);
  assert_equals(JAL_CFG_FAILURE, jal_config_get_elem_group(&root, 0, &group, setting_name));
  restore_function(config_setting_get_elem);
}

/*
 * For each of the types { int, string }, do the following tests:
 *   - Verify that the return value is correct when the element at the specified index
 *     of a group/list matches the expected type
 *   - Verify that the return value is correct when the element at the specified index
 *     of a group/list doesn't match the expected type
 *
 * For the string type only, do the following test:
 *   - Verify that an error is handled when the desired string is NULL
 */
void test_elem_string_good()
{
  char *config_val = DEFAULT_STR_VAL;
  replace_function(&config_setting_get_elem, &mock_config_setting_get_elem_string);
  replace_function(&config_setting_get_string, &mock_config_setting_get_string);
  assert_equals(JAL_CFG_SUCCESS, jal_config_get_elem_string(&root, 0, &config_val, setting_name));
  assert_string_equals(CHANGED_STR_VAL, config_val);
  restore_function(config_setting_get_elem);
  restore_function(config_setting_get_string);

  // Free memory malloc'd by strdup
  free(config_val);
}

void test_elem_string_wrong_type()
{
  char *config_val = DEFAULT_STR_VAL;
  replace_function(&config_setting_get_elem, &mock_config_setting_get_elem_string_wrong_type);
  assert_equals(JAL_CFG_FAILURE, jal_config_get_elem_string(&root, 0, &config_val, setting_name));
  assert_equals(DEFAULT_STR_VAL, config_val);
  restore_function(config_setting_get_elem);
}

void test_elem_string_missing()
{
  char *config_val = DEFAULT_STR_VAL;
  replace_function(&config_setting_get_elem, &mock_config_setting_get_elem_string);
  replace_function(&config_setting_get_string, &mock_config_setting_get_string_null);
  assert_equals(JAL_CFG_FAILURE, jal_config_get_elem_string(&root, 0, &config_val, setting_name));
  assert_equals(DEFAULT_STR_VAL, config_val);
  restore_function(config_setting_get_elem);
  restore_function(config_setting_get_string);
}

void test_elem_int_good()
{
  int config_val = DEFAULT_INT_VAL;
  replace_function(&config_setting_get_elem, &mock_config_setting_get_elem_int);
  replace_function(&config_setting_get_int, &mock_config_setting_get_int);
  assert_equals(JAL_CFG_SUCCESS, jal_config_get_elem_int(&root, 0, &config_val, setting_name));
  assert_equals(CHANGED_INT_VAL, config_val);
  restore_function(config_setting_get_elem);
  restore_function(config_setting_get_int);
}

void test_elem_int_wrong_type()
{
  int config_val = DEFAULT_INT_VAL;
  replace_function(&config_setting_get_elem, &mock_config_setting_get_elem_int_wrong_type);
  assert_equals(JAL_CFG_FAILURE, jal_config_get_elem_int(&root, 0, &config_val, setting_name));
  assert_equals(DEFAULT_INT_VAL, config_val);
  restore_function(config_setting_get_elem);
}