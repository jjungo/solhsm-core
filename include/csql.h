/*
 * Copyright 2016 Joël Jungo
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
/**
 * Library provides a small interface to interact with our sqlite3 database.
 * @file:     csql.h
 * @author:   Joel Jungo
 * @date:     Nov 25, 2014
 */

#pragma once
#ifndef CSQL
#define CSQL_H_

#include <stdint.h>

#define MAX_KEY_SIZE   4096 

/**
 * A callback function passed into get_key_*_from_id() is used to process each row of
 * the result set.
 * 
 * @param param Data provided in the 4th argument of sqlite3_exec() 
 * @param argc The number of columns in row 
 * @param argv An array of strings representing fields in the row 
 * @param azColName An array of strings representing column names 
 */
typedef int (*callback)(void *param, int argc, char **argv, char **azColName);

/**
 * Method to get private key from id.
 * 
 * @param id ID of the key
 * @param cb callback function to process data.
 * @return -1 if error, 0 if succeed
 */
int get_key_priv(uint16_t id, callback cb, void *data);
/**
 * Method to get public key from id.
 * 
 * @param id ID of the key
 * @param cb callback function to process data.
 * @return -1 if error, 0 if succeed
 */
int get_key_pub(uint16_t id, callback cb, void *data);
/**
 * Method to get dummy private key from id.
 * 
 * @param id ID of the key
 * @param cb callback function to process data.
 * @return -1 if error, 0 if succeed
 */
int get_key_dumm_priv(uint16_t id, callback cb, void *data);
/**
 * Method to get dummy public key from id.
 * 
 * @param id ID of the key
 * @param cb callback function to process data.
 * @return -1 if error, 0 if succeed
 */
int get_key_dumm_pub(uint16_t id, callback cb, void *data);
/**
 * Method to get the size of key from id.
 * 
 * @param id ID of the key
 * @param cb callback function to process data.
 * @return -1 if error, 0 if succeed
 */
int get_key_size_from_id(uint16_t id, callback cb, void *data);
#endif

