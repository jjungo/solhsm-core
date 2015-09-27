/* <@LICENSE>
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at:
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * </@LICENSE>
 */
/**
 * This small api provide a simple way to access to the database from main solHSM
 * core program, see csql.h for details.
 * 
 * @file:     csql.hc
 * @author:   Joel Jungo
 * @contributor: Titouan Mesot
 * @date:     April, 2015
 */
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h> 
#include <stdint.h>
#include <string.h>
#include <syslog.h>

#include "../include/csql.h"


#ifdef DEBUG
#define DEBUG 1
#else 
#define DEBUG 0
#endif

#define DBPATH "/data/db/key.db"

typedef int (*callback)(void *param, int argc, char **argv, char **azColName);

/**********************public method*********************************/

extern int get_key_priv_from_id(uint16_t id, callback cb, void *param){
    sqlite3 *db;
    char *zErrMsg = 0;
    int  rc;
    char *sql;
    /* Open database */    
    rc = sqlite3_open(DBPATH, &db);
    if( rc ){
        syslog(LOG_ERR, "Can't open database: %s", sqlite3_errmsg(db)); 
        exit(0);
    }else{
        if (DEBUG)
            syslog(LOG_DEBUG, "Opened database successfully");
    }

    char d[sizeof(uint16_t)];
    sprintf(d, "%d", id);
    /* Create SQL statement */
    sql = sqlite3_mprintf("SELECT key_priv from PRIVKEY\
                            where id=%q;", d);


    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, cb, param, &zErrMsg);

    if( rc != SQLITE_OK ){
        syslog(LOG_ERR, "SQL error: %s", zErrMsg);
        sqlite3_free(zErrMsg);
    }else{
        if (DEBUG)
            syslog(LOG_DEBUG, "Operation done successfully\n");
    }

    sqlite3_close(db);
    return 0;
}


extern int get_key_pub_from_id(uint16_t id, callback cb, void *param){
    sqlite3 *db;
    char *zErrMsg = 0;
    int  rc;
    char *sql;

    /* Open database */
    rc = sqlite3_open(DBPATH, &db);
    if( rc ){
        syslog(LOG_ERR, "Can't open database: %s", sqlite3_errmsg(db));
        exit(0);
    }else{
        if (DEBUG)
            syslog(LOG_DEBUG, "Opened database successfully");
    }

    char d[sizeof(uint16_t)];
    sprintf(d, "%d", id);
    
    /* Create SQL statement */
    sql = sqlite3_mprintf("SELECT key_pub from PRIVKEY\
                            where id=%q;", d);
                            
    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, cb, param, &zErrMsg);
    if( rc != SQLITE_OK ){
        syslog(LOG_ERR, "SQL error: %s", zErrMsg);
        sqlite3_free(zErrMsg);
    }else{
        if (DEBUG)
            syslog(LOG_DEBUG, "Operation done successfully");
    }
    sqlite3_close(db);
    return 0;
}


extern int get_key_dumm_priv_from_id(uint16_t id, callback cb, void *param){
    sqlite3 *db;
    char *zErrMsg = 0;
    int  rc;
    char *sql;

    /* Open database */
    rc = sqlite3_open(DBPATH, &db);
    if( rc ){
        syslog(LOG_ERR, "Can't open database: %s", sqlite3_errmsg(db));
        exit(0);
    }else{
        if (DEBUG)
            syslog(LOG_DEBUG, "Opened database successfully");
    }

    char d[sizeof(uint16_t)];
    sprintf(d, "%d", id);
       
    /* Create SQL statement */
    sql = sqlite3_mprintf("SELECT key_dumm_priv from PRIVKEY\
                            where id=%q;", d);

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, cb, param, &zErrMsg);
    if( rc != SQLITE_OK ){
        syslog(LOG_ERR, "SQL error: %s", zErrMsg);
        sqlite3_free(zErrMsg);
    }else{
        if (DEBUG)
            syslog(LOG_DEBUG, "Operation done successfully");
    }
    sqlite3_close(db);
    return 0;
}


extern int get_key_dumm_pub_from_id(uint16_t id, callback cb, void *param){
    sqlite3 *db;
    char *zErrMsg = 0;
    int  rc;
    char *sql;

    /* Open database */
    rc = sqlite3_open(DBPATH, &db);
    if( rc ){
        syslog(LOG_ERR, "Can't open database: %s", sqlite3_errmsg(db));
        exit(0);    
    }else{
        if (DEBUG)
            syslog(LOG_DEBUG, "Opened database successfully");
    }

    char d[sizeof(uint16_t)];
    sprintf(d, "%d", id);
    
    /* Create SQL statement */
    sql = sqlite3_mprintf("SELECT key_dumm_pub from PRIVKEY\
                            where id=%q;", d);

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, cb, param, &zErrMsg);
    if( rc != SQLITE_OK ){
        syslog(LOG_ERR, "SQL error: %s", zErrMsg);
        sqlite3_free(zErrMsg);
    }else{
        if (DEBUG)
            syslog(LOG_DEBUG, "Operation done successfully");
    }
    sqlite3_close(db);
    return 0;
}


extern int get_key_size_from_id(uint16_t id, callback cb, void *param){
    sqlite3 *db;
    char *zErrMsg = 0;
    int  rc;
    char *sql;

    /* Open database */
    rc = sqlite3_open(DBPATH, &db);
    if( rc ){
        syslog(LOG_ERR, "Can't open database: %s\n", sqlite3_errmsg(db));
        exit(0);
    }else{
        if (DEBUG)
            syslog(LOG_DEBUG, "Opened database successfully\n");
    }

    char d[sizeof(uint16_t)];
    sprintf(d, "%d", id);
    
    /* Create SQL statement */
    sql = sqlite3_mprintf("SELECT len from PRIVKEY\
                            where id=%q;", d);

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, cb, param, &zErrMsg);
    if( rc != SQLITE_OK ){
        syslog(LOG_ERR, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
    }else{
        if (DEBUG)
            syslog(LOG_DEBUG, "Operation done successfully\n");
    }
    sqlite3_close(db);
    return 0;
}
