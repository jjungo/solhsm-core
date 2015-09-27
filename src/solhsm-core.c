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
 * Main program for solhsmCore.
 * @detail This program contains the main loop and process the reception of a 
 * cryptographic command provide by a client. In program implements RSA STANDARD
 * operation, like pub_dec, pub_enc, priv_dec, priv_enc. It implements also RSA
 * KEY. You can run this program in debug mod by activating the CFLAGS DEBUG
 * when you compile and build it (see Makefile).
 * @file:     solHSM-Core.c
 * @author:   Joel Jungo
 * @contributor: Titouan Mesot
 * @date:     Dec-Janv, 2014
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/engine.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <czmq.h>
#include <syslog.h>
#include <pthread.h>
#include <signal.h>
#include "../include/solhsm-network.h"
#include "../include/csql.h"

#define RSA_KEY_ERROR_TYPE      0
#define RSA_KEY_ERROR_FORMAT    1
#define RSA_KEY_ERROR_KEY       2


#define RSA_STD_ERROR_DEC       0
#define RSA_STD_ERROR_ENC       1
#define RSA_STD_ERROR_KEY       3


/* if CFLAGS DEBUG if activate */
#ifdef DEBUG
#define DEBUG 1
#else 
#define DEBUG 0
#endif

/*********************************GOBAL VARIABLES******************************/
static solhsm_network_frame_container *container;
static zctx_t *ctx;
static zauth_t *auth;
static zcert_t *server_cert ;
static void *server_sock;
/******************************************************************************/


/*********************************PRIVATE METHODS******************************/
/*++++++++++++++++++++++++++++++++rsa std+++++++++++++++++++++++++++++++++++++*/
/**
 * Method to encrypt with private key
 *
 * @param rsa_rcv is a rsa std payload
 * @param key is the private key to use for encryption
 * @param payload is the result of processing
 * @param size is the effective size of the payload encrypted
 * @return -1 if error, 0 if succeed
 */
static int priv_enc(solhsm_rsa_std_payload* rsa_rcv, void *key,
                                uint8_t *payload, uint16_t *size);
/**
 * Method to decrypt with private key
 *
 * @param rsa_rcv is a rsa std payload
 * @param key is the private key to use for decryption
 * @param payload is the result of processing
 * @param size is the effective size of the payload decrypted
 * @return -1 if error, 0 if succeed
 */
static int priv_dec(solhsm_rsa_std_payload* rsa_rcv, void *key,
                                uint8_t *payload, uint16_t *size);
/**
 * Method to encrypt with public key
 *
 * @param rsa_rcv is a rsa std payload
 * @param key is the public key to use for encryption
 * @param payload is the result of processing
 * @param size is the effective size of the payload encrypted
 * @return -1 if error, 0 if succeed
 */
static int pub_enc(solhsm_rsa_std_payload* rsa_rcv, void *key,
                                uint8_t *payload, uint16_t *size);
/**
 * Method to decrypt with public key
 *
 * @param rsa_rcv is a rsa std payload
 * @param key is the public key to use for decryption
 * @param payload is the result of processing
 * @param size is the effective size of the payload decrypted
 * @return -1 if error, 0 if succeed
 */
static int pub_dec(solhsm_rsa_std_payload* rsa_rcv, void *key,
                                uint8_t *payload, uint16_t *size);
/**
 * Method to load private key.
 *
 * @param key represent the payload that contains the key
 * @return a pointer on a RSA structure, NULL if an error occcured
 */
static RSA* load_priv_key(void* key);
/**
 * Method to load public key.
 *
 * @param key represent the payload that contains the key
 * @return a pointer on a RSA structure, NULL if an error occcured
 */
static RSA* load_pub_key(void* key);
/**
 * Method to handle errors in RSA STANDARD layer processing.
 * @detail This method will push a LOG_ERR into syslog and send the same message
 *  to the client.
 *
 * @param err_code is a defined error code
 * @param rsa_rcv is the RSA STANDARD payload
 * @param c_r is the network frame containter 
 * @param socket_zmq is the zqm socket
 */
static void rsa_std_error(uint8_t err_code, solhsm_rsa_std_payload *rsa_rcv,
                                solhsm_network_frame_container *c_r, 
                                void*socket_zmq);
                    
                    
/*++++++++++++++++++++++++++++++++rsa key+++++++++++++++++++++++++++++++++++++*/
/**
 * Method to handle errors in RSA KEY layer processing.
 * @detail This method will push a LOG_ERR into syslog and send the same message
 *  to the client.
 *
 * @param err_code is a defined error code
 * @param rsa_rcv is the RSA STANDARD payload
 * @param c_r is the network frame containter 
 * @param socket_zmq is the zqm socket
 */
static void rsa_key_error(uint8_t err_code, 
                                solhsm_rsa_key_payload *rsa_rcv,
                                solhsm_network_frame_container *c_r, 
                                void*socket_zmq);
                    
/*++++++++++++++++++++++++++++++++others+++++++++++++++++++++++++++++++++++++*/
/**
 * Method to receive and process a container.
 *
 * @param socket_zmq is a zmq socket
 * @param c_r is the network frame container
 * @return -1 if error, 0 if succeed
 */
static int sol_recv(void* socket_zmq, solhsm_network_frame_container *c_r);

/**
 * Callback method to get the key (see csql.h file).
 *
 * @param data is the output payload the represents the key
 * @param argc The number of columns in row 
 * @param argv An array of strings representing fields in the row 
 * @param azColName An array of strings representing column names 
 */
static int get_key(void *data, int argc, char **argv, char **azColName);

/**
 * Callback method to get the size of the key (see csql.h file).
 *
 * @param data is the output payload the represents the key
 * @param argc The number of columns in row 
 * @param argv An array of strings representing fields in the row 
 * @param azColName An array of strings representing column names 
 */
static int get_key_size(void *size, int argc, char **argv, char **azColName);

/**
 * Method to catch the signal when the program has stopped.
 * @detail This method is a callback method that we provide to createCatchSignal,
 * this is very useful to destroy contextes and clean propely the memory.
 *
 * @param signal is the id of the signal catched
 */
static void   catchSignal      (int signal);
/**
 * Method to create a way to catch signal.
 * @detail In this method, you should attach a callback function that define 
 * operations when the program has terminated .
 */
static void   createCatchSignal(void);
/******************************************************************************/


static void createCatchSignal(void){
    struct sigaction act;
    act.sa_handler = catchSignal;
    sigemptyset (&act.sa_mask);
    act.sa_flags   = 0;
    sigaction (SIGINT,  &act, 0);
    sigaction (SIGTSTP, &act, 0);
    sigaction (SIGTERM, &act, 0);
    sigaction (SIGABRT, &act, 0);
}


static void catchSignal (int signal){
    syslog(LOG_WARNING, "solHSM Core has stopped"); 
    syslog(LOG_WARNING, "program has been stopped, signal = %d", signal);
    zcert_destroy (&server_cert);
    zauth_destroy (&auth);
    zsocket_destroy(ctx, server_sock);
    zctx_destroy (&ctx);
    free(container);    
    closelog();
    pthread_exit (NULL);
}


int get_key(void *data, int argc, char **argv, char **azColName){  
    (void) argc; (void) azColName; /*Avoiding warning compilation*/

    size_t len  = strlen(argv[0]);
    memcpy((uint8_t *)data, argv[0], len);
    return 0;
}


int get_key_size(void *size, int argc, char **argv, char **azColName){            
    (void) argc; (void) azColName; /*Avoiding warning compilation*/

    memcpy((uint16_t*)size, argv[0], sizeof(uint16_t));
    return 0;
}


RSA* load_priv_key( void* key ){
    BIO *bio = BIO_new_mem_buf( (void*)key, -1 );
    RSA* rsa_priv_key = PEM_read_bio_RSAPrivateKey( bio, NULL, NULL, NULL ) ;

    if (!rsa_priv_key)
        syslog(LOG_ERR, "ERROR: Could not load PRIVATE KEY! \
                 PEM_read_bio_RSAPrivateKey FAILED");

    BIO_free( bio );
    return rsa_priv_key;
}


RSA* load_pub_key( void* key ){
    BIO *bio = BIO_new_mem_buf( (void*)key, -1 );
    RSA* rsa_pub_key = PEM_read_bio_RSA_PUBKEY( bio, NULL, NULL, NULL ) ;

    if (!rsa_pub_key)
        syslog(LOG_ERR, "ERROR: Could not load PUBLIC KEY! \
                 PEM_read_bio_RSAPublicKey FAILED");

    BIO_free( bio );
    return rsa_pub_key;
}


int priv_enc(solhsm_rsa_std_payload* rsa_rcv, void *key, uint8_t *payload, 
                uint16_t *size){
    const RSA_METHOD *meth_rsa = RSA_PKCS1_SSLeay();
    int status = 0;    
    RSA* priv_key = load_priv_key(key);
    unsigned char cipher[RSA_size(priv_key)];
    memset(cipher, 0, sizeof(cipher));
    int crypted_length = meth_rsa->rsa_priv_enc(
                        rsa_rcv->data_length,        
                        rsa_rcv->data,
                        cipher,
                        priv_key ,
                        rsa_rcv->padding);
    if (DEBUG)
        syslog(LOG_DEBUG, "crypted Length =%d",crypted_length);
    if(crypted_length == -1)    {
        syslog(LOG_ERR, "ERROR: crypt failed");
        status = -1;
    }
    else{
        memcpy(payload, cipher, crypted_length);
        *size = crypted_length;
    }
    return status;
}



int priv_dec(solhsm_rsa_std_payload* rsa_rcv, void *key, uint8_t *payload, 
                uint16_t *size){
    const RSA_METHOD *meth_rsa = RSA_PKCS1_SSLeay();
    int status = 0;    
    RSA* priv_key = load_priv_key(key);

    unsigned char plain[RSA_size(priv_key)];
    memset(plain, 0, sizeof(plain));
    int decrypted_length = meth_rsa->rsa_priv_dec(
                        rsa_rcv->data_length,        
                        rsa_rcv->data,
                        plain,
                        priv_key ,
                        rsa_rcv->padding);
    if (DEBUG)
        syslog(LOG_DEBUG, "decrypted Length =%d",decrypted_length);
    if(decrypted_length == -1)    {
        syslog(LOG_ERR, "ERROR: decryption failed ");
        status = -1;
    }
    else{
        if (DEBUG)
            syslog(LOG_DEBUG, "plain: %s", plain);
    }
    memcpy(payload, plain, decrypted_length);
    *size = decrypted_length;
    
    return status;
}


int pub_enc(solhsm_rsa_std_payload* rsa_rcv, void *key, uint8_t *payload, 
                uint16_t *size){
    const RSA_METHOD *meth_rsa = RSA_PKCS1_SSLeay();
    int status = 0;
    RSA* pub_key = load_pub_key(key);

    unsigned char cipher[RSA_size(pub_key)];
    memset(cipher, 0, sizeof(cipher));
    int crypted_length = meth_rsa->rsa_pub_enc(
                        rsa_rcv->data_length,        
                        rsa_rcv->data,
                        cipher,
                        pub_key ,
                        rsa_rcv->padding);
    if (DEBUG)
        syslog(LOG_DEBUG, "crypted Length =%d",crypted_length);
    if(crypted_length == -1)    {
        syslog(LOG_ERR, "ERROR: crypt failed");
        status = -1;
    }
    else{
        memcpy(payload, cipher, sizeof(cipher));
        *size = sizeof(cipher);
    }
    
    return status;
}


int pub_dec(solhsm_rsa_std_payload* rsa_rcv, void *key, uint8_t *payload, 
                uint16_t *size){

    const RSA_METHOD *meth_rsa = RSA_PKCS1_SSLeay();
    int status = 0;
    RSA* pub_key = load_pub_key(key);


    unsigned char plain[RSA_size(pub_key)];
//    unsigned char plain[1024];
    memset(plain, 0, sizeof(plain));
    int decrypted_length = meth_rsa->rsa_pub_dec(
                        rsa_rcv->data_length,        
                        (const unsigned char *)rsa_rcv->data,
                        plain,
                        pub_key,
                        rsa_rcv->padding);
    if (DEBUG)
        syslog(LOG_DEBUG, "decrypted Length =%d",decrypted_length);
    if(decrypted_length == -1)    {
        syslog(LOG_ERR, "ERROR: decryption failed ");
        status = -1;
    }
    else{
        memcpy(payload, plain, decrypted_length );
        *size = decrypted_length ;
    }
    
    return status;
}


void rsa_key_error(uint8_t err_code, solhsm_rsa_key_payload *rsa_rcv,
                    solhsm_network_frame_container *c_r, void*socket_zmq){
    /*Each errors are pushed into syslog as LOG_ERR and we send the same message
        to the client*/
    char *msg[3]={ "Invalid key type", 
                            "Format unknown", 
                            "Key not found, id missmatch"};
    uint16_t len=0;
    uint8_t id_err=0;

    if (err_code == RSA_KEY_ERROR_TYPE){
        syslog(LOG_ERR, "Invalid key type: (%d)", rsa_rcv->key_type);
        id_err = 0;
        len = strlen(msg[id_err]);
    }
    else if (err_code == RSA_KEY_ERROR_FORMAT){
        syslog(LOG_ERR, "Format unknown: (format: %d)", rsa_rcv->key_format);
        id_err = 1;
        len = strlen(msg[id_err]);
    }
    else if (err_code == RSA_KEY_ERROR_KEY){
        syslog(LOG_ERR, "Key not found, id missmatch?: (id: %d)", rsa_rcv->key_id);
        id_err = 2; 
        len = strlen(msg[id_err]);
    }
    solhsm_rsa_key_payload* rsa_snd = solhsm_forge_rsa_key_payload(
                            len, 
                            rsa_rcv->key_id,
                            RSA_KEY_ERROR,
                            rsa_rcv->key_format,
                            (unsigned char*)msg[id_err]);  
                                        
    syslog(LOG_ERR, "Send error code: %d", err_code);
    solhsm_network_frame_container* c_snd = solhsm_forge_container(
                                        c_r->version, 
                                        c_r->payload_type, 
                                        solhsm_get_rsa_key_payload_size(rsa_snd));

    solhsm_network_send(socket_zmq, c_snd, rsa_snd);    

}

void rsa_std_error(uint8_t err_code, solhsm_rsa_std_payload *rsa_rcv,
                    solhsm_network_frame_container *c_r, void*socket_zmq){
    /*Each errors are pushed into syslog as LOG_ERR and we send the same message
        to the client*/
    char *msg[3]={  "Decryption has failed in subsystem", 
                    "Encryption has failed in subsystem", 
                    "Key not found, id missmatch"};
    uint16_t len=0;
    uint8_t id_err=0;
 
    if (err_code == RSA_STD_ERROR_DEC){
        syslog(LOG_ERR, "Decryption with private key's id %d has failed",
                                        rsa_rcv->key_id);
        id_err = 0;
        len = strlen(msg[id_err]);
    
    }
    else if (err_code == RSA_STD_ERROR_ENC){
        syslog(LOG_ERR, "Encryption with private key's id %d has failed",
                                        rsa_rcv->key_id);
        id_err = 1;
        len = strlen(msg[id_err]);                                        
    }
    else if (err_code == RSA_STD_ERROR_KEY){
        syslog(LOG_ERR, "Key not found, id missmatch?: (id: %d)",
                                        rsa_rcv->key_id);
        id_err = 2;
        len = strlen(msg[id_err]);                                        
    }

    solhsm_rsa_std_payload* rsa_snd = solhsm_forge_rsa_std_payload(
                            len, 
                            rsa_rcv->key_id,
                            rsa_rcv->padding,
                            RSA_STD_ERROR,
                            (unsigned char*)msg[id_err]);  
                                        
    syslog(LOG_ERR, "Send error code: %d", err_code);
    solhsm_network_frame_container* c_snd = solhsm_forge_container(
                                        c_r->version, 
                                        c_r->payload_type, 
                                        solhsm_get_rsa_std_payload_size(rsa_snd));

    solhsm_network_send(socket_zmq, c_snd, rsa_snd);    
}


int sol_recv(void* socket_zmq, solhsm_network_frame_container *c_r ){
    int status = 0;
    uint8_t *data = malloc(4096);
    char *key = malloc(MAX_KEY_SIZE);
    memset(&key[0], 0, MAX_KEY_SIZE);

    uint16_t size=0;

    void* ptr_recv = solhsm_network_receive(socket_zmq, c_r);

    if(DEBUG) {
        syslog(LOG_DEBUG, "Frame received");
        syslog(LOG_DEBUG, "Now check what we receive");
        syslog(LOG_DEBUG, "Check container payload size : %i byte", 
                                                        c_r->payload_size);
        syslog(LOG_DEBUG, "Check container payload type : %i", c_r->payload_type);
        syslog(LOG_DEBUG, "Check container payload version : %i", c_r->version);
    }

    /* RSA STANDARD operations */
    if(c_r->payload_type == RSA_STD){        
	    solhsm_rsa_std_payload *rsa_rcv = (solhsm_rsa_std_payload *)ptr_recv;
        if (DEBUG){
            char *op_txt[5] = {     "RSA_ERROR", "RSA_PRIV_ENC",
                                    "RSA_PRIV_DEC","RSA_PUB_ENC",
                                    "RSA_PUB_DEC"};
            syslog(LOG_DEBUG, "RSA_STD received");
	        syslog(LOG_DEBUG, "Check rsa_rec data len : %i", 
	                                               rsa_rcv->data_length);
	        syslog(LOG_DEBUG, "Check rsa_rec keyid : %i",
	                                               rsa_rcv->key_id);
	        syslog(LOG_DEBUG, "Check rsa_rec padding : %i",
	                                               rsa_rcv->padding);
	        syslog(LOG_DEBUG, "Check rsa_rec operation : %s",
	                                               op_txt[rsa_rcv->operation]);
	        
	        syslog(LOG_DEBUG, "Check rsa_rec data : ");
	        int i = 0;
	        char *st= malloc((rsa_rcv->data_length)*6+1);
	        char *p = st;        
	        for(i = 0; i<rsa_rcv->data_length; i++){
		        p += sprintf(p, " 0x%02x", rsa_rcv->data[i]); 
	        }
	        *(p+1) = '\0';
	        syslog(LOG_DEBUG, "%s", st);
	        free(st);
	    }
	    
	    switch (rsa_rcv->operation){
	        /* For an operation, we load the key, process cryptography and send 
	            the response to the client, if an error occurs, we handle it and
	            push it to syslog */
	        case RSA_PRIV_ENC:            
	            status = get_key_priv_from_id(rsa_rcv->key_id, get_key, key);
	            if (strlen(key) == 0){
                    rsa_std_error(RSA_STD_ERROR_KEY, rsa_rcv, c_r, socket_zmq); 
	                return 0;
	            }	  

	            else{           
                    status = priv_enc(rsa_rcv, key, data, &size);
                    if (status != -1){
                        syslog(LOG_INFO, "Encryption with private key's id %d has succeed",
                                                            rsa_rcv->key_id);
                    }
                    else{                           
                        rsa_std_error(RSA_STD_ERROR_ENC, rsa_rcv, c_r, socket_zmq); 
                        return 0;
                    }
                }
	        break;
	        
	        case RSA_PRIV_DEC:
	            status = get_key_priv_from_id(rsa_rcv->key_id, get_key, key);
	            if (strlen(key) == 0){
                    rsa_std_error(RSA_STD_ERROR_KEY, rsa_rcv, c_r, socket_zmq); 
                    return 0;
	            }	            
	            else{           
                    status = priv_dec(rsa_rcv, key, data, &size);
                    if (status != -1)
                        syslog(LOG_INFO, "Decryption with private key's id %d has succeed",
                                                            rsa_rcv->key_id);
                    else{  
                        rsa_std_error(RSA_STD_ERROR_DEC, rsa_rcv, c_r, socket_zmq); 
                        return 0;
                    }
                                        
                }
	        break;
	        
	        case RSA_PUB_ENC:
	            status = get_key_pub_from_id(rsa_rcv->key_id, get_key, key);

	            if (strlen(key) == 0){
                    rsa_std_error(RSA_STD_ERROR_KEY, rsa_rcv, c_r, socket_zmq);	                
	                return 0;
	            }	            
	            else{
                    status = pub_enc(rsa_rcv, key, data, &size);  
                    if (status != -1)
                        syslog(LOG_INFO, "Encryption with public key's id %d has succeed",
                                                            rsa_rcv->key_id);
                    else{ 
                        rsa_std_error(RSA_STD_ERROR_ENC, rsa_rcv, c_r, socket_zmq); 
                        return 0;  
                    }    
                }
    	        break;	        
	
	        case RSA_PUB_DEC:
	            status = get_key_pub_from_id(rsa_rcv->key_id, get_key, key);
	            if (strlen(key) == 0){
                    rsa_std_error(RSA_STD_ERROR_KEY, rsa_rcv, c_r, socket_zmq);	                
	                return 0;
	            }   
	            else{
                    status = pub_dec(rsa_rcv, key, data, &size); 
                    if (status != -1)
                        syslog(LOG_INFO, "Decryption with public key's id %d has succeed",
                                                                rsa_rcv->key_id);
                    else{
                        rsa_std_error(RSA_STD_ERROR_DEC, rsa_rcv, c_r, socket_zmq); 
                        return 0;                                        
                    }
                }
	            break;
	        
	        default:
	            status = -1;
	        
	    }                  
	    if (DEBUG){
	        syslog(LOG_DEBUG, "End of RSA STD operation");
            syslog(LOG_DEBUG,"size: %d", size);       
            
            syslog(LOG_DEBUG, "Result of operation:");
            int i = 0;
	        char *st= malloc(size*5+1);
	        char *p = st;        
	        for(i = 0; i<size; i++){
		        p += sprintf(p, " 0x%02x", data[i]); 
	        }
	        *(p+1) = '\0';
	        syslog(LOG_DEBUG, "%s", st);
	        free(st);	        
	        
	        syslog(LOG_DEBUG, "Trying to send response to the client...");
	    }
	    /* Forge RSA STANDARD layer */
        solhsm_rsa_std_payload* rsa_snd = solhsm_forge_rsa_std_payload(
                                                    size, 
                                                    rsa_rcv->key_id,
                                                    rsa_rcv->padding,
                                                    rsa_rcv->operation,
                                                    data); 

        /* Forge the container */                                                  
        solhsm_network_frame_container* c_snd = solhsm_forge_container(
                                    c_r->version, 
                                    c_r->payload_type, 
                                    solhsm_get_rsa_std_payload_size(rsa_snd));
     
        /* Send the container */
        solhsm_network_send(socket_zmq, c_snd, rsa_snd);
        if (DEBUG)
            syslog(LOG_DEBUG, "Successful send");       

    }

    /*RSA KEY operations*/
    else if(c_r->payload_type == RSA_KEY){  
        if (DEBUG)
            syslog(LOG_DEBUG, "RSA_KEY received");
        
        solhsm_rsa_key_payload *rsa_rcv = (solhsm_rsa_key_payload *)ptr_recv;
        
        if(DEBUG){
	        syslog(LOG_DEBUG,"Check rsa_key data size : %i ", rsa_rcv->key_data_size);
	        syslog(LOG_DEBUG,"Check rsa_key keyid : %i",rsa_rcv->key_id);
	        syslog(LOG_DEBUG,"Check rsa_key key_type : %i",rsa_rcv->key_type);
	        syslog(LOG_DEBUG,"Check rsa_key key_format : %i",rsa_rcv->key_format);
	    }
	    /* We check all parameters provide by client */
	    if (rsa_rcv->key_type == RSA_KEY_PUB)
	    	get_key_dumm_pub_from_id(rsa_rcv->key_id, get_key, key);
	    
	    else if (rsa_rcv->key_type == RSA_KEY_DUMMY_PRIV){
	        get_key_dumm_priv_from_id(rsa_rcv->key_id, get_key, key);
	    }
	    else{
	        rsa_key_error(RSA_KEY_ERROR_TYPE, rsa_rcv, c_r, socket_zmq); 
	    }
	    if (status != -1){
	        if (rsa_rcv->key_format != RSA_KEY_PEM){
                rsa_key_error(RSA_KEY_ERROR_FORMAT, rsa_rcv, c_r, socket_zmq);
	        }
	            
            if (strlen(key) == 0){
                // wrong id
                rsa_key_error(RSA_KEY_ERROR_KEY, rsa_rcv, c_r, socket_zmq);        
            }
            else{ 
                /* IF everything is fine, we get key from database */                 
                status = get_key_size_from_id(rsa_rcv->key_id, 
                                                get_key_size,
                                                &(rsa_rcv->key_data_size));
            }
            if (status != -1){
                if(DEBUG)
                    syslog(LOG_DEBUG, "Trying to send response to the client...");
                /* Forge RSA KEY layer */
                solhsm_rsa_key_payload* rsa_snd = solhsm_forge_rsa_key_payload(
                                strlen(key),//rsa_rcv->key_data_size, 
                                rsa_rcv->key_id,
                                rsa_rcv->key_type,
                                rsa_rcv->key_format,
                                (unsigned char*)key);                              
                /* Forge container */
                solhsm_network_frame_container* c_snd = solhsm_forge_container(
                                        c_r->version, 
                                        c_r->payload_type, 
                                        solhsm_get_rsa_key_payload_size(rsa_snd));
                /* Send the container to the client */
                solhsm_network_send(socket_zmq, c_snd, rsa_snd);
                if (DEBUG)
                    syslog(LOG_DEBUG, "Successful send");
            }
        }
        
    }
    else
        status = -1;
    	    
    free(key);
    free(data);
    return status;
}


/*********************************main loop************************************/
int main(){

    /*private certificate for czmq communication*/
    char *server_cert_file = "/etc/hsm/server/server.cert_secret";
    
    /* publics certificate are stored in this following directory */
    char *client_cert_path = "/etc/hsm/server/pub_key";
    
    int status =0;
    void * payload = malloc(MAX_KEY_SIZE);

    createCatchSignal ();
    openlog("HSM Core", LOG_PID, LOG_LOCAL0); 
    syslog(LOG_WARNING, "solHSM Core is started"); 
    
    ctx = zctx_new ();
    zauth_t *auth = zauth_new (ctx);
    if (auth == NULL){
        syslog(LOG_ERR, "zauth new has failed");
        return -1;
    }
    
    /* Tell the authenticator how to handle CURVE requests */
    zauth_configure_curve (auth, "*", client_cert_path);

    if (DEBUG)
        syslog(LOG_DEBUG, "DEBUG mode acivated");

    /* Create and bind server socket */
    server_sock = zsocket_new (ctx, ZMQ_REP);
    if (server_sock  == NULL){
        syslog(LOG_ERR, "zsocket new has failed");
        return -1;
    }
    zcert_t *server_cert = zcert_load (server_cert_file);
    if (server_cert  == NULL){
        syslog(LOG_ERR, "zcert load has failed");
        return -1;        
    }    
    zcert_apply (server_cert, server_sock);
    zsocket_set_curve_server (server_sock, true);
    int rc = zsocket_bind (server_sock, "tcp://*:9222");
    if (rc != 9222){
        syslog(LOG_ERR, "bind has failed");
        return -1;    
    }

    /* This is main loop in order to receive all requests from users */
    /* Normally, the program will never stop except if a MAJOR error occurs or
        if the process is volontary stopped*/
    while (status != -1){
        //prepare reception
        container = malloc(sizeof(solhsm_network_frame_container));
        //receive frame
        status = sol_recv(server_sock, container);                
    }
    
    //free the memory
    zctx_destroy (&ctx);
    syslog(LOG_WARNING, "solHSM Core has stopped"); 
    closelog();
    
    free(payload);
    zcert_destroy (&server_cert);
    zauth_destroy (&auth);
    zctx_destroy (&ctx);

    return -1; 
}
