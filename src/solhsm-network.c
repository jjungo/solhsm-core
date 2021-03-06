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
 * This small api provide a simple way to send and receive data,
 * on the HSM through zmq context see solhsm_network.h for details.
 *
 * @file:     solhsm_network.c
 * @author:   Titouan Mesot
 * @contributor: Joel Jungo
 * @date:     Dec, 30 2014
 */

#include "../include/solhsm-network.h"

int net_send(void* socket, net_frame_container* container, void* payload)
{
    int res = -1;
    /*Check if the payload to send is rsa_std */
    if(container->payload_type == RSA_STD) {
        /*create struct to send*/
        rsa_std_payload_st *payload_to_send = malloc(container->payload_size);
        net_frame_container *container_to_send = malloc(sizeof(net_frame_container));
        /*cast the payload to rsa_std	*/
        rsa_std_payload_st *source = (rsa_std_payload_st*)payload;
        /*convert to be endianess*/
        container_to_send->version = container->version;
        container_to_send->payload_type = container->payload_type;
        container_to_send->payload_size = htons(container->payload_size);

        payload_to_send->data_length = htons(source->data_length);
        payload_to_send->key_id = htons(source->key_id);
        payload_to_send->padding = source->padding;
        payload_to_send->operation = source->operation;

        /*Create data pointer of the payload, could maybe be optimized */
        payload_to_send->data = malloc(source->data_length);
        memcpy(payload_to_send->data,source->data, source->data_length);

        /*Create the frame*/
        byte *frame = malloc(sizeof(net_frame_container)
                            + container->payload_size);
        /*copy the container*/
        memcpy(&frame[0], container_to_send, sizeof(net_frame_container));
        /*
         * copy the payload struct without data pointer (we remove the size of
         * a void* to be multiplatfome)
         */
        memcpy(&frame[sizeof(net_frame_container)], payload_to_send,
                    sizeof(rsa_std_payload_st)-(sizeof(void*)));
        /* copy the payload data at the end*/
        memcpy(&frame[sizeof(net_frame_container)
                    +(sizeof(rsa_std_payload_st)-(sizeof(void*)))],
                    payload_to_send->data,
                    source->data_length);

        /*create message*/
        zmsg_t *zmsg = zmsg_new();
        /*add our frame to the message*/
        res = zmsg_addmem (zmsg, frame,
                        (sizeof(net_frame_container) + container->payload_size));
        res = zmsg_send(&zmsg, socket);
        free(container);
        free(payload);
        free(payload_to_send->data);
        free(payload_to_send);
        free(container_to_send);
        free(frame);
    } else if(container->payload_type == RSA_KEY) {
        /*create struct to send*/
        rsa_key_payload_st *payload_to_send = malloc(container->payload_size);
        net_frame_container *container_to_send = malloc(sizeof(rsa_key_payload_st));
        /*cast the payload to rsa_std*/
        rsa_key_payload_st *source = (rsa_key_payload_st*)payload;
        /*convert to be endianess*/
        container_to_send->version = container->version;
        container_to_send->payload_type = container->payload_type;
        container_to_send->payload_size = htons(container->payload_size);

        payload_to_send->key_data_size = htons(source->key_data_size);
        payload_to_send->key_id = htons(source->key_id);
        payload_to_send->key_type = source->key_type;
        payload_to_send->key_format = source->key_format;

        /*Create data pointer of the payload, could maybe be optimized*/
        payload_to_send->key_data = malloc(source->key_data_size);
        memcpy(payload_to_send->key_data,source->key_data, source->key_data_size);

        /*Create the frame*/
        byte *frame = malloc(sizeof(net_frame_container) + container->payload_size);
        /* copy the container*/
        memcpy(&frame[0], container_to_send, sizeof(net_frame_container));
        /*
         * copy the payload struct without data pointer (we remove the size of
         * a void* to be multiplatfome)
         */
        memcpy(&frame[sizeof(net_frame_container)], payload_to_send,
                sizeof(rsa_key_payload_st)-(sizeof(void*)));
        /* copy the payload data at the end*/
        memcpy(&frame[sizeof(net_frame_container)
                +(sizeof(rsa_key_payload_st)-(sizeof(void*)))],
                payload_to_send->key_data,
                source->key_data_size);

        /*create message*/
        zmsg_t *zmsg = zmsg_new();
        /*add our frame to the message*/
        res = zmsg_addmem (zmsg, frame,
                        (sizeof(net_frame_container) + container->payload_size));
        res = zmsg_send(&zmsg, socket);
        free(container);
        free(payload);
        free(payload_to_send->key_data);
        free(payload_to_send);
        free(container_to_send);
        free(frame);
    }
    return res;
}

void* net_receive(void* socket, net_frame_container* container)
{
    /*receive message*/
    zframe_t *frame_recv = zframe_recv(socket);
    /*get data*/
    byte *data = zframe_data(frame_recv);
    /*create reception container*/
    memcpy(container, data, sizeof(net_frame_container));
    /*order byte to be endianess*/
    container->payload_size = ntohs(container->payload_size);
    /*check payload type*/
    if(container->payload_type == RSA_STD) {
        rsa_std_payload_st *rsa_payload = malloc(container->payload_size);
        /*put header in stuct as raw without the data*/
        memcpy(rsa_payload,&data[sizeof(net_frame_container)],
                (sizeof(rsa_std_payload_st) - (sizeof(void*))));
        /*Shift them to the good endianess*/
        rsa_payload->key_id = ntohs(rsa_payload->key_id);
        rsa_payload->data_length = ntohs(rsa_payload->data_length);
        /*now add data*/
        rsa_payload->data = malloc(rsa_payload->data_length);
        memcpy(rsa_payload->data, &data[sizeof(net_frame_container)
                + (sizeof(rsa_std_payload_st) - (sizeof(void*)))],
                rsa_payload->data_length);
        /*free the memory*/
        zframe_destroy(&frame_recv);
        return rsa_payload;
    } else if(container->payload_type == RSA_KEY) {
        rsa_key_payload_st *rsa_key = malloc(container->payload_size);
        /*put header in stuct as raw without the data*/
        memcpy(rsa_key,&data[sizeof(net_frame_container)], (
                    sizeof(rsa_key_payload_st) - (sizeof(void*))));
        /*Shift them to the good endianess  */
        rsa_key->key_id = ntohs(rsa_key->key_id);
        rsa_key->key_data_size = ntohs(rsa_key->key_data_size);
        /*now add data*/
        rsa_key->key_data = malloc(rsa_key->key_data_size);
        memcpy(rsa_key->key_data, &data[sizeof(net_frame_container)
                + (sizeof(rsa_key_payload_st)-(sizeof(void*)))],
                rsa_key->key_data_size);
        /*free the memory*/
        zframe_destroy(&frame_recv);
        return rsa_key;
    }
    return NULL;
}

/*Forger for rsa_std*/
rsa_std_payload_st* create_rsa_std_payload(int data_length, int key_id,
                                            int padding, int operation,
                                            unsigned char *data)
{
    rsa_std_payload_st *rsa_std = malloc(sizeof(rsa_std_payload_st)
                                        + sizeof(data_length));
    rsa_std->data_length = data_length;
    rsa_std->key_id = key_id;
    rsa_std->padding = padding;
    rsa_std->operation = operation;
    rsa_std->data = data;
    return rsa_std;
}

/*Forge rsa_key_payload*/
extern rsa_key_payload_st* create_rsa_key_payload(int key_data_size,
                                                    int key_id, int key_type,
                                                    int key_format,
                                                    unsigned char *key_data)
{
    rsa_key_payload_st *rsa_key = malloc(sizeof(rsa_key_payload_st)
                                            + sizeof(key_data_size));
    rsa_key->key_data_size = key_data_size;
    rsa_key->key_id = key_id;
    rsa_key->key_type = key_type;
    rsa_key->key_format = key_format;
    rsa_key->key_data = key_data;
    return rsa_key;
}

/*Forger for container*/
net_frame_container* create_container(int version, int payload_type,
                                        int payload_size)
{
    net_frame_container *container =  malloc(sizeof(net_frame_container));
    container->version = version;
    container->payload_type = payload_type;
    container->payload_size = payload_size;
    return container;
}

/*get rsa_payload size*/
int get_rsa_std_payload_size(rsa_std_payload_st* rsa_std_payload)
{
    return ((sizeof(rsa_std_payload_st) - sizeof(void*))
            + rsa_std_payload->data_length);
}

/*get rsa_key size*/
int get_rsa_key_payload_size(rsa_key_payload_st* rsa_key_payload)
{
    return ((sizeof(rsa_key_payload_st) - sizeof(void*))
            + rsa_key_payload->key_data_size);
}
