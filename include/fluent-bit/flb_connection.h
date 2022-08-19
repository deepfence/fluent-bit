/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef FLB_CONNECTION_H
#define FLB_CONNECTION_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_socket.h>
#include <fluent-bit/flb_config.h>

#define FLB_UNKNOWN_CONNECTION    0
#define FLB_UPSTREAM_CONNECTION   1
#define FLB_DOWNSTREAM_CONNECTION 2

#define FLB_MAX_IPV6_ADDRESS_LENGTH 40

struct flb_net_setup;
struct flb_upstream;
struct flb_downstream;
struct flb_tls_session;

/* Base network connection */
struct flb_connection {
    struct mk_event event;

    void *user_data;

    /* Socket */
    flb_sockfd_t fd;

    int raw_remote_host_family;
    char raw_remote_host[16];

    char remote_host[FLB_MAX_IPV6_ADDRESS_LENGTH];
    unsigned short int remote_port;

    /* Net setup shortcut */
    struct flb_net_setup *net;

    /*
     * Custom 'error' for the connection file descriptor. Commonly used to
     * specify a reason for an exception that was generated locally: consider
     * a connect timeout, we shutdown(2) the connection but in reallity we
     * might want to express an 'ETIMEDOUT'
     */
    int net_error;

    /* If this flag is set, then destroy_conn will ignore this connection, this
     * helps mitigate issues caused by flb_upstream_conn_timeouts marking a connection
     * to be dropped and the event loop manager function destroying that connection
     * at the end of the cycle while the connection coroutine is still suspended which
     * causes the outer functions to access invalid memory when handling the error amongst
     * other things.
     */
    int busy_flag;

    /*
     * Recycle: if the connection is keepalive, this flag is always on, but if
     * the caller wants to drop the connection once is released, it can set
     * recycle to false.
     */
    int recycle;

    /* Keepalive */
    int ka_count;        /* how many times this connection has been used */

    /* Timestamps */
    time_t ts_assigned;
    time_t ts_created;
    time_t ts_available;  /* sets the 'start' available time */

    /* Connect */
    time_t ts_connect_start;
    time_t ts_connect_timeout;

    /* Event loop */
    struct mk_event_loop *evl;

    /* Parent stream */
    union {
        void *stream;
        struct flb_upstream *upstream;
        struct flb_downstream *downstream;
    };

    /* Coroutine in charge of this connection */
    struct flb_coro *coroutine;

    /* Connection type : FLB_UPSTREAM_CONNECTION or FLB_DOWNSTREAM_CONNECTION */
    int type;

    /*
     * Link to list head on the stream, if the connection is busy,
     * it's linked to 'busy_queue', otherwise it resides in 'av_queue'
     * for upstream connections so it can be used by a plugin or 
     * 'destroy_queue' awaiting release.
     */    
    struct mk_list _head;

    /* Each TCP connections using TLS needs a session */
    struct flb_tls_session *tls_session;
};

void flb_connection_init(struct flb_connection *connection,
                         flb_sockfd_t socket,
                         int type,
                         void *stream,
                         struct mk_event_loop *event_loop,
                         struct flb_coro *coroutine);

int flb_connection_get_remote_address(struct flb_connection *connection);

int flb_connection_get_flags(struct flb_connection *connection);
void flb_connection_set_connection_timeout(struct flb_connection *connection);
void flb_connection_reset_connection_timeout(struct flb_connection *connection);

#endif
