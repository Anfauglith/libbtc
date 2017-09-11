/*

 The MIT License (MIT)

 Copyright (c) 2016 Jonas Schnelli

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

 */

#ifndef __LIBIOP_NET_H__
#define __LIBIOP_NET_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <event2/event.h>

#include "iop.h"
#include "buffer.h"
#include "chainparams.h"
#include "cstr.h"
#include "protocol.h"
#include "vector.h"

static const unsigned int IOP_P2P_MESSAGE_CHUNK_SIZE = 4096;

enum NODE_STATE {
    NODE_CONNECTING = (1 << 0),
    NODE_CONNECTED = (1 << 1),
    NODE_ERRORED = (1 << 2),
    NODE_TIMEOUT = (1 << 3),
    NODE_HEADERSYNC = (1 << 4),
    NODE_BLOCKSYNC	= (1 << 5),
    NODE_MISSBEHAVED = (1 << 6),
    NODE_DISCONNECTED = (1 << 7),
    NODE_DISCONNECTED_FROM_REMOTE_PEER = (1 << 8),
};

/* basic group-of-nodes structure */
struct iop_node_;
typedef struct iop_node_group_ {
    void* ctx; /* flexible context usefull in conjunction with the callbacks */
    struct event_base* event_base;
    vector* nodes; /* the groups nodes */
    char clientstr[1024];
    int desired_amount_connected_nodes;
    const iop_chainparams* chainparams;

    /* callbacks */
    int (*log_write_cb)(const char* format, ...); /* log callback, default=printf */
    iop_bool (*parse_cmd_cb)(struct iop_node_* node, iop_p2p_msg_hdr* hdr, struct const_buffer* buf);
    void (*postcmd_cb)(struct iop_node_* node, iop_p2p_msg_hdr* hdr, struct const_buffer* buf);
    void (*node_connection_state_changed_cb)(struct iop_node_* node);
    iop_bool (*should_connect_to_more_nodes_cb)(struct iop_node_* node);
    void (*handshake_done_cb)(struct iop_node_* node);
    iop_bool (*periodic_timer_cb)(struct iop_node_* node, uint64_t* time); // return false will cancle the internal logic
} iop_node_group;

enum {
    NODE_CONNECTIONSTATE_DISCONNECTED = 0,
    NODE_CONNECTIONSTATE_CONNECTING = 5,
    NODE_CONNECTIONSTATE_CONNECTED = 50,
    NODE_CONNECTIONSTATE_ERRORED = 100,
    NODE_CONNECTIONSTATE_ERRORED_TIMEOUT = 101,
};

/* basic node structure */
typedef struct iop_node_ {
    struct sockaddr addr;
    struct bufferevent* event_bev;
    struct event* timer_event;
    iop_node_group* nodegroup;
    int nodeid;
    uint64_t lastping;
    uint64_t time_started_con;
    uint64_t time_last_request;
    uint256 last_requested_inv;

    cstring* recvBuffer;
    uint64_t nonce;
    uint64_t services;
    uint32_t state;
    int missbehavescore;
    iop_bool version_handshake;

    unsigned int bestknownheight;

    uint32_t hints; /* can be use for user defined state */
} iop_node;

LIBIOP_API int net_write_log_printf(const char* format, ...);

/* =================================== */
/* NODES */
/* =================================== */

/* create new node object */
LIBIOP_API iop_node* iop_node_new();
LIBIOP_API void iop_node_free(iop_node* group);

/* set the nodes ip address and port (ipv4 or ipv6)*/
LIBIOP_API iop_bool iop_node_set_ipport(iop_node* node, const char* ipport);

/* disconnect a node */
LIBIOP_API void iop_node_disconnect(iop_node* node);

/* mark a node missbehave and disconnect */
LIBIOP_API iop_bool iop_node_missbehave(iop_node* node);

/* =================================== */
/* NODE GROUPS */
/* =================================== */

/* create a new node group */
LIBIOP_API iop_node_group* iop_node_group_new(const iop_chainparams* chainparams);
LIBIOP_API void iop_node_group_free(iop_node_group* group);

/* disconnect all peers */
LIBIOP_API void iop_node_group_shutdown(iop_node_group* group);

/* add a node to a node group */
LIBIOP_API void iop_node_group_add_node(iop_node_group* group, iop_node* node);

/* start node groups event loop */
LIBIOP_API void iop_node_group_event_loop(iop_node_group* group);

/* connect to more nodex */
LIBIOP_API iop_bool iop_node_group_connect_next_nodes(iop_node_group* group);

/* get the amount of connected nodes */
LIBIOP_API int iop_node_group_amount_of_connected_nodes(iop_node_group* group, enum NODE_STATE state);

/* sends version command to node */
LIBIOP_API void iop_node_send_version(iop_node* node);

/* send arbitrary data to node */
LIBIOP_API void iop_node_send(iop_node* node, cstring* data);

LIBIOP_API int iop_node_parse_message(iop_node* node, iop_p2p_msg_hdr* hdr, struct const_buffer* buf);
LIBIOP_API void iop_node_connection_state_changed(iop_node* node);

/* =================================== */
/* DNS */
/* =================================== */

LIBIOP_API iop_bool iop_node_group_add_peers_by_ip_or_seed(iop_node_group *group, const char *ips);
LIBIOP_API int iop_get_peers_from_dns(const char* seed, vector* ips_out, int port, int family);

#ifdef __cplusplus
}
#endif

#endif //__LIBIOP_NET_H__
