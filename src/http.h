//
// Created by quartzy on 2/7/23.
//

#ifndef SMP_BACKEND_HTTP_H
#define SMP_BACKEND_HTTP_H

#include "defs.h"
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

struct http_connection_pool {
    struct connection {
        struct evhttp_connection *connection;
        struct bufferevent *bev;
        bool active;
        size_t active_requests;
    } connections[CONNECTION_POOL_MAX];
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    char *token;
    size_t token_len;

    //Token refresh connection
    struct connection token_connection;
    SSL *token_ssl;
    SSL_CTX *token_ssl_ctx;
};

struct request_state {
    size_t response_size;
    struct evbuffer *output;
    struct connection *connection;
    struct http_connection_pool *pool;
    char request[URI_MAX_LEN];
    char *token;
    struct write_job write_jobs[MAX_WRITE_JOBS];
    FILE *fp;
    int write_job_index;
};

int http_init(struct http_connection_pool *pool);

int http_dispatch_request_state(struct request_state *state);

int http_dispatch_request(struct http_connection_pool *pool, const char *uri_in, struct bufferevent *bev, FILE *fp);

void http_cleanup(struct http_connection_pool *pool);

#endif //SMP_BACKEND_HTTP_H
