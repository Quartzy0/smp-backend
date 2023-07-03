//
// Created by quartzy on 2/7/23.
//

#ifndef SMP_BACKEND_HTTP_H
#define SMP_BACKEND_HTTP_H

#include "util.h"
#include "vec.h"
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
    SSL *ssl_api;
    SSL_CTX *ssl_ctx_api;
    char *token;
    size_t token_len;
    struct vec queued_requests;
    bool fetching_token;

    SSL *ssl_partner;
    SSL_CTX *ssl_ctx_partner;

    //Token refresh connection
    struct connection token_connection;
    SSL *token_ssl;
    SSL_CTX *token_ssl_ctx;
    struct event_base *base;
};

typedef void (*http_request_finished_cb)(void *userp);

struct request_state {
    size_t response_size;
    int out_fd;
    struct connection *connection;
    struct http_connection_pool *pool;
    char request[URI_MAX_LEN];
    char *token;
    struct write_job write_job;
    FILE *fp;
    bool api; // Is host api.spotify.com or api-partner.spotify.com
    http_request_finished_cb cb;
    void *userp;
};

int http_init(struct http_connection_pool *pool);

void http_set_base(struct event_base *base, struct http_connection_pool *pool);

int http_dispatch_request(struct http_connection_pool *pool, const char *uri_in, int fd, FILE *fp, SSL *ssl,
                          const char *host, bool api, http_request_finished_cb cb, void *userp);

#define http_dispatch_request_api(pool, uri_in, bev, fp, cb, userp) http_dispatch_request(pool, uri_in, bev, fp, (pool)->ssl_api, SPOTIFY_API_HOST, true, cb, userp)
#define http_dispatch_request_partner(pool, uri_in, bev, fp, cb, userp) http_dispatch_request(pool, uri_in, bev, fp, (pool)->ssl_partner, SPOTIFY_PARTNER_HOST, false, cb, userp)

void http_cleanup(struct http_connection_pool *pool);

char *urlencode(const char *src, int len);

#endif //SMP_BACKEND_HTTP_H
