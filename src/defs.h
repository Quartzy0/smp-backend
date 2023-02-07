//
// Created by quartzy on 2/7/23.
//

#ifndef SMP_BACKEND_DEFS_H
#define SMP_BACKEND_DEFS_H

#include "debug.h"
#include <aio.h>
#include <event2/bufferevent.h>

#define PORT 5394
#define SESSION_POOL_MAX 50
#define MAX_BYTES_PER_READ (1024 * 8) // Same amount used internally by librespot-c
#define MAX_WRITE_JOBS 10
#define MAX_CREDENTIAL_USES 5
#define CONNECTION_POOL_MAX 50
#define URI_MAX_LEN 200
#define SPOTIFY_TOKEN_HEADER_PREFIX_LEN 7
#define SPOTIFY_API_HOST "api.spotify.com"
#define SPOTIFY_TOKEN_HOST "open.spotify.com"
#define HTTPS_PORT 443
#define MAX_REQUESTS 5

struct write_job {
    struct aiocb cb;
    char tmp[MAX_BYTES_PER_READ];
};

enum error_type {
    ET_NO_ERROR = 0,
    ET_SPOTIFY = 1,
    ET_SPOTIFY_INTERNAL = 2,
    ET_HTTP = 3,
    ET_FULL = 4
};

void
write_error_evb(struct evbuffer *buf, enum error_type err, const char *msg);

void
write_error(struct bufferevent *bev, enum error_type err, const char *msg);

#endif //SMP_BACKEND_DEFS_H
