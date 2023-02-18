//
// Created by quartzy on 2/7/23.
//

#ifndef SMP_BACKEND_SPOTIFY_H
#define SMP_BACKEND_SPOTIFY_H

#include "librespot-util.h"
#include "stdbool.h"
#include "defs.h"
#include "vec.h"
#include <event2/bufferevent.h>

static struct sp_sysinfo s_sysinfo;
struct credentials {
    struct sp_credentials creds;
    size_t uses;
};

struct session_pool {
    struct element {
        struct sp_session *session;
        struct credentials *creds;
        struct vec bev_vec;
        struct event_base *base;
        struct event *read_ev;
        bool active;
        FILE *cache_fp;
        struct write_job write_job;
        char id[22];
        char *path;
        size_t progress;
        size_t file_len;
        uint8_t retries;
    } elements[SESSION_POOL_MAX];
};

int spotify_init(int argc, char **argv, struct session_pool *pool, int fd);

struct element *
spotify_activate_session(struct session_pool *pool, size_t progress, uint8_t *id, char *path, struct bufferevent *bev);

void spotify_clean(struct session_pool *pool);

#endif //SMP_BACKEND_SPOTIFY_H
