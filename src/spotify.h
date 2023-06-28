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

extern char *available_regions;
extern size_t available_region_count;

struct credentials {
    struct sp_credentials creds;
    char region[2];
    size_t uses;
};

struct element;
typedef void (*audio_finished_cb)(struct element *element, void *arg);

struct session_pool {
    struct element {
        struct sp_session *session;
        struct credentials *creds;
        struct fd_vec{
            int *el;
            size_t len;
            size_t size;
        } fd_vec;
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
        audio_finished_cb cb;
        void *cb_arg;
    } elements[SESSION_POOL_MAX];
};

int spotify_init(int argc, char **argv);

struct element *
spotify_activate_session(struct session_pool *pool, size_t progress, char *id, char *path, int fd,
                         const char *region, audio_finished_cb cb, void *cb_arg,
                         struct event_base *base);

void spotify_update_available_regions();

void spotify_stop_element(struct element *element);

void spotify_clean(struct session_pool *pool);

void spotify_free_global();

void
fd_vec_init(struct fd_vec *v);

void
fd_vec_add(struct fd_vec *vec, int fd);

void
fd_vec_remove(struct fd_vec *vec, int index);

bool
fd_vec_remove_element(struct fd_vec *vec, int fd);

bool
fd_vec_is_empty(struct fd_vec *vec);

void
fd_vec_free(struct fd_vec *v);

#endif //SMP_BACKEND_SPOTIFY_H
