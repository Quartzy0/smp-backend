//
// Created by quartzy on 4/30/23.
//

#ifndef SMP_BACKEND_WORKER_H
#define SMP_BACKEND_WORKER_H

#include <pthread.h>
#include "vec.h"
#include "http.h"
#include "spotify.h"

#define WORKER_HASH_TABLE_BUCKETS 50

typedef enum PacketType {
    MUSIC_DATA = 0,
    MUSIC_INFO = 1,
    PLAYLIST_INFO = 2,
    ALBUM_INFO = 3,
    RECOMMENDATIONS = 4,
    ARTIST_INFO = 5,
    SEARCH = 6,
    AVAILABLE_REGIONS = 7,


    DISCONNECTED = 0xff, // Only used for communication between master thread and workers
} PacketType;

struct worker_request{
    PacketType type;
    int client_fd;
    union {
        char generic_id[22];
        struct {
            char id[22];
            char region[2];
        } regioned_id;
        struct {
            uint8_t flags;
            char *generic_query;
        } search_query;
        struct {
            uint8_t t, a;
            char ids[5][22];
        } recommendation_seed;
    };
};

struct worker{
    pthread_t tid;
    int cmd[2];
    int id; // Maybe useful for debug purposes

    struct event_base *base;
    struct event *cmd_ev;

    struct vec clients;

    struct session_pool session_pool;
    struct http_connection_pool http_connection_pool;
};

struct worker_hash_table{
    struct worker_hash_table_bucket{
        struct worker_hash_table_element{
            char key[22];
            struct worker *worker;
        } *elements;
        size_t len, size;
    } buckets[WORKER_HASH_TABLE_BUCKETS];
    pthread_mutex_t mutex;
    bool initialized;
};

extern struct worker_hash_table worker_id_table;

void hash_table_init(struct worker_hash_table *table);

struct worker_hash_table_element* hash_table_put_if_not_get(struct worker_hash_table *table, const char *key, struct worker *worker);

void hash_table_remove(struct worker_hash_table *table, const char *key);

struct worker* worker_find_least_busy(struct worker *workers, size_t count);

int worker_init(struct worker *worker);

void worker_send_request(struct worker *worker, struct worker_request *request);

void worker_cleanup(struct worker *worker);

#endif //SMP_BACKEND_WORKER_H
