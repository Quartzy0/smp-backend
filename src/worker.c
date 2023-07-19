//
// Created by quartzy on 4/30/23.
//

#include "worker.h"

#include <unistd.h>
#include <stdio.h>
#include <event2/event.h>
#include <sys/sendfile.h>

#include "spotify.h"
#include "http.h"
#include "util.h"

struct worker_hash_table worker_id_table;
char region_url_insertion[] = "?market=";

void
http_generic_request(const char *id, int fd, struct http_connection_pool *http_connection_pool, const char *uri_in,
                     const char *path_in, bool api, bool insert_id_url, http_request_finished_cb cb, void *userp) {
    JDM_ENTER_FUNCTION;
    char *uri;
    if (insert_id_url) {
        size_t uri_in_len = strlen(uri_in);
        uri = calloc(22 + uri_in_len + sizeof(region_url_insertion) + 2, sizeof(*uri));
        memcpy(uri, uri_in, uri_in_len);
        memcpy(&uri[uri_in_len], id, 22);
        memcpy(&uri[uri_in_len+22], region_url_insertion, sizeof(region_url_insertion)-1);
        uri[uri_in_len+22+sizeof(region_url_insertion)-1] = top_region[0];
        uri[uri_in_len+22+sizeof(region_url_insertion)] = top_region[1];
    }

    size_t path_in_len = strlen(path_in);
    char *path = calloc(22 + path_in_len + 1, sizeof(*path));
    memcpy(path, path_in, path_in_len);
    memcpy(&path[path_in_len], id, 22);

    if (!access(path, R_OK)) {
        FILE *fp = fopen(path, "r");
        size_t read_size = 0;
        fread(&read_size, sizeof(read_size), 1, fp);

        fseek(fp, 0L, SEEK_END);
        int64_t len = ftell(fp);
        rewind(fp);

        if (len - sizeof(read_size) == read_size) {
            sendfile(fd, fileno(fp), NULL, len);
        } else {
            if (api) {
                http_dispatch_request_api(http_connection_pool, insert_id_url ? uri : uri_in, fd,
                                          NULL, cb, userp);
            } else {
                http_dispatch_request_partner(http_connection_pool, insert_id_url ? uri : uri_in, fd,
                                              NULL, cb, userp);
            }
            // Cache is still being written, make the request without writing to the cache.
        }   // Since the API requests are very small in comparison to downloading songs, an
            // extra request isn't a big deal.
        fclose(fp);
        JDM_LEAVE_FUNCTION;
        return;
    }
    FILE *fp = fopen(path, "a");

    if (api) {
        http_dispatch_request_api(http_connection_pool, insert_id_url ? uri : uri_in, fd, fp, cb, userp);
    } else {
        http_dispatch_request_partner(http_connection_pool, insert_id_url ? uri : uri_in, fd, fp, cb, userp);
    }
    JDM_LEAVE_FUNCTION;
}

void
element_finished_cb(struct element *element, void *arg){
    hash_table_remove(&worker_id_table, element->id);
    ((struct worker*)arg)->job_count--;
}

void
http_request_finished(void *arg){
    struct worker *worker = (struct worker*) arg;
    worker->job_count--;
}

static void
cmd_read_cb(int wrk_fd, short what, void *arg) {
    JDM_ENTER_FUNCTION;
    struct worker *worker = (struct worker *) arg;
    struct worker_request req;
    read(wrk_fd, &req, sizeof(req));
    switch (req.type) {
        case MUSIC_DATA: {
            char path[35] = "music_cache/";
            memcpy(&path[12], req.regioned_id.id, 22);
            path[34] = 0;
            worker->job_count++;

            size_t progress = 0;
            if (!access(path, R_OK)) {
                FILE *fp = fopen(path, "r");
                size_t file_len;
                char tmp_data[1 + sizeof(file_len)];
                size_t bytes_read = fread(tmp_data, sizeof(tmp_data), 1, fp);
                file_len = *((size_t *) &tmp_data[1]); // Skip first byte
                fseek(fp, 0L, SEEK_END);
                size_t actual_len = ftell(fp);
                rewind(fp);

                if (tmp_data[0] != ET_NO_ERROR){
                    fclose(fp); // File contains an error response (somehow)
                    remove(path);
                } else{
                    int fd = fileno(fp);
                    sendfile(req.client_fd, fd, NULL, actual_len);
                    if (!bytes_read || file_len != actual_len - sizeof(tmp_data)) { // Check if file is fully written
                        struct element *element = NULL;
                        for (int i = 0; i < SESSION_POOL_MAX; ++i) {
                            if (!memcmp(worker->session_pool.elements[i].id, req.regioned_id.id, sizeof(worker->session_pool.elements[i].id))) {
                                element = &worker->session_pool.elements[i];
                                break;
                            }
                        }
                        if (element) {
                            fd_vec_add(&element->fd_vec, req.client_fd);
                            JDM_TRACE("[worker %d] Sending data for '%.22s' from cache while reading", worker->id, req.regioned_id.id);
                            fclose(fp);
                            break;
                        } else {
                            progress = actual_len - sizeof(tmp_data);
                        }
                        fclose(fp);
                    } else {
                        JDM_TRACE("[worker %d] Sending data for '%.22s' from cache", worker->id, req.regioned_id.id);
                        fclose(fp);
                        break;
                    }
                }
            }
            JDM_TRACE("[worker %d] Sending data for '%.22s'", worker->id, req.regioned_id.id);

            spotify_activate_session(&worker->session_pool, progress, req.regioned_id.id, path, req.client_fd, req.regioned_id.region[0] ? req.regioned_id.region : NULL, element_finished_cb, worker, worker->base);
            break;
        }
        case MUSIC_INFO: {
            http_generic_request(req.generic_id, req.client_fd, &worker->http_connection_pool, "/v1/tracks/",
                                 "music_info/", true, true, http_request_finished, worker);
            break;
        }
        case PLAYLIST_INFO: {
            http_generic_request(req.generic_id, req.client_fd, &worker->http_connection_pool, "/v1/playlists/",
                                 "playlist_info/", true, true, http_request_finished, worker);
            break;
        }
        case ALBUM_INFO: {
            http_generic_request(req.generic_id, req.client_fd, &worker->http_connection_pool, "/v1/albums/",
                                 "album_info/", true, true, http_request_finished, worker);
            break;
        }
        case ARTIST_INFO: {
            // TODO: Not yet implemented but will let us get artist's radio & mix
            write_error(req.client_fd, ET_HTTP, "Feature not yet implemented");
//            http_generic_request(req->generic_id, req->client_fd, &worker->http_connection_pool, "/v1/albums/", "artist_info/", false, false);
            break;
        }
        case SEARCH: {
            int flags = req.search_query.flags;
            size_t uri_len = 19 + (flags & 1) * 6 + (flags & 2) * 7 + (flags & 4) * 6 + (flags & 8) * 9 + strlen(req.search_query.generic_query) + 1;
            char *uri = calloc(uri_len, sizeof(*uri));
            strcat(uri, "/v1/search?type=");
            if (flags & 1) {
                strcat(uri, "track");
            }
            if (flags & 2) {
                if (flags & 1) strcat(uri, ",artist");
                else strcat(uri, "artist");
            }
            if (flags & 4) {
                if (flags & 3) strcat(uri, ",album");
                else strcat(uri, "album");
            }
            if (flags & 8) {
                if (flags & 7) strcat(uri, ",playlist");
                else strcat(uri, "playlist");
            }
            strcat(uri, "&q=");
            strcat(uri, req.search_query.generic_query);
            free(req.search_query.generic_query);

            JDM_TRACE("Search url: %s", uri);

            http_dispatch_request_api(&worker->http_connection_pool, uri, req.client_fd, NULL, http_request_finished, worker);
            free(uri);
            break;
        }
        case RECOMMENDATIONS: {
            uint8_t t = req.recommendation_seed.t, a = req.recommendation_seed.a;
            size_t uri_len = (t != 0) * (13 + t * 22 + (t - 1)) +
                             (a != 0) * (14 + a * 22 + (a - 1)) +
                             19 + 9 + 1;
            char uri[uri_len];
            char *uri_b = uri;
            char *ids = &req.recommendation_seed.ids[0][0];
            memcpy(uri_b, "/v1/recommendations?", 20);
            uri_b += 20;
            if (t != 0) {
                memcpy(uri_b, "seed_tracks=", 12);
                uri_b += 12;
                for (int i = 0; i < t; ++i) {
                    if (i != 0) {
                        *(uri_b++) = ',';
                    }
                    memcpy(uri_b, ids, 22);
                    ids += 22;
                    uri_b += 22;
                }
            }
            if (a != 0) {
                if (t != 0) {
                    *(uri_b++) = '&';
                }
                memcpy(uri_b, "seed_artists=", 13);
                uri_b += 13;
                for (int i = 0; i < a; ++i) {
                    if (i != 0) {
                        *(uri_b++) = ',';
                    }
                    memcpy(uri_b, ids, 22);
                    ids += 22;
                    uri_b += 22;
                }
            }
            memcpy(uri_b, "&limit=30", 9);
            uri[uri_len - 1] = 0;
            JDM_TRACE("Performing request using uri: %s", uri);
            http_dispatch_request_api(&worker->http_connection_pool, uri, req.client_fd, NULL, http_request_finished, worker);
            break;
        }
        case DISCONNECTED: {
            int element_len = SESSION_POOL_MAX;
            for (int i = 0; i < element_len; ++i) {
                if(fd_vec_remove_element(&worker->session_pool.elements[i].fd_vec, req.client_fd)) {
                    JDM_TRACE("Client disconnected (%d)", req.client_fd);
                    if (fd_vec_is_empty(&worker->session_pool.elements[i].fd_vec)){
                        JDM_TRACE("All clients for element streaming '%.22s' have disconnected", worker->session_pool.elements[i].id);
                        spotify_stop_element(&worker->session_pool.elements[i]);
                    }
                    break;
                }
            }
            break;
        }
        case CLEANUP: {
            http_cleanup(&worker->http_connection_pool);
            spotify_clean(&worker->session_pool);
            close(worker->cmd[1]);
            close(worker->cmd[0]);
            event_free(worker->cmd_ev);
            event_base_loopbreak(worker->base);
            break;
        }
        default: break;
    }
    JDM_LEAVE_FUNCTION;
}

void *
worker_loop(void *arg) {
    struct worker *worker = (struct worker *) arg;
    char thread_name[12];
    snprintf(thread_name, 12, "Worker %d", worker->id);
    jdm_init_thread(thread_name, JDM_MESSAGE_LEVEL_NONE, 256, 256, NULL);
    jdm_set_hook(error_message_hook, NULL);
    JDM_ENTER_FUNCTION;
    set_sigsegv_handler();

    worker->base = event_base_new();
    worker->cmd_ev = event_new(worker->base, worker->cmd[0], EV_READ | EV_PERSIST, cmd_read_cb, worker);
    event_add(worker->cmd_ev, NULL);
    worker->job_count = 0;
    http_set_base(worker->base, &worker->http_connection_pool);
    event_base_dispatch(worker->base);
    event_base_free(worker->base);
    JDM_INFO("Worker %d freed", worker->id);
    JDM_LEAVE_FUNCTION;
    jdm_cleanup_thread();
    pthread_exit(NULL);
}

int
worker_init(struct worker *worker) {
    JDM_ENTER_FUNCTION;
    memset(&worker->session_pool, 0, sizeof(worker->session_pool));
    http_init(&worker->http_connection_pool);
    hash_table_init(&worker_id_table);
    pipe(worker->cmd);
    int ret = pthread_create(&worker->tid, NULL, worker_loop, worker);
    if (ret) {
        JDM_ERROR("Error when calling pthread_create(): %s", strerror(errno));
        JDM_LEAVE_FUNCTION;
        return 1;
    }
    JDM_LEAVE_FUNCTION;
    return 0;
}

void worker_send_request(struct worker *worker, struct worker_request *request) {
    write(worker->cmd[1], request, sizeof(*request));
}

struct worker *
worker_find_least_busy(struct worker *workers, size_t count) {
    JDM_ENTER_FUNCTION;
    size_t lowest = -1;
    struct worker *lw;
    for (int i = 0; i < count; ++i) {
        if (workers[i].job_count == 0){
            JDM_LEAVE_FUNCTION;
            return &workers[i];
        }
        if (workers[i].job_count < lowest){
            lowest = workers[i].job_count;
            lw = &workers[i];
        }
    }
    JDM_LEAVE_FUNCTION;
    return lw;
}

static unsigned long
hash(const char *name) {
    unsigned long hash = 5381;
    char p;

    while ((p = *(name++)))
        hash = ((hash << 5) + hash) + p; /* hash * 33 + c */
    return hash;
}

void
hash_table_remove(struct worker_hash_table *table, const char *key){
    JDM_ENTER_FUNCTION;
    unsigned long bucket_index = hash(key) % WORKER_HASH_TABLE_BUCKETS;

    pthread_mutex_lock(&table->mutex);
    struct worker_hash_table_bucket *bucket = &table->buckets[bucket_index];
    for (int i = 0; i < bucket->len; ++i) {
        if (bucket->elements && !memcmp(bucket->elements[i].key, key, 22)) {
            if (i == bucket->len - 1) break;
            memmove(&bucket->elements[i], &bucket->elements[i+1], bucket->len-(i+1));
            bucket->len--;
            break;
        }
    }
    pthread_mutex_unlock(&table->mutex);
    JDM_LEAVE_FUNCTION;
}

void hash_table_init(struct worker_hash_table *table) {
    if(table->initialized) return;
    table->initialized = true;
    memset(table, 0, sizeof(*table));
    table->mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;
}

struct worker_hash_table_element *
hash_table_put_if_not_get(struct worker_hash_table *table, const char *key, struct worker *worker) {
    JDM_ENTER_FUNCTION;
    unsigned long bucket_index = hash(key) % WORKER_HASH_TABLE_BUCKETS;

    pthread_mutex_lock(&table->mutex);
    struct worker_hash_table_bucket *bucket = &table->buckets[bucket_index];
    for (int i = 0; i < bucket->len; ++i) {
        if (bucket->elements && !memcmp(bucket->elements[i].key, key, 22)) {
            pthread_mutex_unlock(&table->mutex);
            JDM_LEAVE_FUNCTION;
            return &bucket->elements[i];
        }
    }

    if (!bucket->elements){
        bucket->size = 20;
        bucket->elements = calloc(bucket->size, sizeof(*bucket->elements));
    }else if (bucket->size<=bucket->len+1){
        bucket->size *= 2;
        struct worker_hash_table_element *tmp = realloc(bucket->elements, bucket->size * sizeof(*tmp));
        if (!tmp) perror("error while calling realloc()");
        bucket->elements = tmp;
    }
    memcpy(bucket->elements[bucket->len].key, key, sizeof(bucket->elements[bucket->len].key));
    bucket->elements[bucket->len].worker = worker;
    bucket->len++;
    pthread_mutex_unlock(&table->mutex);
    JDM_LEAVE_FUNCTION;
    return &bucket->elements[bucket->len-1];
}

void
hash_table_clean(struct worker_hash_table *table){
    JDM_ENTER_FUNCTION;
    pthread_mutex_lock(&table->mutex);
    for (int i = 0; i < WORKER_HASH_TABLE_BUCKETS; ++i) {
        free(table->buckets[i].elements);
    }
    pthread_mutex_unlock(&table->mutex);
    pthread_mutex_destroy(&table->mutex);
    memset(table, 0, sizeof(*table));
    JDM_LEAVE_FUNCTION;
}

void worker_cleanup(struct worker *worker) {
    struct worker_request req = {
            .type = CLEANUP,
    };
    worker_send_request(worker, &req);
}
