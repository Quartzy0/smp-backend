#include "debug.h"
#include <event2/event.h>
#include <string.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <aio.h>
#include <event2/thread.h>
#include <event2/http.h>
#include "cmd.h"
#include "vec.h"
#include <ctype.h>
#include "http.h"
#include "defs.h"
#include "spotify.h"

size_t client_count;
int cmds[2];

typedef enum PacketType {
    MUSIC_DATA = 0,
    MUSIC_INFO = 1,
    PLAYLIST_INFO = 2,
    ALBUM_INFO = 3,
    RECOMMENDATIONS = 4
} PacketType;

struct pools {
    struct session_pool session_pool;
    struct http_connection_pool http_connection_pool;
};

bool
is_valid_id(uint8_t *id) {
    if (!id) return false;
    if (memchr(id, '\0', 22)) return false; // If string is shorter than the minimum length
    for (int i = 0; i < 22; ++i) {
        if (!isalnum(id[i])) return false;
    }
    return true;
}

void
write_error_evb(struct evbuffer *buf, enum error_type err, const char *msg) {
    char data[1 + sizeof(size_t)];
    data[0] = err;

    if (msg) {
        size_t len = strlen(msg);
        memcpy(&data[1], &len, sizeof(len));
        evbuffer_add(buf, data, sizeof(data));
        evbuffer_add(buf, msg, len * sizeof(*msg));
    } else {
        memset(&data[1], 0, sizeof(size_t));
        evbuffer_add(buf, data, sizeof(data));
    }
}

void
write_error(struct bufferevent *bev, enum error_type err, const char *msg) {
    char data[1 + sizeof(size_t)];
    data[0] = err;

    if (msg) {
        size_t len = strlen(msg);
        memcpy(&data[1], &len, sizeof(len));
        bufferevent_write(bev, data, sizeof(data));
        bufferevent_write(bev, msg, len * sizeof(*msg));
    } else {
        memset(&data[1], 0, sizeof(size_t));
        bufferevent_write(bev, data, sizeof(data));
    }
}

static void
client_read_cb(struct bufferevent *bev, void *ctx) {
    struct pools *pool = (struct pools *) ctx;
    struct session_pool *session_pool = &pool->session_pool;
    struct http_connection_pool *http_connection_pool = &pool->http_connection_pool;
    /* This callback is invoked when there is data to read on bev. */
    struct evbuffer *input = bufferevent_get_input(bev);
    struct evbuffer *output = bufferevent_get_output(bev);

    size_t in_len = evbuffer_get_length(input);
    if (in_len < 1) return; // Wait for more data
    uint8_t *in = evbuffer_pullup(input, -1);
    switch (in[0]) {
        case MUSIC_DATA: {
            if (in_len < 23) return; // Wait for more data
            uint8_t *id = &in[1];
            if (!is_valid_id(id)) {
                write_error(bev, ET_SPOTIFY, "Invalid track id");
                evbuffer_drain(input, 23);
                return;
            }
            printf("Track requested: %.22s\n", id);

            char path[35] = "music_cache/";
            memcpy(&path[12], id, 22);
            path[34] = 0;

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

                int fd = fileno(fp);
                evbuffer_add_file(output, fd, 0, -1);
//                fclose(fp); TODO: Figure out how to close properly
                if (!bytes_read || file_len != actual_len - sizeof(tmp_data)) { // File is fully written
                    struct element *element = NULL;
                    for (int i = 0; i < SESSION_POOL_MAX; ++i) {
                        if (!memcmp(session_pool->elements[i].id, id, sizeof(session_pool->elements[i].id))) {
                            element = &session_pool->elements[i];
                            break;
                        }
                    }
                    if (element) {
                        vec_add(&element->bev_vec, bev);
                        printf("Sending data for '%.22s' from cache while reading\n", id);
                        evbuffer_drain(input, 23);
                        return;
                    } else {
                        progress = actual_len - sizeof(tmp_data);
                    }
                } else {
                    printf("Sending data for '%.22s' from cache\n", id);
                    evbuffer_drain(input, 23);
                    return;
                }
            }

            spotify_activate_session(session_pool, progress, id, path, bev);
            evbuffer_drain(input, 23);
            return;
        }
        case MUSIC_INFO: {
            if (in_len < 23) return; // Wait for more data
            uint8_t *id = &in[1];
            if (!is_valid_id(id)) {
                write_error(bev, ET_SPOTIFY, "Invalid track id");
                evbuffer_drain(input, 23);
                return;
            }
            char uri[34] = "/v1/tracks/";
            memcpy(&uri[11], id, 22);
            uri[33] = 0;

            char path[34] = "music_info/";
            memcpy(&path[11], &id[11], 23);

            if (!access(path, R_OK)) {
                FILE *fp = fopen(path, "r");
                size_t read_size = 0;
                fread(&read_size, sizeof(read_size), 1, fp);

                fseek(fp, 0L, SEEK_END);
                int64_t len = ftell(fp);
                rewind(fp);

                if (len - sizeof(read_size) == read_size) {
                    evbuffer_add_file(bufferevent_get_output(bev), fileno(fp), 0L, len);
                } else {
                    http_dispatch_request(http_connection_pool, uri, bev,
                                          NULL);     // Cache is still being written, make the request without writing to the cache.
                }                                   // Since the API requests are very small in comparison to downloading songs, an
                evbuffer_drain(input, 23); // extra request isn't a big deal.
                return;
            }
            FILE *fp = fopen(path, "a");

            http_dispatch_request(http_connection_pool, uri, bev, fp);
            evbuffer_drain(input, 23);
            return;
        }
        case PLAYLIST_INFO: {
            if (in_len < 23) return; // Wait for more data
            uint8_t *id = &in[1];
            if (!is_valid_id(id)) {
                write_error(bev, ET_SPOTIFY, "Invalid track id");
                evbuffer_drain(input, 23);
                return;
            }
            char uri[37] = "/v1/playlists/";
            memcpy(&uri[14], id, 22);
            uri[36] = 0;

            char path[37] = "playlist_info/";
            memcpy(&path[14], &id[14], 23);

            if (!access(path, R_OK)) {
                FILE *fp = fopen(path, "r");
                size_t read_size = 0;
                fread(&read_size, sizeof(read_size), 1, fp);

                fseek(fp, 0L, SEEK_END);
                int64_t len = ftell(fp);
                rewind(fp);

                if (len - sizeof(read_size) == read_size) {
                    evbuffer_add_file(bufferevent_get_output(bev), fileno(fp), 0L, len);
                } else {
                    http_dispatch_request(http_connection_pool, uri, bev,
                                          NULL);     // Cache is still being written, make the request without writing to the cache.
                }                                   // Since the API requests are very small in comparison to downloading songs, an
                evbuffer_drain(input, 23);// extra request isn't a big deal.
                return;
            }
            FILE *fp = fopen(path, "a");

            http_dispatch_request(http_connection_pool, uri, bev, fp);
            evbuffer_drain(input, 23);
            return;
        }
        case ALBUM_INFO: {
            if (in_len < 23) return; // Wait for more data
            uint8_t *id = &in[1];
            if (!is_valid_id(id)) {
                write_error(bev, ET_SPOTIFY, "Invalid track id");
                evbuffer_drain(input, 23);
                return;
            }

            char uri[34] = "/v1/albums/";
            memcpy(&uri[11], id, 22);
            uri[33] = 0;

            char path[34] = "album_info/";
            memcpy(&path[11], &id[11], 23);

            if (!access(path, R_OK)) {
                FILE *fp = fopen(path, "r");
                size_t read_size = 0;
                fread(&read_size, sizeof(read_size), 1, fp);

                fseek(fp, 0L, SEEK_END);
                int64_t len = ftell(fp);
                rewind(fp);

                if (len - sizeof(read_size) == read_size) {
                    evbuffer_add_file(bufferevent_get_output(bev), fileno(fp), 0L, len);
                } else {
                    http_dispatch_request(http_connection_pool, uri, bev,
                                          NULL);     // Cache is still being written, make the request without writing to the cache.
                }                                   // Since the API requests are very small in comparison to downloading songs, an
                evbuffer_drain(input, 23);// extra request isn't a big deal.
                return;
            }
            FILE *fp = fopen(path, "a");

            http_dispatch_request(http_connection_pool, uri, bev, fp);
            evbuffer_drain(input, 23);
            return;
        }
        case RECOMMENDATIONS: {
            if (in_len < 25) return;
            uint8_t *n = &in[1];// 0: number of seed tracks, 1: number of seed artists TODO: Support seed genres
            size_t sum = n[0] + n[1];
            size_t expected_len = sum * 22;
            if (sum > 5) { // There can be a maximum of 5 seed tracks, artists and genres in total
                write_error(bev, ET_SPOTIFY, "Maximum of 5 seed tracks, artists in total are allowed");
                evbuffer_drain(input, 3 + expected_len);
                return;
            } else if (sum < 1) {
                write_error(bev, ET_SPOTIFY, "At least 1 seed track, artist must be provided");
                evbuffer_drain(input, 3 + expected_len);
                return;
            }
            if (in_len < 3 + expected_len) return; // Not enough data
            //&limit=10
            size_t uri_len = (n[0] != 0) * (13 + n[0] * 22 + (n[0] - 1)) +
                             (n[1] != 0) * (14 + n[1] * 22 + (n[1] - 1)) +
                             19 + 9 + 1;
            char uri[uri_len];
            char *uri_b = uri;
            uint8_t *ids = &in[3];
            memcpy(uri_b, "/v1/recommendations?", 20);
            uri_b += 20;
            if (n[0] != 0) {
                memcpy(uri_b, "seed_tracks=", 12);
                uri_b += 12;
                for (int i = 0; i < n[0]; ++i) {
                    if (i != 0) {
                        *(uri_b++) = ',';
                    }
                    memcpy(uri_b, ids, 22);
                    ids += 22;
                    uri_b += 22;
                }
            }
            if (n[1] != 0) {
                if (n[0] != 0) {
                    *(uri_b++) = '&';
                }
                memcpy(uri_b, "seed_artists=", 13);
                uri_b += 13;
                for (int i = 0; i < n[1]; ++i) {
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
            printf("Performing request using uri: %s\n", uri);
            http_dispatch_request(http_connection_pool, uri, bev, NULL);
            evbuffer_drain(input, expected_len + 3);
            return;
        }
        default:
            evbuffer_drain(input, 1); //Invalid data
    }
}

static void
client_event_cb(struct bufferevent *bev, short events, void *ctx) {
    if (events & BEV_EVENT_ERROR)
        perror("Error from bufferevent");
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        struct session_pool *pool = (struct session_pool *) ctx;
        for (int i = 0; i < SESSION_POOL_MAX; ++i) {
            if (!vec_remove_element(&pool->elements[i].bev_vec, bev)) break;
        }
        bufferevent_free(bev);
        printf("Client disconnected (%zu)\n", --client_count);
    }
}

void
accept_connection_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *addr, int socklen,
                     void *userp) {
    /* We got a new connection! Set up a bufferevent for it. */
    struct event_base *base = evconnlistener_get_base(listener);
    struct bufferevent *bev = bufferevent_socket_new(
            base, fd, BEV_OPT_CLOSE_ON_FREE);

    bufferevent_setcb(bev, client_read_cb, NULL, client_event_cb, userp);

    bufferevent_enable(bev, EV_READ | EV_WRITE);
    printf("Client connected (%zu)\n", ++client_count);
}

static void
accept_error_cb(struct evconnlistener *listener, void *ctx) {
    struct event_base *base = evconnlistener_get_base(listener);
    int err = EVUTIL_SOCKET_ERROR();
    fprintf(stderr, "Got an error %d (%s) on the listener. "
                    "Shutting down.\n", err, evutil_socket_error_to_string(err));

    event_base_loopexit(base, NULL);
}

static void
cmd_read_cb(int fd, short what, void *arg) {
    struct cmd_data data;
    size_t got = read(fd, &data, sizeof(data));
    if (got <= 0) {
        // TODO: END OF FD
        return;
    }
    if (data.cb) data.cb(data.retval, data.userp);
}

int main(int argc, char **argv) {
    struct event_base *base = NULL;
    struct evconnlistener *listener = NULL;
    struct sockaddr_in sin = {0};
    struct pools pool = {0};
    pipe(cmds);

    client_count = 0;

    spotify_init(argc, argv, &pool.session_pool, cmds[1]);
    http_init(&pool.http_connection_pool);

    evthread_use_pthreads();

    base = event_base_new();
    if (!base) {
        fprintf(stderr, "Couldn't open event base");
        return 1;
    }
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(0);
    sin.sin_port = htons(PORT);
    struct event *cmd_ev = event_new(base, cmds[0], EV_READ | EV_PERSIST, cmd_read_cb, &pool);
    event_add(cmd_ev, NULL);

    listener = evconnlistener_new_bind(base, accept_connection_cb, &pool, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
                                       -1, (struct sockaddr *) &sin, sizeof(sin));
    if (!listener) {
        perror("Couldn't create listener");
        return 1;
    }
    evconnlistener_set_error_cb(listener, accept_error_cb);
    printf("Listening on 0.0.0.0:%d\n", PORT);
    event_base_dispatch(base);

    http_cleanup(&pool.http_connection_pool);
    spotify_clean(&pool.session_pool);
    return 0;
}
