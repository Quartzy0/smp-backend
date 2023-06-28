#include "debug.h"
#include <event2/event.h>
#include <string.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/http.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include "defs.h"
#include "spotify.h"
#include "util.h"
#include "config.h"
#include "worker.h"

static struct sp_sysinfo s_sysinfo;

struct worker_pool{
    struct worker *workers;
    size_t worker_count;
};

struct worker_callback_container{
    struct worker_pool *pool;
    struct worker *worker;
};

void
write_error(int fd, enum error_type err, const char *msg) {
    if (fd == -1) return;
    char data[1 + sizeof(size_t)];
    data[0] = err;

    if (msg) {
        size_t len = strlen(msg);
        memcpy(&data[1], &len, sizeof(len));
        write(fd, data, sizeof(data));
        write(fd, msg, len * sizeof(*msg));
    } else {
        memset(&data[1], 0, sizeof(size_t));
        write(fd, data, sizeof(data));
    }
}

static void
client_read_cb(struct bufferevent *bev, void *ctx){
    struct worker_callback_container *container = (struct worker_callback_container*)ctx;
    struct worker_pool *worker_pool = container->pool;
    int fd = bufferevent_getfd(bev);

    struct evbuffer *input = bufferevent_get_input(bev);
    size_t in_len = evbuffer_get_length(input);
    if (in_len < 1) return; // Wait for more data
    uint8_t *in = evbuffer_pullup(input, -1);
    switch (in[0]) {
        case MUSIC_DATA: {
            if (in_len < 25) return; // Wait for more data
            uint8_t *id = &in[1];
            if (!is_valid_id(id)) {
                printf("Invalid track id: %.22s\n", id);
                write_error(fd, ET_SPOTIFY, "Invalid track id");
                evbuffer_drain(input, 25);
                return;
            }
            printf("Track requested: %.22s\n", id);

            struct worker_hash_table_element *worker = hash_table_put_if_not_get(&worker_id_table, (const char*) id, worker_find_least_busy(worker_pool->workers, worker_pool->worker_count));
            struct worker_request req = {0};
            req.type = MUSIC_DATA;
            req.client_fd = fd;
            memcpy(req.regioned_id.id, id, sizeof(req.regioned_id.id));
            memcpy(req.regioned_id.region, &in[23], sizeof(req.regioned_id.region));
            worker_send_request(worker->worker, &req);
            container->worker = worker->worker;

            evbuffer_drain(input, 25);
            return;
        }
        case PLAYLIST_INFO:
        case ALBUM_INFO:
        case ARTIST_INFO:
        case MUSIC_INFO: {
            uint8_t *id = &in[1];
            if (!is_valid_id(id)) {
                write_error(fd, ET_SPOTIFY, "Invalid track id");
                evbuffer_drain(input, 23);
                return;
            }
            struct worker_request req = {0};
            req.type = in[0];
            req.client_fd = fd;
            memcpy(req.generic_id, id, sizeof(req.generic_id));
            worker_send_request(worker_find_least_busy(worker_pool->workers, worker_pool->worker_count), &req);
            evbuffer_drain(input, 23);
            return;
        }
        case SEARCH: {
            if (in_len < 2 + sizeof(uint16_t)) return;
            uint8_t flags = in[1];
            uint16_t q_len = *((uint16_t *) &in[2]);
            if (in_len < 2 + sizeof(uint16_t) + q_len) return;

            struct worker_request req = {0};
            req.type = SEARCH;
            req.client_fd = fd;
            req.search_query.flags = flags;
            req.search_query.generic_query = urlencode((const char *) &in[2 + sizeof(uint16_t)], q_len);
            worker_send_request(worker_find_least_busy(worker_pool->workers, worker_pool->worker_count), &req);
            evbuffer_drain(input, 2 + sizeof(uint16_t) + q_len);
            return;
        }
        case AVAILABLE_REGIONS: {
            char resp[sizeof(available_region_count) + 1];
            resp[0] = ET_NO_ERROR;
            *((size_t *) &resp[1]) = available_region_count * 2;
            write(fd, &resp, sizeof(resp));
            write(fd, available_regions, available_region_count*2);
            evbuffer_drain(input, 1);
            return;
        }
        case RECOMMENDATIONS: {
            if (in_len < 25) return;
            uint8_t *n = &in[1];// 0: number of seed tracks, 1: number of seed artists TODO: Support seed genres
            size_t sum = n[0] + n[1];
            size_t expected_len = sum * 22;
            if (sum > 5) { // There can be a maximum of 5 seed tracks, artists and genres in total
                write_error(fd, ET_SPOTIFY, "Maximum of 5 seed tracks, artists in total are allowed");
                evbuffer_drain(input, 3 + expected_len);
                return;
            } else if (sum < 1) {
                write_error(fd, ET_SPOTIFY, "At least 1 seed track, artist must be provided");
                evbuffer_drain(input, 3 + expected_len);
                return;
            }
            if (in_len < 3 + expected_len) return; // Not enough data

            struct worker_request req = {0};
            req.type = RECOMMENDATIONS;
            req.client_fd = fd;
            req.recommendation_seed.t = n[0];
            req.recommendation_seed.a = n[1];
            memcpy(&req.recommendation_seed.ids[0][0], &n[2], expected_len);
            worker_send_request(worker_find_least_busy(worker_pool->workers, worker_pool->worker_count), &req);
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
        struct worker_callback_container *container = (struct worker_callback_container*) ctx;
        if (container->worker){
            struct worker_request req = {0};
            req.type = DISCONNECTED;
            req.client_fd = bufferevent_getfd(bev);
            worker_send_request(container->worker, &req);
        }
        bufferevent_free(bev);
        printf("Client disconnected\n");
    }
}

void
accept_connection_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *addr, int socklen,
                     void *userp) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (!(flags & O_NONBLOCK)) fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    /* We got a new connection! Set up a bufferevent for it. */
    struct event_base *base = evconnlistener_get_base(listener);
    struct bufferevent *bev = bufferevent_socket_new(
            base, fd, BEV_OPT_CLOSE_ON_FREE);

    struct worker_callback_container *container = calloc(1, sizeof(*container));
    container->pool = (struct worker_pool*) userp;

    bufferevent_setcb(bev, client_read_cb, NULL, client_event_cb, container);

    bufferevent_enable(bev, EV_READ);
    printf("Client connected\n");
}

static void
accept_error_cb(struct evconnlistener *listener, void *ctx) {
    struct event_base *base = evconnlistener_get_base(listener);
    int err = EVUTIL_SOCKET_ERROR();
    fprintf(stderr, "Got an error %d (%s) on the listener. "
                    "Shutting down.\n", err, evutil_socket_error_to_string(err));

    event_base_loopexit(base, NULL);
}

void
cache_check_cb(int fd, short what, void *arg) {
    struct smp_config *config = (struct smp_config *) arg;
    if (config->music_info_cache_max != -1)
        delete_oldest_until_size_requirement(config->music_info_cache_max, config->music_info_cache_path, NULL);
    if (config->music_data_cache_max != -1)
        delete_oldest_until_size_requirement(config->music_data_cache_max, config->music_data_cache_path, NULL);
    if (config->album_info_cache_max != -1)
        delete_oldest_until_size_requirement(config->album_info_cache_max, config->album_info_cache_path, NULL);
    if (config->playlist_info_cache_max != -1)
        delete_oldest_until_size_requirement(config->playlist_info_cache_max, config->playlist_info_cache_path, NULL);
    if (config->total_cache_max != -1)
        delete_oldest_until_size_requirement(config->total_cache_max, config->music_info_cache_path,
                                             config->music_data_cache_path, config->album_info_cache_path,
                                             config->playlist_info_cache_path, NULL);

}

void sigterm_handler(int signal, short events, void *arg)
{
    event_base_loopbreak(arg);
    printf("Signal received, shutting down...\n");
}

int main(int argc, char **argv) {
    struct smp_config config;
    if (argc > 1)
        parse_config(argv[1],&config);
    else
        parse_config("config.cfg", &config);
    printf("Parsed config:\n");
    print_config(&config);

    // Create needed directories
    mkdir("music_info", 0777);
    mkdir("music_cache", 0777);
    mkdir("album_info", 0777);
    mkdir("playlist_info", 0777);

    spotify_init(argc, argv);

    struct worker_pool worker_pool;
    worker_pool.worker_count = config.worker_threads;
    worker_pool.workers = calloc(worker_pool.worker_count, sizeof(*worker_pool.workers));
    for (int i = 0; i < worker_pool.worker_count; ++i) {
        worker_init(&worker_pool.workers[i]);
        worker_pool.workers[i].id = i;
    }

    struct event_base *base = NULL;
    struct evconnlistener *listener = NULL;
    struct sockaddr_in sin = {0};

    base = event_base_new();
    if (!base) {
        fprintf(stderr, "Couldn't open event base\n");
        return 1;
    }

    struct event *sigterm_event;
    sigterm_event = evsignal_new(base, SIGTERM, sigterm_handler, base);
    evsignal_add(sigterm_event, NULL);

    struct event *sigint_event;
    sigint_event = evsignal_new(base, SIGINT, sigterm_handler, base);
    evsignal_add(sigint_event, NULL);

    struct event *sighup_event;
    sighup_event = evsignal_new(base, SIGHUP, sigterm_handler, base);
    evsignal_add(sighup_event, NULL);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(0);
    sin.sin_port = htons(PORT);

    if (config.total_cache_max != -1 || config.album_info_cache_max != -1 || config.playlist_info_cache_max != -1 ||
        config.music_data_cache_max != -1 || config.music_info_cache_max != -1) {
        struct event *cache_check_ev = event_new(base, -1, EV_PERSIST, cache_check_cb, &config);
        struct timeval timeval = {.tv_sec = 10, .tv_usec = 0};
        event_add(cache_check_ev, &timeval);
    }

    memset(&s_sysinfo, 0, sizeof(struct sp_sysinfo));
    snprintf(s_sysinfo.device_id, sizeof(s_sysinfo.device_id), "aabbccddeeff");

    int ret = librespotc_init(&s_sysinfo, &callbacks);
    if (ret < 0) {
        printf("Error initializing Spotify: %s\n", librespotc_last_errmsg());
        return -1;
    }

    listener = evconnlistener_new_bind(base, accept_connection_cb, &worker_pool, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
                                       -1, (struct sockaddr *) &sin, sizeof(sin));
    if (!listener) {
        perror("Couldn't create listener");
        return 1;
    }
    evconnlistener_set_error_cb(listener, accept_error_cb);
    printf("Listening on 0.0.0.0:%d\n", PORT);
    event_base_dispatch(base);

    for (int i = 0; i < worker_pool.worker_count; ++i) {
        struct worker *worker = &worker_pool.workers[i];
        worker_cleanup(worker);
    }
    for (int i = 0; i < worker_pool.worker_count; ++i) {
        struct worker *worker = &worker_pool.workers[i];
        pthread_join(worker->tid, NULL);
    }
    hash_table_clean(&worker_id_table);
    free(worker_pool.workers);
    event_free(sigterm_event);
    event_free(sigint_event);
    event_free(sighup_event);
    evconnlistener_free(listener);
    event_base_free(base);
    spotify_free_global();
    free_config(&config);
    printf("Main thread freed\n");

    return 0;
}
