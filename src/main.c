#include "debug.h"
#include <event2/event.h>
#include <string.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <stdbool.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <aio.h>
#include <event2/thread.h>
#include <event2/bufferevent_ssl.h>
#include <event2/http.h>
#include <event2/http_struct.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "librespot-util.h"
#include "openssl_hostname_validation.h"
#include "cmd.h"
#include "vec.h"


#define PORT 5394
#define SESSION_POOL_MAX 50
#define MAX_BYTES_PER_READ (1024 * 8) // Same amount used internally by librespot-c
#define MAX_WRITE_JOBS 10
#define MAX_CREDENTIAL_USES 5
#define CONNECTION_POOL_MAX 50
#define URI_MAX_LEN 50
#define SPOTIFY_TOKEN_LEN 115
#define SPOTIFY_TOKEN_HEADER_PREFIX_LEN 7
#define SPOTIFY_API_HOST "api.spotify.com"
#define SPOTIFY_TOKEN_HOST "open.spotify.com"
#define HTTPS_PORT 443
#define MAX_REQUESTS 5

static struct sp_sysinfo s_sysinfo;
struct credentials {
    struct sp_credentials creds;
    size_t uses;
} *credentials;
size_t credentials_count;
size_t credentials_last_index;
size_t client_count;
int cmds[2];

typedef enum PacketType {
    MUSIC_DATA = 0,
    MUSIC_INFO = 1,
    PLAYLIST_INFO = 2,
    ALBUM_INFO = 3,
    RECOMMENDATIONS = 4
} PacketType;

enum error_type {
    ET_NO_ERROR,
    ET_SPOTIFY,
    ET_HTTP,
    ET_FULL
};

struct session_pool {
    struct element {
        struct sp_session *session;
        struct vec bev_vec;
        struct event_base *base;
        struct event *read_ev;
        bool active;
        FILE *cache_fp;
        struct write_job {
            struct aiocb cb;
            char tmp[MAX_BYTES_PER_READ];
        } write_jobs[MAX_WRITE_JOBS];
        int write_job_index;
        char id[22];
        char *path;
        size_t progress;
    } elements[SESSION_POOL_MAX];
};

struct request_state;

struct http_connection_pool {
    struct connection {
        struct evhttp_connection *connection;
        struct bufferevent *bev;
        bool active;
        size_t active_requests;
    } connections[CONNECTION_POOL_MAX];
    SSL *ssl;
    SSL_CTX *ssl_ctx;
    char token[SPOTIFY_TOKEN_HEADER_PREFIX_LEN + SPOTIFY_TOKEN_LEN + 1 /* +1 for null byte */];

    //Token refresh connection
    struct connection token_connection;
    SSL *token_ssl;
    SSL_CTX *token_ssl_ctx;
};

struct pools {
    struct session_pool session_pool;
    struct http_connection_pool http_connection_pool;
};

struct request_state {
    size_t response_size;
    struct evbuffer *output;
    struct connection *connection;
    struct http_connection_pool *pool;
    char request[URI_MAX_LEN];
    char token[SPOTIFY_TOKEN_HEADER_PREFIX_LEN + SPOTIFY_TOKEN_LEN + 1 /* +1 for null byte */];
    struct write_job write_jobs[MAX_WRITE_JOBS];
    FILE *fp;
    int write_job_index;
};

static void
audio_read_cb(int fd, short what, void *arg);

int dispatch_request_state(struct request_state *state);

struct credentials *get_credentials();

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

void
write_error_spotify(struct bufferevent *bev) {
    write_error(bev, ET_SPOTIFY, librespotc_last_errmsg());
}

static void
err_openssl(const char *func) {
    fprintf(stderr, "%s failed:\n", func);

    /* This is the OpenSSL function that prints the contents of the
     * error stack to the specified file handle. */
    ERR_print_errors_fp(stderr);

    exit(1);
}

/* See http://archives.seul.org/libevent/users/Jan-2013/msg00039.html */
static int cert_verify_callback(X509_STORE_CTX *x509_ctx, void *arg) {
    char cert_str[256];
    const char *host = (const char *) arg;
    const char *res_str = "X509_verify_cert failed";
    HostnameValidationResult res = Error;

    /* This is the function that OpenSSL would call if we hadn't called
     * SSL_CTX_set_cert_verify_callback().  Therefore, we are "wrapping"
     * the default functionality, rather than replacing it. */
    int ok_so_far;

    X509 *server_cert = NULL;

    ok_so_far = X509_verify_cert(x509_ctx);

    server_cert = X509_STORE_CTX_get_current_cert(x509_ctx);

    if (ok_so_far) {
        res = validate_hostname(host, server_cert);

        switch (res) {
            case MatchFound:
                break;
            case MatchNotFound:
                res_str = "MatchNotFound";
                break;
            case NoSANPresent:
                res_str = "NoSANPresent";
                break;
            case MalformedCertificate:
                res_str = "MalformedCertificate";
                break;
            case Error:
                res_str = "Error";
                break;
            default:
                res_str = "WTF!";
                break;
        }
    }

    X509_NAME_oneline(X509_get_subject_name(server_cert),
                      cert_str, sizeof(cert_str));

    if (res == MatchFound) {
        printf("https server '%s' has this certificate, "
               "which looks good to me:\n%s\n",
               host, cert_str);
        return 1;
    } else {
        printf("Got '%s' for hostname '%s' and certificate:\n%s\n",
               res_str, host, cert_str);
        return 0;
    }
}

static void
token_get_completed_cb(struct evhttp_request *req, void *arg) {
    printf("Got token response: %d %s\n", req->response_code, req->response_code_line);
    struct request_state *state = (struct request_state *) arg;

    struct evbuffer *buf = evhttp_request_get_input_buffer(req);
    struct evbuffer_ptr ptr = evbuffer_search(buf, "\"accessToken\":\"", 15, NULL);
    evbuffer_ptr_set(buf, &ptr, 15, EVBUFFER_PTR_ADD);
    evbuffer_copyout_from(buf, &ptr, &state->pool->token[SPOTIFY_TOKEN_HEADER_PREFIX_LEN], SPOTIFY_TOKEN_LEN);
    printf("Got token: %s\n", state->pool->token);
    dispatch_request_state(state);
}

static void
http_get_no_cache_cb(struct evhttp_request *req, void *arg) {
    struct request_state *state = (struct request_state *) arg;

    if (req == NULL) {
        printf("timed out!\n");
        return;
    } else if (req->response_code == 0) {
        printf("connection refused!\n");
        return;
    } else if (req->response_code != 200) {
        printf("error: %u %s\n", req->response_code, req->response_code_line);
        return;
    }

    if (!state->response_size) {
        const char *clens = evhttp_find_header(req->input_headers, "content-length");
        char *end = NULL;
        state->response_size = strtoll(clens, &end, 10);
        printf("Send expected response size: %zu\n", state->response_size);
        enum error_type no_err = ET_NO_ERROR;
        evbuffer_add(state->output, &no_err, 1);
        evbuffer_add(state->output, &state->response_size, sizeof(state->response_size));
    }
    evbuffer_add_buffer(state->output, evhttp_request_get_input_buffer(req));
}

static void
http_get_cb(struct evhttp_request *req, void *arg) {
    struct request_state *state = (struct request_state *) arg;
    struct evbuffer *output = state->output;

    if (req == NULL || req->response_code != 200) {
        return;
    }

    struct write_job *wj = &state->write_jobs[state->write_job_index++];
    if (state->write_job_index >= MAX_WRITE_JOBS) state->write_job_index = 0;
    while (aio_error(&wj->cb) == EINPROGRESS) {} // Wait for write job to finish if still in progress

    int offset = 0;
    if (!state->response_size) {
        const char *clens = evhttp_find_header(req->input_headers, "content-length");
        char *end = NULL;
        state->response_size = strtoll(clens, &end, 10);
        printf("Send expected response size: %zu\n", state->response_size);

        offset = sizeof(state->response_size) + 1;
        enum error_type no_err = ET_NO_ERROR;
        memcpy(wj->tmp, &no_err, 1);
        memcpy(&wj->tmp[1], &state->response_size, sizeof(state->response_size));
    }
    struct evbuffer *req_data = evhttp_request_get_input_buffer(req);

    size_t got = evbuffer_copyout(req_data, &wj->tmp[offset], MAX_BYTES_PER_READ - offset);

    evbuffer_add(output, wj->tmp, got + offset);

    wj->cb.aio_buf = wj->tmp;
    wj->cb.aio_nbytes = got + offset;
    aio_write(&wj->cb);
}

static void
http_connection_close(struct evhttp_connection *connection, void *arg) {
    struct connection *conn = (struct connection *) arg;
    conn->active = false;
}

static void
http_get_complete_cb(struct evhttp_request *req, void *arg) {
    struct request_state *state = (struct request_state *) arg;
    if (req == NULL) {
        printf("timed out!\n");
        write_error_evb(state->output, ET_HTTP, "timed out!");
    } else if (req->response_code == 0) {
        printf("connection refused!\n");
        write_error_evb(state->output, ET_HTTP, "connection refused!");
    } else if (req->response_code == 401) { // Token expired, get new one

        if (strcmp(state->token, state->pool->token) != 0) {
            dispatch_request_state(state);
            return; // Token has changed since the request was made
        }

        printf("access token expired, getting new one\n");

        if (!state->pool->token_connection.active) {
            struct event_base *base = evhttp_connection_get_base(state->connection->connection);
            state->pool->token_connection.bev = bufferevent_openssl_socket_new(base, -1, state->pool->token_ssl,
                                                                               BUFFEREVENT_SSL_CONNECTING,
                                                                               BEV_OPT_CLOSE_ON_FREE |
                                                                               BEV_OPT_DEFER_CALLBACKS);
            bufferevent_openssl_set_allow_dirty_shutdown(state->pool->token_connection.bev, 1);

            state->pool->token_connection.connection = evhttp_connection_base_bufferevent_new(base, NULL,
                                                                                              state->pool->token_connection.bev,
                                                                                              SPOTIFY_TOKEN_HOST,
                                                                                              HTTPS_PORT);
            evhttp_connection_set_family(state->pool->token_connection.connection, AF_INET);
            evhttp_connection_set_closecb(state->pool->token_connection.connection, http_connection_close,
                                          &state->pool->token_connection);
            state->pool->token_connection.active = true;
        }

        struct evhttp_request *token_req = evhttp_request_new(token_get_completed_cb, arg);
        evhttp_add_header(token_req->output_headers, "Host", SPOTIFY_TOKEN_HOST);
        evhttp_add_header(token_req->output_headers, "User-Agent",
                          "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0");
        evhttp_add_header(token_req->output_headers, "Accept", "*/*");

        evhttp_make_request(state->pool->token_connection.connection, token_req, EVHTTP_REQ_GET, "/");
        return;
    } else if (req->response_code != 200) {
        write_error_evb(state->output, ET_HTTP, req->response_code_line);
    }
    if (state->fp) {
        for (int i = 0; i < MAX_WRITE_JOBS; ++i) { // Wait for all write jobs to finish
            while (aio_error(&state->write_jobs[i].cb) == EINPROGRESS) {}
        }
        fclose(state->fp);
    }
    free(arg);
}

int
dispatch_request_state(struct request_state *state) {
    struct evhttp_request *req = evhttp_request_new(http_get_complete_cb, state);
    evhttp_add_header(req->output_headers, "Connection", "keep-alive");
    evhttp_add_header(req->output_headers, "Host", SPOTIFY_API_HOST);
    evhttp_add_header(req->output_headers, "Authorization", state->pool->token);
    req->chunk_cb = state->fp ? http_get_cb : http_get_no_cache_cb;
    req->cb_arg = state;

    evhttp_make_request(state->connection->connection, req, EVHTTP_REQ_GET, state->request);
    return 0;
}

int
dispatch_request(struct http_connection_pool *pool, const char *uri_in, struct bufferevent *bev, FILE *fp) {
    struct event_base *base = bufferevent_get_base(bev);

    struct connection *connection;
    {
        size_t min_index, min_amount = -1, inactive = -1;
        for (int i = 0; i < CONNECTION_POOL_MAX; ++i) {
            if (pool->connections[i].active && pool->connections[i].active_requests < min_amount) {
                min_amount = pool->connections[i].active_requests;
                min_index = i;
            } else if (!pool->connections[i].active && inactive == (size_t) -1) {
                inactive = i;
            }
        }
        if (min_amount < MAX_REQUESTS || inactive == (size_t) -1) {
            connection = &pool->connections[min_index];
        } else {
            connection = &pool->connections[inactive];
        }
    }


    if (!connection->active) {
        printf("Activated new connection\n");
        connection->bev = bufferevent_openssl_socket_new(base, -1, pool->ssl,
                                                         BUFFEREVENT_SSL_CONNECTING,
                                                         BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
        bufferevent_openssl_set_allow_dirty_shutdown(connection->bev, 1);

        connection->connection = evhttp_connection_base_bufferevent_new(base, NULL, connection->bev, SPOTIFY_API_HOST,
                                                                        HTTPS_PORT);
        evhttp_connection_set_family(connection->connection, AF_INET);
        evhttp_connection_set_closecb(connection->connection, http_connection_close, connection);
        connection->active = true;
    }

    struct request_state *state = calloc(1, sizeof(*state));
    state->output = bufferevent_get_output(bev);
    state->connection = connection;
    state->pool = pool;
    memcpy(state->request, uri_in, (strlen(uri_in) + 1) > URI_MAX_LEN ? URI_MAX_LEN : (strlen(uri_in) + 1));
    memcpy(state->token, pool->token, sizeof(pool->token));
    if (fp) {
        state->fp = fp;
        for (int i = 0; i < MAX_WRITE_JOBS; ++i) {
            state->write_jobs[i].cb.aio_fildes = fileno(fp);
        }
    }

    struct evhttp_request *req = evhttp_request_new(http_get_complete_cb, state);
    evhttp_add_header(req->output_headers, "Connection", "keep-alive");
    evhttp_add_header(req->output_headers, "Host", SPOTIFY_API_HOST);
    req->chunk_cb = state->fp ? http_get_cb : http_get_no_cache_cb;
    req->cb_arg = state;

    evhttp_make_request(connection->connection, req, EVHTTP_REQ_GET, uri_in);
    return 0;
}

void
clean_element(struct element *element) {
    if (!element) return;
    if (element->active && element->session) {
        librespotc_close(element->session);
    }
    vec_free(&element->bev_vec);
    if (element->read_ev) event_free(element->read_ev);
    if (element->cache_fp) fclose(element->cache_fp);
    free(element->path);
    memset(element, 0, sizeof(*element));
}

//TODO: Pretty sure this doesn't work
/*static void
session_error(
        struct sp_session *session, enum sp_error err,
        void *userp) { // On session error, create a new session in its place and continue playing the previous song
    if (err == SP_ERR_NOCONNECTION) return;
    printf("Session error detected, reconnecting\n");
    struct element *element = (struct element *) userp;

    if (element->read_ev) event_free(element->read_ev);

    librespotc_close(element->session);
    librespotc_logout(element->session); // Log out just in case

    if (!element->active) { // Clean if not in use
        clean_element(element);
        return;
    }
    // Log back in
    struct credentials *creds = get_credentials();
    printf("Creating new session as %s\n", creds->creds.username);
    if (creds->creds.stored_cred_len == 0) {
        element->session = librespotc_login_password(creds->creds.username,
                                                     creds->creds.password, NULL);
    } else {
        element->session = librespotc_login_stored_cred(creds->creds.username,
                                                        creds->creds.stored_cred,
                                                        creds->creds.stored_cred_len, NULL);
    }
    if (!element->session) {
        fprintf(stderr, "Error creating librespot session: %s\n", librespotc_last_errmsg());
        return;
    }
    creds->uses++;
    char id[23];
    memcpy(id, element->id, sizeof(element->id));
    int fd = librespotc_open(id, element->session);

    element->read_ev = event_new(element->base, fd, EV_READ | EV_PERSIST, audio_read_cb, element);
    event_add(element->read_ev, NULL);

    librespotc_seek(element->session, element->progress);
    librespotc_write(element->session, NULL, NULL);
}*/

struct credentials *
get_credentials() {
    for (int i = 0; i < credentials_count; ++i) {
        if (++credentials_last_index >= credentials_count) credentials_last_index = 0;
        if (credentials[credentials_last_index].uses <= MAX_CREDENTIAL_USES)
            return &credentials[credentials_last_index];
    }
    return NULL;
}

void
finish_seek_cb(int ret, void *userp) {
    struct element *element = (struct element *) userp;
    struct event_base *base = element->base;

    memset(element->write_jobs, 0, sizeof(element->write_jobs));
    for (int i = 0; i < MAX_WRITE_JOBS; ++i) {
        element->write_jobs[i].cb.aio_fildes = fileno(element->cache_fp);
    }
    element->read_ev = event_new(base, librespotc_get_session_fd(element->session), EV_READ | EV_PERSIST, audio_read_cb,
                                 element);
    event_add(element->read_ev, NULL);

    librespotc_write(element->session, NULL, NULL);
    if (element->progress) printf("Continuing sending data for '%s' starting at %zu\n", element->id, element->progress);
    else
        printf("Sending data for '%s'\n", element->id);
}

void
spotify_file_open_cb(int fd, void *userp) {
    struct element *element = (struct element *) userp;

    if (fd < 0) {
        for (int i = 0; i < element->bev_vec.len; ++i) {
            write_error_spotify(element->bev_vec.el[i]);
        }
        return;
    }

    printf("Opened spotify track (%d)\n", fd);

    element->cache_fp = fopen(element->path, "a");
    if (element->progress) {
        librespotc_seek(element->session, element->progress, finish_seek_cb, userp);
        return;
    }
    size_t file_len = librespotc_get_filelen(element->session);
    enum error_type no_err = ET_NO_ERROR;
    for (int i = 0; i < element->bev_vec.len; ++i) {
        bufferevent_write(element->bev_vec.el[i], &no_err, 1);
        bufferevent_write(element->bev_vec.el[i], &file_len, sizeof(file_len));
    }
    fwrite(&no_err, 1, 1, element->cache_fp);
    fwrite(&file_len, sizeof(file_len), 1, element->cache_fp);
    fflush(element->cache_fp);
    finish_seek_cb(0, userp);
}

void
session_cb(int ret, void *userp) {
    struct element *element = (struct element *) userp;

    if (!element->session) {
        fprintf(stderr, "Error creating librespot session: %s\n", librespotc_last_errmsg());
        return;
    }
    printf("Created spotify session (%d)\n", ret);

    int r = librespotc_open(element->id, element->session, spotify_file_open_cb, userp);
    if (r) {
        fprintf(stderr, "Error when calling librespotc_open: %s\n", librespotc_last_errmsg());
    }
}

struct element *
activate_session(struct session_pool *pool, size_t progress, char *id, char *path,
                 struct bufferevent *bev) {

    int uninit = -1;
    for (int i = 0; i < SESSION_POOL_MAX; ++i) {
        if (!pool->elements[i].active) {
            if (pool->elements[i].session) {
                pool->elements[i].active = true;
                pool->elements[i].progress = progress;
                memcpy(pool->elements[i].id, id, sizeof(pool->elements[i].id));
                pool->elements[i].path = strdup(path);
                vec_init(&pool->elements[i].bev_vec);
                vec_add(&pool->elements[i].bev_vec, bev);
                session_cb(0, &pool->elements[i]);
                return &pool->elements[i]; // Not active and a valid session
            }
            if (uninit == -1) uninit = i;
        }
    }

    if (uninit != -1) {
        struct credentials *creds = get_credentials();
        printf("Creating new session as %s\n", creds->creds.username);
        pool->elements[uninit].progress = progress;
        vec_init(&pool->elements[uninit].bev_vec);
        vec_add(&pool->elements[uninit].bev_vec, bev);
        pool->elements[uninit].path = strdup(path);
        pool->elements[uninit].base = bufferevent_get_base(bev);
        pool->elements[uninit].read_ev = NULL;
        pool->elements[uninit].active = true;
        memcpy(pool->elements[uninit].id, id, sizeof(pool->elements[uninit].id));
        if (creds->creds.stored_cred_len == 0) {
            librespotc_login_password(creds->creds.username,
                                      creds->creds.password, &pool->elements[uninit].session, session_cb,
                                      &pool->elements[uninit]);
        } else {
            librespotc_login_stored_cred(creds->creds.username,
                                         creds->creds.stored_cred,
                                         creds->creds.stored_cred_len, &pool->elements[uninit].session, session_cb,
                                         &pool->elements[uninit]);
        }
        creds->uses++;
        return &pool->elements[uninit];
    }
    return NULL;
}

static void
audio_read_cb(int fd, short what, void *arg) {
    struct element *element = (struct element *) arg;
    size_t got;

    struct write_job *wj = &element->write_jobs[element->write_job_index++];
    if (element->write_job_index >= MAX_WRITE_JOBS) element->write_job_index = 0;
    while (aio_error(&wj->cb) == EINPROGRESS) {} // Wait for write job to finish if still in progress

    got = read(fd, wj->tmp, MAX_BYTES_PER_READ);

    if (got <= 0) {
        printf("Playback ended (%zu)\n", got);
        event_free(element->read_ev);
        librespotc_close(element->session);
        element->read_ev = NULL;
        vec_free(&element->bev_vec);
        element->active = false;
        fclose(element->cache_fp);
        element->cache_fp = NULL;
        element->progress = 0;
        return;
    }
    element->progress += got;
    wj->cb.aio_buf = wj->tmp;
    wj->cb.aio_nbytes = got;
    aio_write(&wj->cb);

    for (int i = 0; i < element->bev_vec.len; ++i) {
        bufferevent_write(element->bev_vec.el[i], wj->tmp, got);
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

    uint8_t data;
    evbuffer_remove(input, &data, sizeof(data));
    switch (data) {
        case MUSIC_DATA: {
            char id[23];
            evbuffer_remove(input, id, sizeof(id) - 1);
            id[22] = 0;

            char path[35] = "music_cache/";
            memcpy(&path[12], id, sizeof(id));

            size_t progress = 0;
            if (!access(path, R_OK)) {
                FILE *fp = fopen(path, "r");
                size_t file_len = 0;
                fread(&file_len, 1, sizeof(file_len), fp);
                fseek(fp, 0L, SEEK_END);
                size_t actual_len = ftell(fp);
                rewind(fp);

                int fd = fileno(fp);
                evbuffer_add_file(output, fd, 0, -1);
//                fclose(fp); TODO: Figure out how to close properly
                if (file_len != actual_len - sizeof(file_len)) { // File is fully written
                    struct element *element = NULL;
                    for (int i = 0; i < SESSION_POOL_MAX; ++i) {
                        if (!memcmp(session_pool->elements[i].id, id, sizeof(session_pool->elements[i].id))) {
                            element = &session_pool->elements[i];
                            break;
                        }
                    }
                    if (element) {
                        vec_add(&element->bev_vec, bev);
                        printf("Sending data for '%s' from cache while reading\n", id);
                        return;
                    } else {
                        progress = actual_len - sizeof(file_len);
                    }
                } else {
                    printf("Sending data for '%s' from cache\n", id);
                    return;
                }
            }

            activate_session(session_pool, progress, id, path, bev);
            /*if (!element) {
                bufferevent_write(bev, error_response, sizeof(error_response));
                fprintf(stderr, "Error occurred when getting new session\n");
                write_error(bev, ET_FULL, NULL);
                return;
            }
            element->progress = progress;
            memcpy(element->id, id, sizeof(element->id));
            int fd = librespotc_open(id, element->session);
            if (fd < 0) {
                write_error_spotify(bev);
                return;
            }

            element->cache_fp = fopen(path, "a");
            if (!progress) {
                struct sp_metadata metadata;
                int ret = librespotc_metadata_get(&metadata, element->session);
                if (ret < 0) {
                    write_error_spotify(bev);
                    return;
                }
                enum error_type no_err = ET_NO_ERROR;
                bufferevent_write(bev, &no_err, 1);
                bufferevent_write(bev, &metadata.file_len, sizeof(metadata.file_len));
                fwrite(&no_err, 1, 1, element->cache_fp);
                fwrite(&metadata.file_len, sizeof(metadata.file_len), 1, element->cache_fp);
                fflush(element->cache_fp);
            } else {
                librespotc_seek(element->session, progress);
            }

            element->bevs = calloc(INITIAL_BEVS, sizeof(*element->bevs) * INITIAL_BEVS);
            element->bevs_size = INITIAL_BEVS;
            element->bevs_len = 0;
            add_bev(element, bev);
            memset(element->write_jobs, 0, sizeof(element->write_jobs));
            for (int i = 0; i < MAX_WRITE_JOBS; ++i) {
                element->write_jobs[i].cb.aio_fildes = fileno(element->cache_fp);
            }
            element->read_ev = event_new(base, fd, EV_READ | EV_PERSIST, audio_read_cb, element);
            event_add(element->read_ev, NULL);

            librespotc_write(element->session, NULL, NULL);
            if (progress) printf("Continuing sending data for '%s' starting at %zu\n", id, progress);
            else printf("Sending data for '%s'\n", id);*/
            return;
        }
        case MUSIC_INFO: {
            char id[34] = "/v1/tracks/";
            evbuffer_remove(input, &id[11], 22);
            id[33] = 0;

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
                    dispatch_request(http_connection_pool, id, bev,
                                     NULL); // Cache is still being written, make the request without writing to the cache.
                }                               // Since the API requests are very small in comparison to downloading songs, an
                return;                         // extra request isn't a big deal.
            }
            FILE *fp = fopen(path, "a");

            dispatch_request(http_connection_pool, id, bev, fp);
            return;
        }
        case PLAYLIST_INFO: {
            char id[37] = "/v1/playlists/";
            evbuffer_remove(input, &id[14], 22);
            id[36] = 0;

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
                    dispatch_request(http_connection_pool, id, bev,
                                     NULL); // Cache is still being written, make the request without writing to the cache.
                }                               // Since the API requests are very small in comparison to downloading songs, an
                return;                         // extra request isn't a big deal.
            }
            FILE *fp = fopen(path, "a");

            dispatch_request(http_connection_pool, id, bev, fp);
            return;
        }
        case ALBUM_INFO: {
            char id[34] = "/v1/albums/";
            evbuffer_remove(input, &id[11], 22);
            id[33] = 0;

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
                    dispatch_request(http_connection_pool, id, bev,
                                     NULL); // Cache is still being written, make the request without writing to the cache.
                }                               // Since the API requests are very small in comparison to downloading songs, an
                return;                         // extra request isn't a big deal.
            }
            FILE *fp = fopen(path, "a");

            dispatch_request(http_connection_pool, id, bev, fp);
            return;
        }
        case RECOMMENDATIONS: {

        }
        default:; //Invalid data
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
        if (client_count == 0) { // !!! TEMPORARY AND ONLY FOR TESTING !!!
            event_base_loopexit(bufferevent_get_base(bev), NULL);
        }
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
    int ret = 0;

    client_count = 0;
    if (argc == 2) { // Load credentials from file
        FILE *fp = fopen(argv[1], "r"); // File format is: <email> <password> <username>\n
        fseek(fp, 0L, SEEK_END);
        size_t n = ftell(fp);
        rewind(fp);
        char buffer[n];
        fread(buffer, 1, n, fp);
        fclose(fp);

        size_t credentials_len = n / 71 + 1;
        credentials = calloc(credentials_len, sizeof(*credentials));

        char *nxt = buffer, *nxt1;
        while (1) {
            nxt = strchr(nxt, ' ');
            if (!nxt) break;
            nxt += 1;
            nxt1 = strchr(nxt, ' ');
            if (!nxt1) break;
            if (credentials_len <= credentials_count) {
                struct credentials *tmp = realloc(credentials, (credentials_len + 10) * sizeof(*tmp));
                if (!tmp) {
                    perror("Error when reallocating");
                    return -1;
                }
                credentials = tmp;
                credentials_len += 10;
            }

            memcpy(credentials[credentials_count].creds.password, nxt, nxt1 - nxt);
            nxt1 += 1;
            nxt = strchr(nxt1, '\n');
            if (!nxt) break;
            memcpy(credentials[credentials_count++].creds.username, nxt1, nxt - nxt1);
        }
        if (credentials_len > credentials_count) { // Reallocate credentials to be just the right size
            struct credentials *tmp = realloc(credentials, (credentials_count) * sizeof(*tmp));
            if (!tmp) {
                perror("Error when reallocating");
                return -1;
            }
            credentials = tmp;
        }
        printf("Parsed %zu credentials from %s\n", credentials_count, argv[1]);
    } else { // Load credentials from arguments
        credentials_count = (argc - 1) / 2;
        credentials_last_index = -1;
        credentials = calloc(credentials_count, sizeof(*credentials));
        printf("Detected %zu users from arguments\n", credentials_count);
        for (int i = 0; i < credentials_count; ++i) {
            size_t username_len = strlen(argv[i * 2 + 1]), password_len = strlen(argv[i * 2 + 2]);
            memcpy(credentials[i].creds.username, argv[i * 2 + 1], username_len > 64 ? 64 : username_len);
            memcpy(credentials[i].creds.password, argv[i * 2 + 2], password_len > 32 ? 32 : password_len);
        }
    }

    memset(pool.session_pool.elements, 0, sizeof(pool.session_pool.elements));

    memset(pool.http_connection_pool.connections, 0, sizeof(pool.http_connection_pool.connections));
    memcpy(pool.http_connection_pool.token, "Bearer ", 7);
    pool.http_connection_pool.token[SPOTIFY_TOKEN_HEADER_PREFIX_LEN + SPOTIFY_TOKEN_LEN] = 0;

    memset(&s_sysinfo, 0, sizeof(struct sp_sysinfo));
    snprintf(s_sysinfo.device_id, sizeof(s_sysinfo.device_id), "aabbccddeeff");


    // Initialize OpenSSL
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
    (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L)
    SSL_library_init();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#endif
    pool.http_connection_pool.ssl_ctx = SSL_CTX_new(SSLv23_method());
    if (!pool.http_connection_pool.ssl_ctx) {
        err_openssl("SSL_CTX_new");
        return -1;
    }

    X509_STORE *store;
    /* Attempt to use the system's trusted root certificates. */
    store = SSL_CTX_get_cert_store(pool.http_connection_pool.ssl_ctx);
    if (X509_STORE_set_default_paths(store) != 1) {
        err_openssl("X509_STORE_set_default_paths");
        return -1;
    }
    SSL_CTX_set_verify(pool.http_connection_pool.ssl_ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_cert_verify_callback(pool.http_connection_pool.ssl_ctx, cert_verify_callback,
                                     (void *) SPOTIFY_API_HOST);

    pool.http_connection_pool.ssl = SSL_new(pool.http_connection_pool.ssl_ctx);
    if (pool.http_connection_pool.ssl == NULL) {
        err_openssl("SSL_new()");
        return -1;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    // Set hostname for SNI extension
    SSL_set_tlsext_host_name(pool.http_connection_pool.ssl, SPOTIFY_API_HOST);
#endif

    //Token SSL

    pool.http_connection_pool.token_ssl_ctx = SSL_CTX_new(SSLv23_method());
    if (!pool.http_connection_pool.token_ssl_ctx) {
        err_openssl("SSL_CTX_new");
        return -1;
    }

    X509_STORE *store_token;
    /* Attempt to use the system's trusted root certificates. */
    store_token = SSL_CTX_get_cert_store(pool.http_connection_pool.token_ssl_ctx);
    if (X509_STORE_set_default_paths(store_token) != 1) {
        err_openssl("X509_STORE_set_default_paths");
        return -1;
    }
    SSL_CTX_set_verify(pool.http_connection_pool.token_ssl_ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_cert_verify_callback(pool.http_connection_pool.token_ssl_ctx, cert_verify_callback,
                                     (void *) SPOTIFY_TOKEN_HOST);

    pool.http_connection_pool.token_ssl = SSL_new(pool.http_connection_pool.token_ssl_ctx);
    if (pool.http_connection_pool.token_ssl == NULL) {
        err_openssl("SSL_new()");
        return -1;
    }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    // Set hostname for SNI extension
    SSL_set_tlsext_host_name(pool.http_connection_pool.token_ssl, SPOTIFY_TOKEN_HOST);
#endif
    // End initializing OpenSSL


    pipe(cmds);
    ret = librespotc_init(&s_sysinfo, &callbacks, cmds[1]);
    if (ret < 0) {
        printf("Error initializing Spotify: %s\n", librespotc_last_errmsg());
        return -1;
    }

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

    if (pool.http_connection_pool.ssl_ctx)
        SSL_CTX_free(pool.http_connection_pool.ssl_ctx);
    if (pool.http_connection_pool.ssl)
        SSL_free(pool.http_connection_pool.ssl);
    if (pool.http_connection_pool.token_ssl_ctx)
        SSL_CTX_free(pool.http_connection_pool.token_ssl_ctx);
    if (pool.http_connection_pool.token_ssl)
        SSL_free(pool.http_connection_pool.token_ssl);
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
    (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L)
    EVP_cleanup();
    ERR_free_strings();

#if OPENSSL_VERSION_NUMBER < 0x10000000L
    ERR_remove_state(0);
#else
    ERR_remove_thread_state(NULL);
#endif

    CRYPTO_cleanup_all_ex_data();

    sk_SSL_COMP_free(SSL_COMP_get_compression_methods());
#endif /* (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
	(defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L) */

    for (int i = 0; i < SESSION_POOL_MAX; ++i) {
        clean_element(&pool.session_pool.elements[i]);
    }

    free(credentials);
    librespotc_deinit();
    return 0;
}
