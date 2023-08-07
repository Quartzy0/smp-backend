//
// Created by quartzy on 2/7/23.
//

#include "http.h"
#include <event2/bufferevent_ssl.h>
#include <event2/http.h>
#include <event2/http_struct.h>
#include <event2/buffer.h>
#include <unistd.h>
#include <ctype.h>
#include "openssl_hostname_validation.h"

const char SPOTIFY_TOKEN_HEADER_PREFIX[] = "Bearer ";

static int
http_dispatch_request_state(struct request_state *state);

static int
dispatch_all_queued_requests(struct http_connection_pool *pool);

static void
err_openssl(const char *func) {
    JDM_ERROR("%s failed:", func);

    /* This is the OpenSSL function that prints the contents of the
     * error stack to the specified file handle. */
    ERR_print_errors_fp(stderr);

    exit(1);
}

/* See http://archives.seul.org/libevent/users/Jan-2013/msg00039.html */
static int cert_verify_callback(X509_STORE_CTX *x509_ctx, void *arg) {
    JDM_ENTER_FUNCTION;
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
        JDM_LEAVE_FUNCTION;
        return 1;
    } else {
        JDM_WARN("Got '%s' for hostname '%s' and certificate: %s",
               res_str, host, cert_str);
        JDM_LEAVE_FUNCTION;
        return 0;
    }
}

int
http_init_ssl(SSL **ssl, SSL_CTX **ssl_ctx, char *host){
    JDM_ENTER_FUNCTION;
    (*ssl_ctx) = SSL_CTX_new(SSLv23_method());
    if (!(*ssl_ctx)) {
        err_openssl("SSL_CTX_new");
        return -1;
    }

    X509_STORE *store;
    /* Attempt to use the system's trusted root certificates. */
    store = SSL_CTX_get_cert_store((*ssl_ctx));
    if (X509_STORE_set_default_paths(store) != 1) {
        err_openssl("X509_STORE_set_default_paths");
        return -1;
    }
    SSL_CTX_set_verify((*ssl_ctx), SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_cert_verify_callback((*ssl_ctx), cert_verify_callback,
                                     (void *) host);

    (*ssl) = SSL_new((*ssl_ctx));
    if ((*ssl) == NULL) {
        err_openssl("SSL_new()");
        JDM_LEAVE_FUNCTION;
        return -1;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    // Set hostname for SNI extension
    SSL_set_tlsext_host_name((*ssl), host);
#endif
    JDM_LEAVE_FUNCTION;
    return 0;
}

int
http_init(struct http_connection_pool *pool){
    JDM_ENTER_FUNCTION;
    memset(pool->connections, 0, sizeof(pool->connections));
    // Initialize OpenSSL
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
    (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L)
    SSL_library_init();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#endif
    http_init_ssl(&pool->ssl_api, &pool->ssl_ctx_api, SPOTIFY_API_HOST);
    http_init_ssl(&pool->token_ssl, &pool->token_ssl_ctx, SPOTIFY_TOKEN_HOST);
    http_init_ssl(&pool->ssl_partner, &pool->ssl_ctx_partner, SPOTIFY_PARTNER_HOST);
    // End initializing OpenSSL

    vec_init(&pool->queued_requests);
    JDM_LEAVE_FUNCTION;
    return 0;
}

static void
token_get_completed_cb(struct evhttp_request *req, void *arg);

static void
http_connection_close(struct evhttp_connection *connection, void *arg);

void
make_token_request(struct http_connection_pool *pool){
    if (pool->fetching_token) return;
    JDM_ENTER_FUNCTION;
    pool->fetching_token = true;
    if (!pool->token_connection.active) {
        pool->token_connection.bev = bufferevent_openssl_socket_new(pool->base, -1, pool->token_ssl,
                                                                           BUFFEREVENT_SSL_CONNECTING,
                                                                           BEV_OPT_CLOSE_ON_FREE |
                                                                           BEV_OPT_DEFER_CALLBACKS);
        bufferevent_openssl_set_allow_dirty_shutdown(pool->token_connection.bev, 1);

        pool->token_connection.connection = evhttp_connection_base_bufferevent_new(pool->base, NULL,
                                                                                          pool->token_connection.bev,
                                                                                          SPOTIFY_TOKEN_HOST,
                                                                                          HTTPS_PORT);
        evhttp_connection_set_family(pool->token_connection.connection, AF_INET);
        evhttp_connection_set_closecb(pool->token_connection.connection, http_connection_close,
                                      &pool->token_connection);
        pool->token_connection.active = true;
    }

    struct evhttp_request *token_req = evhttp_request_new(token_get_completed_cb, pool);
    evhttp_add_header(token_req->output_headers, "Host", SPOTIFY_TOKEN_HOST);
    evhttp_add_header(token_req->output_headers, "User-Agent",
                      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:78.0) Gecko/20100101 Firefox/78.0");
    evhttp_add_header(token_req->output_headers, "Accept", "*/*");

    evhttp_make_request(pool->token_connection.connection, token_req, EVHTTP_REQ_GET, "/");
    JDM_LEAVE_FUNCTION;
}

static void
token_get_completed_cb(struct evhttp_request *req, void *arg) {
    JDM_ENTER_FUNCTION;
    JDM_TRACE("Got token response: %d %s", req->response_code, req->response_code_line);
    struct http_connection_pool *pool = (struct http_connection_pool *) arg;
    if (req->response_code != 200) goto fail;

    struct evbuffer *buf = evhttp_request_get_input_buffer(req);
    struct evbuffer_ptr ptr = evbuffer_search(buf, "\"accessToken\":\"", 15, NULL);
    if (ptr.pos == -1) goto fail;

    evbuffer_ptr_set(buf, &ptr, 15, EVBUFFER_PTR_ADD);
    struct evbuffer_ptr end_ptr = evbuffer_search(buf, "\"", 1, &ptr);
    if (end_ptr.pos == -1) goto fail;

    size_t token_len = (end_ptr.pos-ptr.pos) + SPOTIFY_TOKEN_HEADER_PREFIX_LEN + 1;
    if (pool->token_len != token_len){
        free(pool->token);
        pool->token = NULL;
        pool->token_len = 0;
    }
    if (!pool->token){
        pool->token = malloc(token_len);
        pool->token_len = token_len;
    }
    evbuffer_copyout_from(buf, &ptr, &pool->token[SPOTIFY_TOKEN_HEADER_PREFIX_LEN], token_len - SPOTIFY_TOKEN_HEADER_PREFIX_LEN - 1);
    pool->token[token_len-1] = 0;
    memcpy(pool->token, SPOTIFY_TOKEN_HEADER_PREFIX, SPOTIFY_TOKEN_HEADER_PREFIX_LEN);
    pool->fetching_token = false;

    JDM_TRACE("Got token: %s", pool->token);
    dispatch_all_queued_requests(pool);
    JDM_LEAVE_FUNCTION;
    return;

    fail:
    JDM_TRACE("Unable to get token, retrying");
    pool->fetching_token = false;
    make_token_request(pool);
    JDM_LEAVE_FUNCTION;
}

static int
dispatch_request_state_on_token(struct http_connection_pool *pool, struct request_state *state) {
    JDM_ENTER_FUNCTION;
    if (pool->token){
        JDM_LEAVE_FUNCTION;
        return http_dispatch_request_state(state);
    }else {
        make_token_request(pool);
    }

    if (pool->fetching_token)
        vec_add(&pool->queued_requests, state);
    JDM_LEAVE_FUNCTION;
    return 1;
}

static int
dispatch_all_queued_requests(struct http_connection_pool *pool){
    JDM_ENTER_FUNCTION;
    int ret = (int) pool->queued_requests.len;
    for (int i = 0; i < pool->queued_requests.len; ++i) {
        struct request_state *state = (struct request_state*) pool->queued_requests.el[i];
        state->token = pool->token;
        http_dispatch_request_state(state);
    }
    vec_remove_all(&pool->queued_requests);
    JDM_LEAVE_FUNCTION;
    return ret;
}

static void
http_get_no_cache_cb(struct evhttp_request *req, void *arg) {
    JDM_ENTER_FUNCTION;
    struct request_state *state = (struct request_state *) arg;

    if (req == NULL) {
        JDM_WARN("Timed out when making http request!");
        JDM_LEAVE_FUNCTION;
        return;
    } else if (req->response_code == 0) {
        JDM_WARN("Connection refused when making http request!");
        JDM_LEAVE_FUNCTION;
        return;
    } else if (req->response_code != 200) {
        JDM_WARN("Error with http request: %u %s", req->response_code, req->response_code_line);
        JDM_LEAVE_FUNCTION;
        return;
    }

    if (!state->response_size) {
        const char *clens = evhttp_find_header(req->input_headers, "content-length");
        char *end = NULL;
        state->response_size = strtoll(clens, &end, 10);
        JDM_TRACE("Send expected response size: %zu", state->response_size);
        static const enum error_type no_err = ET_NO_ERROR;
        write(state->out_fd, &no_err, 1);
        write(state->out_fd, &state->response_size, sizeof(state->response_size));
    }
    struct evbuffer *b = evhttp_request_get_input_buffer(req);
    evbuffer_write(b, state->out_fd);
    JDM_LEAVE_FUNCTION;
}

static void
http_get_cb(struct evhttp_request *req, void *arg) {
    struct request_state *state = (struct request_state *) arg;

    if (req == NULL || req->response_code != 200) {
        return;
    }
    JDM_ENTER_FUNCTION;

    struct write_job *wj = &state->write_job;

    int offset = 0;
    if (!state->response_size) {
        const char *clens = evhttp_find_header(req->input_headers, "content-length");
        char *end = NULL;
        state->response_size = strtoll(clens, &end, 10);
        JDM_TRACE("Send expected response size: %zu", state->response_size);

        offset = sizeof(state->response_size) + 1;
        static const enum error_type no_err = ET_NO_ERROR;
        memcpy(&wj->tmp[wj->current_buf][wj->offset], &no_err, 1);
        memcpy(&wj->tmp[wj->current_buf][wj->offset+1], &state->response_size, sizeof(state->response_size));
    }
    struct evbuffer *req_data = evhttp_request_get_input_buffer(req);

    size_t got = evbuffer_copyout(req_data, &wj->tmp[wj->current_buf][wj->offset+offset], MAX_BYTES_PER_READ - offset);

    write(state->out_fd, &wj->tmp[wj->current_buf][wj->offset], got + offset);

    if(MAX_WRITE_BUFFER_SIZE - (wj->offset + got + offset) < MAX_BYTES_PER_READ * 2) {
        while (aio_error(&wj->cb) == EINPROGRESS) {} // Wait for write job to finish if still in progress
        wj->cb.aio_buf = wj->tmp[wj->current_buf];
        wj->cb.aio_nbytes = wj->offset + got + offset;
        aio_write(&wj->cb);
        wj->offset = 0;
        wj->current_buf = !wj->current_buf;
    }else{
        wj->offset += got + offset;
    }
    JDM_LEAVE_FUNCTION;
}

static void
http_connection_close(struct evhttp_connection *connection, void *arg) {
    struct connection *conn = (struct connection *) arg;
    conn->active = false;
}

static void
http_get_complete_cb(struct evhttp_request *req, void *arg) {
    JDM_ENTER_FUNCTION;
    struct request_state *state = (struct request_state *) arg;
    if (req == NULL) {
        JDM_WARN("Timed out when making http request!");
        write_error(state->out_fd, ET_HTTP, "timed out!");
    } else if (req->response_code == 0) {
        JDM_WARN("Connection refused when making http request!");
        write_error(state->out_fd, ET_HTTP, "connection refused!");
    } else if (req->response_code == 401) { // Token expired, get new one

        if (state->token && state->pool->token && strcmp(state->token, state->pool->token) != 0) {
            http_dispatch_request_state(state);
            return; // Token has changed since the request was made
        }

        JDM_TRACE("access token expired, getting new one");

        vec_add(&state->pool->queued_requests, state);
        make_token_request(state->pool);
        return;
    } else if (req->response_code != 200) {
        write_error(state->out_fd, ET_HTTP, req->response_code_line);
    }
    if (state->fp) {
        struct write_job *wj = &state->write_job;
        while (aio_error(&wj->cb) == EINPROGRESS) {}
        if (wj->offset){
            wj->cb.aio_buf = wj->tmp[wj->current_buf];
            wj->cb.aio_nbytes = wj->offset;
            aio_write(&wj->cb);
            wj->offset = 0;
            wj->current_buf = !wj->current_buf;
            while (aio_error(&wj->cb) == EINPROGRESS) {}
        }
        fclose(state->fp);
    }
    struct evbuffer *b = evhttp_request_get_input_buffer(req);
    evbuffer_write(b, state->out_fd);
    if (state->cb) state->cb(state->out_fd, state->userp);
    free(arg);
    JDM_LEAVE_FUNCTION;
}

static int
http_dispatch_request_state(struct request_state *state) {
    JDM_ENTER_FUNCTION;
    struct evhttp_request *req = evhttp_request_new(http_get_complete_cb, state);
    evhttp_add_header(req->output_headers, "Connection", "keep-alive");
    evhttp_add_header(req->output_headers, "Host", state->api ? SPOTIFY_API_HOST : SPOTIFY_PARTNER_HOST);
    evhttp_add_header(req->output_headers, "Authorization", state->pool->token);
    req->chunk_cb = state->fp ? http_get_cb : http_get_no_cache_cb;
    req->cb_arg = state;

    evhttp_make_request(state->connection->connection, req, EVHTTP_REQ_GET, state->request);
    JDM_LEAVE_FUNCTION;
    return 0;
}

int
http_dispatch_request(struct http_connection_pool *pool, const char *uri_in, int fd, FILE *fp, SSL *ssl,
                      const char *host, bool api, http_request_finished_cb cb, void *userp) {
    JDM_ENTER_FUNCTION;
    struct event_base *base = pool->base;

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
        JDM_TRACE("Activated new http connection");
        connection->bev = bufferevent_openssl_socket_new(base, -1, ssl,
                                                        BUFFEREVENT_SSL_CONNECTING,
                                                         BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
        bufferevent_openssl_set_allow_dirty_shutdown(connection->bev, 1);

        connection->connection = evhttp_connection_base_bufferevent_new(base, NULL, connection->bev, host,
                                                                        HTTPS_PORT);
        evhttp_connection_set_family(connection->connection, AF_INET);
        evhttp_connection_set_closecb(connection->connection, http_connection_close, connection);
        connection->active = true;
    }

    struct request_state *state = calloc(1, sizeof(*state));
    state->out_fd = fd;
    state->connection = connection;
    state->pool = pool;
    state->api = api;
    state->cb = cb;
    state->userp = userp;
    memcpy(state->request, uri_in, (strlen(uri_in) + 1) > URI_MAX_LEN ? URI_MAX_LEN : (strlen(uri_in) + 1));
    state->token = pool->token;
    if (fp) {
        state->fp = fp;
        state->write_job.cb.aio_fildes = fileno(fp);
    }

    dispatch_request_state_on_token(pool, state);
    JDM_LEAVE_FUNCTION;
    return 0;
}

void
http_cleanup(struct http_connection_pool *pool){
    JDM_ENTER_FUNCTION;
    if (pool->ssl_ctx_api)
        SSL_CTX_free(pool->ssl_ctx_api);
    if (pool->ssl_api)
        SSL_free(pool->ssl_api);
    if (pool->token_ssl_ctx)
        SSL_CTX_free(pool->token_ssl_ctx);
    if (pool->token_ssl)
        SSL_free(pool->token_ssl);
    if (pool->ssl_ctx_partner)
        SSL_CTX_free(pool->ssl_ctx_partner);
    if (pool->ssl_partner)
        SSL_free(pool->ssl_partner);
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

    free(pool->token);
    vec_free(&pool->queued_requests);
    JDM_LEAVE_FUNCTION;
}

// to_hex & urlencode from https://www.geekhideout.com/urlcode.shtml
/* Converts an integer value to its hex character*/
char to_hex(char code) {
    static char hex[] = "0123456789abcdef";
    return hex[code & 15];
}

/* Returns a url-encoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *
urlencode(const char *src, int len) {
    char *buf = malloc(len * 3 + 1), *pbuf = buf;
    for(int i = 0; i < len; i++) {
        if (isalnum(src[i]) || src[i] == '-' || src[i] == '_' || src[i] == '.' || src[i] == '~')
            *pbuf++ = src[i];
        else
            *pbuf++ = '%', *pbuf++ = to_hex((char) (src[i] >> 4)), *pbuf++ = to_hex((char) (src[i] & 15));
    }
    *pbuf = '\0';
    return buf;
}

void http_set_base(struct event_base *base, struct http_connection_pool *pool) {
    pool->base = base;
}
