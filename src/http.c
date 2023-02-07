//
// Created by quartzy on 2/7/23.
//

#include "http.h"
#include "defs.h"
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/http.h>
#include <event2/http_struct.h>
#include <event2/buffer.h>
#include "openssl_hostname_validation.h"

const char SPOTIFY_TOKEN_HEADER_PREFIX[] = "Bearer ";

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

int
http_init(struct http_connection_pool *pool){
    memset(pool->connections, 0, sizeof(pool->connections));
    // Initialize OpenSSL
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
    (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L)
    SSL_library_init();
    ERR_load_crypto_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#endif
    pool->ssl_ctx = SSL_CTX_new(SSLv23_method());
    if (!pool->ssl_ctx) {
        err_openssl("SSL_CTX_new");
        return -1;
    }

    X509_STORE *store;
    /* Attempt to use the system's trusted root certificates. */
    store = SSL_CTX_get_cert_store(pool->ssl_ctx);
    if (X509_STORE_set_default_paths(store) != 1) {
        err_openssl("X509_STORE_set_default_paths");
        return -1;
    }
    SSL_CTX_set_verify(pool->ssl_ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_cert_verify_callback(pool->ssl_ctx, cert_verify_callback,
                                     (void *) SPOTIFY_API_HOST);

    pool->ssl = SSL_new(pool->ssl_ctx);
    if (pool->ssl == NULL) {
        err_openssl("SSL_new()");
        return -1;
    }

#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    // Set hostname for SNI extension
    SSL_set_tlsext_host_name(pool->ssl, SPOTIFY_API_HOST);
#endif

    //Token SSL

    pool->token_ssl_ctx = SSL_CTX_new(SSLv23_method());
    if (!pool->token_ssl_ctx) {
        err_openssl("SSL_CTX_new");
        return -1;
    }

    X509_STORE *store_token;
    /* Attempt to use the system's trusted root certificates. */
    store_token = SSL_CTX_get_cert_store(pool->token_ssl_ctx);
    if (X509_STORE_set_default_paths(store_token) != 1) {
        err_openssl("X509_STORE_set_default_paths");
        return -1;
    }
    SSL_CTX_set_verify(pool->token_ssl_ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_cert_verify_callback(pool->token_ssl_ctx, cert_verify_callback,
                                     (void *) SPOTIFY_TOKEN_HOST);

    pool->token_ssl = SSL_new(pool->token_ssl_ctx);
    if (pool->token_ssl == NULL) {
        err_openssl("SSL_new()");
        return -1;
    }
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
    // Set hostname for SNI extension
    SSL_set_tlsext_host_name(pool->token_ssl, SPOTIFY_TOKEN_HOST);
#endif
    // End initializing OpenSSL
}

static void
token_get_completed_cb(struct evhttp_request *req, void *arg) {
    printf("Got token response: %d %s\n", req->response_code, req->response_code_line);
    struct request_state *state = (struct request_state *) arg;

    struct evbuffer *buf = evhttp_request_get_input_buffer(req);
    struct evbuffer_ptr ptr = evbuffer_search(buf, "\"accessToken\":\"", 15, NULL);
    if (ptr.pos != -1){
        evbuffer_ptr_set(buf, &ptr, 15, EVBUFFER_PTR_ADD);
        struct evbuffer_ptr end_ptr = evbuffer_search(buf, "\"", 1, &ptr);
        if (end_ptr.pos == -1) goto fail;
        size_t token_len = (end_ptr.pos-ptr.pos) + SPOTIFY_TOKEN_HEADER_PREFIX_LEN + 1;
        if (state->pool->token_len != token_len){
            free(state->pool->token);
            state->pool->token = NULL;
            state->pool->token_len = 0;
        }
        if (!state->pool->token){
            state->pool->token = malloc(token_len);
            state->pool->token_len = token_len;
        }
        evbuffer_copyout_from(buf, &ptr, &state->pool->token[SPOTIFY_TOKEN_HEADER_PREFIX_LEN], token_len - SPOTIFY_TOKEN_HEADER_PREFIX_LEN - 1);
        state->pool->token[token_len-1] = 0;
        memcpy(state->pool->token, SPOTIFY_TOKEN_HEADER_PREFIX, SPOTIFY_TOKEN_HEADER_PREFIX_LEN);
        state->token = state->pool->token;
        printf("Got token: %s\n", state->pool->token);
    }else{
        fail:
        printf("Unable to get token\n");
    }
    http_dispatch_request_state(state);
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

        if (state->token && state->pool->token && strcmp(state->token, state->pool->token) != 0) {
            http_dispatch_request_state(state);
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
http_dispatch_request_state(struct request_state *state) {
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
http_dispatch_request(struct http_connection_pool *pool, const char *uri_in, struct bufferevent *bev, FILE *fp) {
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
    state->token = pool->token;
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
http_cleanup(struct http_connection_pool *pool){
    if (pool->ssl_ctx)
        SSL_CTX_free(pool->ssl_ctx);
    if (pool->ssl)
        SSL_free(pool->ssl);
    if (pool->token_ssl_ctx)
        SSL_CTX_free(pool->token_ssl_ctx);
    if (pool->token_ssl)
        SSL_free(pool->token_ssl);
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
}