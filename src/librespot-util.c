//
// Created by quartzy on 8/10/22.
//

#include "librespot-util.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <openssl/ssl.h>

#include "debug.h"

static const char data[] = "GET / HTTP/1.1\r\nHost: APResolve.spotify.com\r\nUser-Agent: curl/7.81.0\r\nAccept: */*\r\n\r\n";
static SSL_CTX *ssl_ctx = NULL;

void
hexdump_dummy(const char *msg, uint8_t *mem, size_t len) {}

int
https_get(char **body, const char *host_str) {
    int sock;
    struct addrinfo *addrinfo;
    sock = socket(AF_INET, /* IPV4 protocol. */
                  SOCK_STREAM, /* TCP socket. */
                  0); /* O for socket() function choose the correct protocol based on the socket type. */

    if(sock == -1) return -1;
    struct addrinfo hints = {
            .ai_family = AF_INET,
            .ai_socktype = SOCK_STREAM,
            .ai_protocol = 0,
            .ai_addr = NULL,
            .ai_addrlen = 0,
            .ai_canonname = NULL,
            .ai_flags = 0,
            .ai_next = NULL,
    };

    if(getaddrinfo(host_str, "443", &hints, &addrinfo)) {
        perror("error when resolving host");
        close(sock);
        return -1;
    }

    if(connect(sock, addrinfo->ai_addr, sizeof(*addrinfo->ai_addr)) == -1) {
        perror("error when connecting to apresolve.spotify.com");
        freeaddrinfo(addrinfo);
        close(sock);
        return -1;
    }

    if (!ssl_ctx){
        SSL_load_error_strings();
        SSL_library_init();
        ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    }
    SSL *conn = SSL_new(ssl_ctx);
    SSL_set_fd(conn, sock);

    if (SSL_connect(conn) != 1){
        close(sock);
        SSL_free(conn);
        freeaddrinfo(addrinfo);
        return -1;
    }

    if(SSL_write(conn, data, sizeof(data)) == -1){
        perror("error when writing to socket apresolve.spotify.com");
        freeaddrinfo(addrinfo);
        close(sock);
        SSL_free(conn);
        return -1;
    }

    char buf[4096];
    size_t bytes_read;
    if ((bytes_read = SSL_read(conn, buf, sizeof(buf))) == -1){
        perror("error when reading from socket apresolve.spotify.com");
        freeaddrinfo(addrinfo);
        close(sock);
        SSL_free(conn);
        return -1;
    }
    char *body_start = strstr(buf, "\r\n\r\n");
    body_start += 4;
    size_t body_len = bytes_read-(body_start-buf);

    *body = malloc(body_len+1);
    memcpy(*body, body_start, body_len);
    (*body)[body_len] = 0;

    close(sock);
    SSL_free(conn);
    freeaddrinfo(addrinfo);

    return 0;
}

void
logmsgf(const char *fmt, ...){
    printf("");
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
}

struct sp_callbacks callbacks =
        {
                .https_get = https_get,

                .hexdump  = hexdump_dummy,
                .logmsg   = logmsgf,
        };