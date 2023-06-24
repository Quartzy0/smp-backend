//
// Created by quartzy on 8/10/22.
//

#include "librespot-util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <event2/buffer.h>
#include <curl/curl.h>
#include "debug.h"

void
hexdump_dummy(const char *msg, uint8_t *mem, size_t len) {}

size_t
https_write_cb(char *data, size_t size, size_t nmemb, void *userdata) {
    char **body;
    size_t realsize;

    realsize = size * nmemb;
    body = (char **) userdata;

    *body = malloc(realsize + 1);
    memcpy(*body, data, realsize);
    (*body)[realsize] = 0;

    return realsize;
}

int
https_get(char **body, const char *url) {
    CURL *curl;
    CURLcode res;
    long response_code;

    curl = curl_easy_init();
    if (!curl) {
        printf("Could not initialize CURL\n");
        goto error;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, https_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, body);

    res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        printf("CURL could not make request (%d)\n", (int) res);
        goto error;
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (response_code != 200) {
        printf("HTTP response code %d\n", (int) response_code);
        goto error;
    }

    curl_easy_cleanup(curl);

    return 0;

    error:
    curl_easy_cleanup(curl);
    return -1;
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