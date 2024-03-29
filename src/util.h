//
// Created by quartzy on 4/24/23.
//

#ifndef SMP_BACKEND_UTIL_H
#define SMP_BACKEND_UTIL_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <aio.h>
#define JDM_STACKTRACE
#include <jdm.h>

#define PORT 5394
#define SESSION_POOL_MAX 50
#define MAX_BYTES_PER_READ (1024 * 8 * 2) // Same amount used internally by librespot-c
#define MAX_WRITE_BUFFER_SIZE (1024 * 1024)
#define MAX_CREDENTIAL_USES 5
#define CONNECTION_POOL_MAX 50
#define URI_MAX_LEN 1024
#define SPOTIFY_TOKEN_HEADER_PREFIX_LEN 7
#define SPOTIFY_API_HOST "api.spotify.com"
#define SPOTIFY_TOKEN_HOST "open.spotify.com"
#define SPOTIFY_PARTNER_HOST "api-partner.spotify.com"
#define HTTPS_PORT 443
#define MAX_REQUESTS 5



struct write_job {
    struct aiocb cb;
    char tmp[2][MAX_WRITE_BUFFER_SIZE];
    bool current_buf;
    size_t offset;
};

enum error_type {
    ET_NO_ERROR = 0,
    ET_SPOTIFY = 1,
    ET_SPOTIFY_INTERNAL = 2,
    ET_HTTP = 3,
    ET_FULL = 4
};

void
write_error(int fd, enum error_type err, const char *msg);

size_t get_dir_size(const char *path);

size_t delete_older_files(const char *path, time_t older_than);

// The parameters after size_requirements are all expected to be const char* and the last one should be NULL
size_t delete_oldest_until_size_requirement(size_t size_requirement, ...);

int get_cpu_cores();

bool is_valid_id(uint8_t *id);

int error_message_hook(const char* thread_name, uint32_t stack_trace_count, const char*const* stack_trace, jdm_message_level level, uint32_t line, const char* file, const char* function, const char* message, void* param);

int set_sigsegv_handler();

#endif //SMP_BACKEND_UTIL_H
