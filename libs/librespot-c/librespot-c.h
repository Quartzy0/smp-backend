#ifndef __LIBRESPOT_C_H__
#define __LIBRESPOT_C_H__

#include <inttypes.h>
#include <stddef.h>
#include <pthread.h>
#include <event2/event.h>
#include "../../src/cmd.h"

#define LIBRESPOT_C_VERSION_MAJOR 0
#define LIBRESPOT_C_VERSION_MINOR 1


struct sp_session;

enum sp_error {
    SP_OK_OTHER = 3,
    SP_OK_WAIT = 2,
    SP_OK_DATA = 1,
    SP_OK_DONE = 0,
    SP_ERR_OOM = -1,
    SP_ERR_INVALID = -2,
    SP_ERR_DECRYPTION = -3,
    SP_ERR_WRITE = -4,
    SP_ERR_NOCONNECTION = -5,
    SP_ERR_OCCUPIED = -6,
    SP_ERR_NOSESSION = -7,
    SP_ERR_LOGINFAILED = -8,
    SP_ERR_TIMEOUT = -9,
};

enum sp_bitrates {
    SP_BITRATE_ANY,
    SP_BITRATE_96,
    SP_BITRATE_160,
    SP_BITRATE_320,
};

typedef void (*sp_progress_cb)(int fd, void *arg, size_t received, size_t len);

typedef void (*sp_error_callback)(struct sp_session *session, enum sp_error err, void *userp);

struct sp_credentials {
    char username[64];
    char password[32];

    uint8_t stored_cred[256]; // Actual size is 146, but leave room for some more
    size_t stored_cred_len;
    uint8_t token[256]; // Actual size is ?
    size_t token_len;
};

struct sp_metadata {
    size_t file_len;
};

struct sp_sysinfo {
    char client_name[16];
    char client_version[16];
    char client_build_id[16];
    char device_id[41]; // librespot gives a 20 byte id (so 40 char hex + 1 zero term)
};

struct sp_callbacks {
    // Bring your own https client and tcp connector
    int (*https_get)(char **body, const char *url);

    int (*tcp_connect)(const char *address, unsigned short port);

    void (*tcp_disconnect)(int fd);

    // Optional - set name of thread
    void (*thread_name_set)(pthread_t thread);

    // Debugging
    void (*hexdump)(const char *msg, uint8_t *data, size_t data_len);

    void (*logmsg)(const char *fmt, ...);
};

void
librespotc_login_password(const char *username, const char *password, struct sp_session **session, cmd_callback cmd_cb,
                          void *cb_arg);

void
librespotc_login_stored_cred(const char *username, uint8_t *stored_cred, size_t stored_cred_len,
                             struct sp_session **session, cmd_callback cmd_cb, void *cb_arg);

void
librespotc_login_token(const char *username, const char *token, struct sp_session **session);

int
librespotc_logout(struct sp_session *session);

int
librespotc_bitrate_set(struct sp_session *session, enum sp_bitrates bitrate);

int
librespotc_credentials_get(struct sp_credentials *credentials, struct sp_session *session);

// Returns a file descriptor (in non-blocking mode) from which caller can read
// one chunk of data. To get more data written/start playback loop, call
// librespotc_play().
int
librespotc_open(const char *path, struct sp_session *session, cmd_callback cmd_cb, void *cmd_arg);

// Continues writing data to the file descriptor until error or end of track.
// A read of the fd that returns 0 means end of track, and a negative read
// return value means error. progress_cb and cb_arg optional.
void
librespotc_write(struct sp_session *session, cmd_callback cmd_cb, void *cb_arg);

// Seeks to pos (measured in bytes, so must not exceed file_len), flushes old
// data from the fd and prepares one chunk of data for reading.
int
librespotc_seek(struct sp_session *session, size_t pos, cmd_callback cmd_cb, void *cmd_arg);

// Closes a track download, incl. the fd.
int
librespotc_close(struct sp_session *session);

size_t
librespotc_get_filelen(struct sp_session *session);

const char *
librespotc_last_errmsg(void);

int
librespotc_init(struct sp_sysinfo *sysinfo, struct sp_callbacks *callbacks, int fd);

void
librespotc_deinit(void);

void
librespotc_session_error_cb(struct sp_session *session, sp_error_callback cb, void *userp);

int
librespotc_get_session_fd(struct sp_session *session);

#endif /* !__LIBRESPOT_C_H__ */
