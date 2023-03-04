//
// Created by quartzy on 2/7/23.
//

#include "spotify.h"
#include "vec.h"
#include "defs.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

struct credentials *credentials;
size_t credentials_count;
size_t credentials_last_index;

struct credentials *get_credentials();

static void
audio_read_cb(int fd, short what, void *arg);

void session_cb(int ret, void *userp);

void
write_error_spotify(struct bufferevent *bev) {
    write_error(bev, ET_SPOTIFY_INTERNAL, librespotc_last_errmsg());
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

static void
session_error(
        struct sp_session *session, enum sp_error err,
        void *userp) { // On session error, create a new session in its place and continue playing the previous song
    if (err == SP_ERR_NOCONNECTION || err == SP_ERR_TRACK_NOT_FOUND) return;
    struct element *element = (struct element *) userp;
    if (element->retries >= 3){
        fprintf(stderr, "Session error detected. Failed after 3 retries, disconnecting.\n");
        for (int i = 0; i < element->bev_vec.len; ++i) {
            write_error(element->bev_vec.el[i], ET_SPOTIFY_INTERNAL, "Failed after 3 retries, disconnecting");
        }
        clean_element(element);
        return;
    }
    element->retries++;
    printf("Session error detected, reconnecting\n");
    element->creds->uses--;

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
    element->creds = creds;
    if (creds->creds.stored_cred_len == 0) {
        librespotc_login_password(creds->creds.username,
                                  creds->creds.password, &element->session, session_cb,
                                  element);
    } else {
        librespotc_login_stored_cred(creds->creds.username,
                                     creds->creds.stored_cred,
                                     creds->creds.stored_cred_len, &element->session, session_cb,
                                     element);
    }
    if (!element->session) {
        fprintf(stderr, "Error creating librespot session: %s\n", librespotc_last_errmsg());
        return;
    }
    creds->uses++;
}

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
    if (ret){
        fprintf(stderr, "Error when seeking\n"); // TODO: Handle this error
//        session_error(element->session, SP_ERR_INVALID, element);
        return;
    }
    int fd = librespotc_get_session_fd(element->session);
    if(fd == -1) {
        session_error(element->session, SP_ERR_INVALID, element);
        return;
    }

    memset(&element->write_job, 0, sizeof(element->write_job));
    if (element->cache_fp){
        element->write_job.cb.aio_fildes = fileno(element->cache_fp);
    }
    if (!element->progress){
        enum error_type no_err = ET_NO_ERROR;
        for (int i = 0; i < element->bev_vec.len; ++i) {
            bufferevent_write(element->bev_vec.el[i], &no_err, 1);
            bufferevent_write(element->bev_vec.el[i], &element->file_len, sizeof(element->file_len));
        }
        if (element->cache_fp){
            fwrite(&no_err, 1, 1, element->cache_fp);
            fwrite(&element->file_len, sizeof(element->file_len), 1, element->cache_fp);
            fflush(element->cache_fp);
        }
    }

    element->read_ev = event_new(base, fd, EV_READ | EV_PERSIST, audio_read_cb,
                                 element);
    event_add(element->read_ev, NULL);

    librespotc_write(element->session);
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
        if (element->cache_fp) fclose(element->cache_fp);
        element->cache_fp = NULL;
        remove(element->path);
        return;
    }

    printf("Opened spotify track (%d)\n", fd);

    if (element->progress) {
        librespotc_seek(element->session, element->progress, finish_seek_cb, userp);
        return;
    }
    element->file_len = librespotc_get_filelen(element->session);
    finish_seek_cb(0, userp);
}

void
session_cb(int ret, void *userp) {
    struct element *element = (struct element *) userp;

    if (!element->session) {
        fprintf(stderr, "Error creating librespot session: %s\n", librespotc_last_errmsg());
        for (int i = 0; i < element->bev_vec.len; ++i) {
            write_error_spotify(element->bev_vec.el[i]);
        }
        fclose(element->cache_fp);
        remove(element->path);
        return;
    }
    printf("Created spotify session (%d)\n", ret);
    librespotc_session_error_cb(element->session, session_error, element);

    int r = librespotc_open(element->id, element->session, spotify_file_open_cb, userp);
    if (r) {
        fprintf(stderr, "Error when calling librespotc_open: %s\n", librespotc_last_errmsg());
    }
}

struct element *
spotify_activate_session(struct session_pool *pool, size_t progress, uint8_t *id, char *path,
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
                pool->elements[i].cache_fp = fopen(pool->elements[i].path, "a");
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
        pool->elements[uninit].cache_fp = fopen(pool->elements[uninit].path, "a");
        if (!pool->elements[uninit].cache_fp){
            fprintf(stderr, "Error occurred while trying to open file '%s': %s\n", pool->elements[uninit].path,
                    strerror(errno));
        }
        memcpy(pool->elements[uninit].id, id, sizeof(pool->elements[uninit].id));
        pool->elements[uninit].creds = creds;
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

    struct write_job *wj = &element->write_job;

    got = read(fd, &wj->tmp[wj->current_buf][wj->offset], MAX_BYTES_PER_READ);

    if (got <= 0) {
        printf("Playback ended (%zu)\n", got);
        event_free(element->read_ev);
        librespotc_close(element->session);
        if (element->cache_fp){
            while (aio_error(&wj->cb) == EINPROGRESS) {}
            if (wj->offset){
                wj->cb.aio_buf = wj->tmp[wj->current_buf];
                wj->cb.aio_nbytes = wj->offset + got;
                aio_write(&wj->cb);
                while (aio_error(&wj->cb) == EINPROGRESS) {}
            }
            fclose(element->cache_fp);
            element->cache_fp = NULL;
        }

        element->read_ev = NULL;
        vec_free(&element->bev_vec);
        element->active = false;
        element->progress = 0;
        return;
    }
    element->progress += got;

    for (int i = 0; i < element->bev_vec.len; ++i) {
        bufferevent_write(element->bev_vec.el[i], &wj->tmp[wj->current_buf][wj->offset], got);
    }
    if (element->cache_fp){
        if (MAX_WRITE_BUFFER_SIZE - (wj->offset + got) < MAX_BYTES_PER_READ*2){
            while (aio_error(&wj->cb) == EINPROGRESS) {} // Wait for write job to finish if still in progress
            wj->cb.aio_buf = wj->tmp[wj->current_buf];
            wj->cb.aio_nbytes = wj->offset + got;
            aio_write(&wj->cb);
            wj->offset = 0;
            wj->current_buf = !wj->current_buf;
        }else{
            wj->offset += got;
        }
    }
}

int
spotify_init(int argc, char **argv, struct session_pool *pool, int fd) {
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
    memset(pool->elements, 0, sizeof(pool->elements));

    memset(&s_sysinfo, 0, sizeof(struct sp_sysinfo));
    snprintf(s_sysinfo.device_id, sizeof(s_sysinfo.device_id), "aabbccddeeff");

    int ret = librespotc_init(&s_sysinfo, &callbacks, fd);
    if (ret < 0) {
        printf("Error initializing Spotify: %s\n", librespotc_last_errmsg());
        return -1;
    }
}

void
spotify_clean(struct session_pool *pool){
    for (int i = 0; i < SESSION_POOL_MAX; ++i) {
        clean_element(&pool->elements[i]);
    }
    free(credentials);
    librespotc_deinit();
}