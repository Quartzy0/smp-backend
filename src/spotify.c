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
pthread_mutex_t credentials_mutex;

char *available_regions;
size_t available_region_count;

struct credentials *get_credentials();

static void
audio_read_cb(int fd, short what, void *arg);

void session_cb(int ret, void *userp);

void
fd_vec_init(struct fd_vec *v){
    v->size = VEC_INITIAL_SIZE;
    v->len = 0;
    v->el = calloc(VEC_INITIAL_SIZE, sizeof(*v->el));
}

void
fd_vec_add(struct fd_vec *vec, int fd){
    if (vec->size <= vec->len + 1) {
        int *realloc_tmp = realloc(vec->el, (vec->size + VEC_SIZE_STEP) * sizeof(*realloc_tmp));
        if (!realloc_tmp) perror("error when calling realloc()");
        vec->el = realloc_tmp;
        vec->size += VEC_SIZE_STEP;
    }
    memcpy(&vec->el[vec->len++], &fd, sizeof(fd));
}

void
fd_vec_remove(struct fd_vec *vec, int index){
    vec->el[index] = -1;
}

bool
fd_vec_remove_element(struct fd_vec *vec, int fd){
    for (int i = 0; i < vec->len; ++i) {
        if (vec->el[i]==fd){
            fd_vec_remove(vec, i);
            return true;
        }
    }
    return false;
}

bool
fd_vec_is_empty(struct fd_vec *vec){
    if (vec->len == 0) return true;
    for (int i = 0; i < vec->len; ++i) {
        if (vec->el[i] != -1) return false;
    }
    return true;
}

void
fd_vec_free(struct fd_vec *v){
    free(v->el);
    memset(v, 0, sizeof(*v));
}

void
write_error_spotify(int fd) {
    write_error(fd, ET_SPOTIFY_INTERNAL, librespotc_last_errmsg());
}

void
clean_element(struct element *element) {
    if (!element) return;
    if (element->active && element->session) {
        librespotc_close(element->session);
    }
    fd_vec_free(&element->fd_vec);
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
        for (int i = 0; i < element->fd_vec.len; ++i) {
            write_error(element->fd_vec.el[i], ET_SPOTIFY_INTERNAL, "Failed after 3 retries, disconnecting");
        }
        clean_element(element);
        return;
    }
    element->retries++;
    printf("Session error detected, reconnecting\n");
    element->creds->uses--;

    if (element->read_ev){
        event_free(element->read_ev);
        element->read_ev = NULL;
    }

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
                                  element, element->base);
    } else {
        librespotc_login_stored_cred(creds->creds.username,
                                     creds->creds.stored_cred,
                                     creds->creds.stored_cred_len, &element->session, session_cb,
                                     element, element->base);
    }
    if (!element->session) {
        fprintf(stderr, "Error creating librespot session: %s\n", librespotc_last_errmsg());
        return;
    }
    creds->uses++;
}

struct credentials *
get_credentials() {
    pthread_mutex_lock(&credentials_mutex);
    for (int i = 0; i < credentials_count; ++i) {
        if (++credentials_last_index >= credentials_count) credentials_last_index = 0;
        if (credentials[credentials_last_index].uses <= MAX_CREDENTIAL_USES){
            pthread_mutex_unlock(&credentials_mutex);
            return &credentials[credentials_last_index];
        }
    }
    pthread_mutex_unlock(&credentials_mutex);
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
        for (int i = 0; i < element->fd_vec.len; ++i) {
            if (element->fd_vec.el[i] == -1) continue;
            write(element->fd_vec.el[i], &no_err, 1);
            write(element->fd_vec.el[i], &element->file_len, sizeof(element->file_len));
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
        for (int i = 0; i < element->fd_vec.len; ++i) {
            write_error_spotify(element->fd_vec.el[i]);
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
        for (int i = 0; i < element->fd_vec.len; ++i) {
            write_error_spotify(element->fd_vec.el[i]);
        }
        fclose(element->cache_fp);
        remove(element->path);
        return;
    }
    char *region = librespotc_get_country(element->session);
    printf("Created spotify session (%d). Region: %.2s\n", ret, region);

    if (region[0] != element->creds->region[0] || region[1] != element->creds->region[1]){ // Correct region in case it's wrong
        printf("Region mismatch found for account '%s'. Correcting from %.2s to %.2s\n", element->creds->creds.username, element->creds->region, region);
        element->creds->region[0] = region[0];
        element->creds->region[1] = region[1];
        spotify_update_available_regions();
    }

    int r = librespotc_open(element->id, element->session, spotify_file_open_cb, userp);
    if (r) {
        fprintf(stderr, "Error when calling librespotc_open: %s\n", librespotc_last_errmsg());
    }
}

struct element *
spotify_activate_session(struct session_pool *pool, size_t progress, char *id, char *path, int fd,
                         const char *region, audio_finished_cb cb, void *cb_arg,
                         struct event_base *base) {

    int uninit = -1;
    for (int i = 0; i < SESSION_POOL_MAX; ++i) {
        if (!pool->elements[i].active && (!region || (region[0] == pool->elements[i].creds->region[0] && region[1] == pool->elements[i].creds->region[1]))) {
            if (pool->elements[i].session) {
                pool->elements[i].active = true;
                pool->elements[i].progress = progress;
                memcpy(pool->elements[i].id, id, sizeof(pool->elements[i].id));
                pool->elements[i].path = strdup(path);
                fd_vec_init(&pool->elements[i].fd_vec);
                fd_vec_add(&pool->elements[i].fd_vec, fd);
                pool->elements[i].cache_fp = fopen(pool->elements[i].path, "a");
                pool->elements[i].cb = cb;
                pool->elements[i].cb_arg = cb_arg;
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
        fd_vec_init(&pool->elements[uninit].fd_vec);
        fd_vec_add(&pool->elements[uninit].fd_vec, fd);
        pool->elements[uninit].path = strdup(path);
        pool->elements[uninit].base = base;
        pool->elements[uninit].read_ev = NULL;
        pool->elements[uninit].active = true;
        pool->elements[uninit].cb = cb;
        pool->elements[uninit].cb_arg = cb_arg;
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
                                      &pool->elements[uninit], pool->elements[uninit].base);
        } else {
            librespotc_login_stored_cred(creds->creds.username,
                                         creds->creds.stored_cred,
                                         creds->creds.stored_cred_len, &pool->elements[uninit].session, session_cb,
                                         &pool->elements[uninit], pool->elements[uninit].base);
        }
        librespotc_session_error_cb(pool->elements[uninit].session, session_error, &pool->elements[uninit]);
        creds->uses++;
        return &pool->elements[uninit];
    }
    return NULL;
}

void spotify_stop_element(struct element *element) {
    if (!element) return;
    if (element->read_ev) event_free(element->read_ev);
    element->read_ev = NULL;
    if (element->session) librespotc_close(element->session);
    if (element->cache_fp){
        struct write_job *wj = &element->write_job;
        while (aio_error(&wj->cb) == EINPROGRESS) {}
        if (wj->offset){
            wj->cb.aio_buf = wj->tmp[wj->current_buf];
            wj->cb.aio_nbytes = wj->offset;
            aio_write(&wj->cb);
            while (aio_error(&wj->cb) == EINPROGRESS) {}
        }
        fclose(element->cache_fp);
        element->cache_fp = NULL;
    }
    if (element->cb) element->cb(element, element->cb_arg);

    clean_element(element);
    element->active = false;
    element->progress = 0;
}

static void
audio_read_cb(int fd, short what, void *arg) {
    struct element *element = (struct element *) arg;
    size_t got;

    struct write_job *wj = &element->write_job;

    got = read(fd, &wj->tmp[wj->current_buf][wj->offset], MAX_BYTES_PER_READ);

    element->progress += got;
    if (got > 0){
        for (int i = 0; i < element->fd_vec.len; ++i) {
            if(element->fd_vec.el[i] != -1) write(element->fd_vec.el[i], &wj->tmp[wj->current_buf][wj->offset], got);
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
    if (got <= 0 || element->progress >= element->file_len) {
        printf("Playback ended (%zu)\n", got);
        event_free(element->read_ev);
        element->read_ev = NULL;
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
        if (element->cb) element->cb(element, element->cb_arg);

        clean_element(element);
        element->active = false;
        element->progress = 0;
    }
}

int
spotify_init(int argc, char **argv) {
    credentials_mutex = (pthread_mutex_t) PTHREAD_MUTEX_INITIALIZER;
    if (argc == 2) { // Load credentials from file
        FILE *fp = fopen(argv[1], "r"); // File format is: <email> <password> <username> <region>\n
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
            nxt = strchr(nxt1, ' ');
            if (!nxt) break;
            memcpy(credentials[credentials_count].creds.username, nxt1, nxt - nxt1);

            nxt += 1;
            nxt1 = strchr(nxt, '\n');
            if (!nxt1) {
                memcpy(credentials[credentials_count].region, nxt, sizeof(credentials[credentials_count].region));
                credentials_count++;
                break;
            }
            memcpy(credentials[credentials_count].region, nxt, sizeof(credentials[credentials_count].region));
            credentials_count++;
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
        credentials_count = (argc - 1) / 3;
        credentials_last_index = -1;
        credentials = calloc(credentials_count, sizeof(*credentials));
        printf("Detected %zu users from arguments\n", credentials_count);
        char **argv1 = &argv[1];
        for (int i = 0; i < credentials_count; ++i) {
            size_t username_len = strlen(argv1[i * 3]), password_len = strlen(argv1[i * 3 + 1]), region_len = strlen(argv1[i * 3 + 2]);
            memcpy(credentials[i].creds.username, argv1[i * 3], username_len > 64 ? 64 : username_len);
            memcpy(credentials[i].creds.password, argv1[i * 3 + 1], password_len > 32 ? 32 : password_len);
            memcpy(credentials[i].region, argv1[i * 3 + 2], region_len > 2 ? 2 : region_len);
        }
    }
    spotify_update_available_regions();
    printf("Available regions (%zu): ", available_region_count);
    for (int i = 0; i < available_region_count; ++i) {
        putc(available_regions[i*2], stdout);
        putc(available_regions[i*2+1], stdout);
        if (i==available_region_count-1){
            putc('\n', stdout);
        }else{
            putc(' ', stdout);
        }
    }

    memset(&s_sysinfo, 0, sizeof(struct sp_sysinfo));
    snprintf(s_sysinfo.device_id, sizeof(s_sysinfo.device_id), "aabbccddeeff");

    int ret = librespotc_init(&s_sysinfo, &callbacks);
    if (ret < 0) {
        printf("Error initializing Spotify: %s\n", librespotc_last_errmsg());
        return -1;
    }
    return 0;
}

void
spotify_update_available_regions() { // TODO: Make this thread safe
    if (available_regions){
        free(available_regions);
        available_regions = NULL;
    }
    available_region_count = 0;
    available_regions = calloc(credentials_count, sizeof(*available_regions) * 2);
    for (int i = 0; i < credentials_count; ++i) {
        // Check if region already included
        char *r = memchr(available_regions, credentials[i].region[0], available_region_count * 2 * sizeof(sizeof(*available_regions)));
        if (r && r[1] == credentials[i].region[1]) continue; // Already included

        available_regions[available_region_count*2] = credentials[i].region[0];
        available_regions[available_region_count*2+1] = credentials[i].region[1];
        available_region_count++;
    }
    if (available_region_count != credentials_count){ // realloc to exact size
        char *tmp = realloc(available_regions, available_region_count * sizeof(*available_regions) * 2);
        if (!tmp) perror("error calling realloc");
        available_regions = tmp;
    }
}

void
spotify_clean(struct session_pool *pool) {
    for (int i = 0; i < SESSION_POOL_MAX; ++i) {
        clean_element(&pool->elements[i]);
    }
    free(credentials);
    pthread_mutex_destroy(&credentials_mutex);
    librespotc_deinit();
}
