//
// Created by quartzy on 2/7/23.
//

#include "spotify.h"
#include "util.h"
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

char top_region[2];

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
    JDM_ENTER_FUNCTION;
    if (element->session) {
        librespotc_close(element->session);
    }
    fd_vec_free(&element->fd_vec);
    if (element->read_ev) event_free(element->read_ev);
    if (element->cache_fp) fclose(element->cache_fp);
    free(element->path);
    memset(element, 0, sizeof(*element));
    JDM_LEAVE_FUNCTION;
}

static void
session_error(
        struct sp_session *session, enum sp_error err,
        void *userp) { // On session error, create a new session in its place and continue playing the previous song
    if (err == SP_ERR_NOCONNECTION) return;
    JDM_ENTER_FUNCTION;
    struct element *element = (struct element *) userp;
    if (err == SP_ERR_TRACK_NOT_FOUND){
        JDM_TRACE("Track not found error: '%s'", element->id);
        for (int i = 0; i < element->fd_vec.len; ++i) {
            write_error_spotify(element->fd_vec.el[i]);
        }
        clean_element(element);
        JDM_LEAVE_FUNCTION;
        return;
    }
    if (element->retries >= 3){
        JDM_WARN("Session error detected. Failed after 3 retries, disconnecting.");
        for (int i = 0; i < element->fd_vec.len; ++i) {
            write_error(element->fd_vec.el[i], ET_SPOTIFY_INTERNAL, "Failed after 3 retries, disconnecting");
        }
        clean_element(element);
        JDM_LEAVE_FUNCTION;
        return;
    }
    element->retries++;
    JDM_WARN("Session error detected, reconnecting");
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
    JDM_TRACE("Creating new session as %s", creds->creds.username);
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
        JDM_ERROR("Error creating librespot session: %s", librespotc_last_errmsg());
        JDM_LEAVE_FUNCTION;
        return;
    }
    creds->uses++;
    JDM_LEAVE_FUNCTION;
}

struct credentials *
get_credentials() {
    JDM_ENTER_FUNCTION;
    pthread_mutex_lock(&credentials_mutex);
    for (int i = 0; i < credentials_count; ++i) {
        if (++credentials_last_index >= credentials_count) credentials_last_index = 0;
        if (credentials[credentials_last_index].uses <= MAX_CREDENTIAL_USES){
            pthread_mutex_unlock(&credentials_mutex);
            JDM_LEAVE_FUNCTION;
            return &credentials[credentials_last_index];
        }
    }
    pthread_mutex_unlock(&credentials_mutex);
    JDM_LEAVE_FUNCTION;
    return NULL;
}

void
finish_seek_cb(int ret, void *userp) {
    JDM_ENTER_FUNCTION;
    struct element *element = (struct element *) userp;
    struct event_base *base = element->base;
    if (ret){
        JDM_ERROR("Error when seeking"); // TODO: Handle this error
//        session_error(element->session, SP_ERR_INVALID, element);
        JDM_LEAVE_FUNCTION;
        return;
    }
    int fd = librespotc_get_session_fd(element->session);
    if(fd == -1) {
        session_error(element->session, SP_ERR_INVALID, element);
        JDM_LEAVE_FUNCTION;
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
    if (element->progress) JDM_TRACE("Continuing sending data for '%s' starting at %zu", element->id, element->progress);
    else
        JDM_TRACE("Sending data for '%s'", element->id);
    JDM_LEAVE_FUNCTION;
}

void
spotify_file_open_cb(int fd, void *userp) {
    JDM_ENTER_FUNCTION;
    struct element *element = (struct element *) userp;

    if (fd < 0) {
        JDM_ERROR("Error opening librespot file: %s", librespotc_last_errmsg());
        for (int i = 0; i < element->fd_vec.len; ++i) {
            write_error_spotify(element->fd_vec.el[i]);
        }
        if (element->cache_fp) fclose(element->cache_fp);
        element->cache_fp = NULL;
        remove(element->path);
        JDM_LEAVE_FUNCTION;
        return;
    }

    JDM_TRACE("Opened spotify track (%d)", fd);

    if (element->progress) {
        librespotc_seek(element->session, element->progress, finish_seek_cb, userp);
        JDM_LEAVE_FUNCTION;
        return;
    }
    element->file_len = librespotc_get_filelen(element->session);
    finish_seek_cb(0, userp);
    JDM_LEAVE_FUNCTION;
}

void
session_cb(int ret, void *userp) {
    JDM_ENTER_FUNCTION;
    struct element *element = (struct element *) userp;

    if (!element->session) {
        JDM_ERROR("Error creating librespot session: %s", librespotc_last_errmsg());
        for (int i = 0; i < element->fd_vec.len; ++i) {
            write_error_spotify(element->fd_vec.el[i]);
        }
        fclose(element->cache_fp);
        remove(element->path);
        JDM_LEAVE_FUNCTION;
        return;
    }
    char *region = librespotc_get_country(element->session);
    JDM_TRACE("Created spotify session (%d). Region: %.2s", ret, region);

    if (region[0] != element->creds->region[0] || region[1] != element->creds->region[1]){ // Correct region in case it's wrong
        JDM_WARN("Region mismatch found for account '%s'. Correcting from %.2s to %.2s", element->creds->creds.username, element->creds->region, region);
        element->creds->region[0] = region[0];
        element->creds->region[1] = region[1];
        spotify_update_available_regions();
    }

    int r = librespotc_open(element->id, element->session, spotify_file_open_cb, userp);
    if (r) {
        JDM_ERROR("Error when calling librespotc_open: %s", librespotc_last_errmsg());
    }
    JDM_LEAVE_FUNCTION;
}

struct element *
spotify_activate_session(struct session_pool *pool, size_t progress, char *id, char *path, int fd,
                         const char *region, audio_finished_cb cb, void *cb_arg,
                         struct event_base *base) {
    JDM_ENTER_FUNCTION;
    int uninit = -1;
    for (int i = 0; i < SESSION_POOL_MAX; ++i) {
        if (!pool->elements[i].active && (!region || !pool->elements[i].creds || (region[0] == pool->elements[i].creds->region[0] && region[1] == pool->elements[i].creds->region[1]))) {
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
                JDM_LEAVE_FUNCTION;
                return &pool->elements[i]; // Not active and a valid session
            }
            if (uninit == -1) uninit = i;
        }
    }

    if (uninit != -1) {
        struct credentials *creds = get_credentials();
        JDM_TRACE("Creating new session as %s", creds->creds.username);
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
            JDM_ERROR("Error occurred while trying to open file '%s': %s", pool->elements[uninit].path,
                    JDM_ERRNO_MESSAGE);
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
        JDM_LEAVE_FUNCTION;
        return &pool->elements[uninit];
    }
    JDM_LEAVE_FUNCTION;
    return NULL;
}

void spotify_stop_element(struct element *element) {
    if (!element) return;
    JDM_ENTER_FUNCTION;
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
    JDM_LEAVE_FUNCTION;
}

static void
audio_read_cb(int fd, short what, void *arg) {
    JDM_ENTER_FUNCTION;
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
        JDM_TRACE("Playback ended (%zu)", got);
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
    JDM_LEAVE_FUNCTION;
}

int
spotify_init(int argc, char **argv) {
    JDM_ENTER_FUNCTION;
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
                    JDM_ERROR("Error when reallocating: %s", JDM_ERRNO_MESSAGE);
                    JDM_LEAVE_FUNCTION;
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
                JDM_ERROR("Error when reallocating: %s", JDM_ERRNO_MESSAGE);
                JDM_LEAVE_FUNCTION;
                return -1;
            }
            credentials = tmp;
        }
        JDM_INFO("Parsed %zu credentials from %s", credentials_count, argv[1]);
    } else { // Load credentials from arguments
        credentials_count = (argc - 1) / 3;
        credentials_last_index = -1;
        credentials = calloc(credentials_count, sizeof(*credentials));
        JDM_INFO("Detected %zu users from arguments", credentials_count);
        char **argv1 = &argv[1];
        for (int i = 0; i < credentials_count; ++i) {
            size_t username_len = strlen(argv1[i * 3]), password_len = strlen(argv1[i * 3 + 1]), region_len = strlen(argv1[i * 3 + 2]);
            memcpy(credentials[i].creds.username, argv1[i * 3], username_len > 64 ? 64 : username_len);
            memcpy(credentials[i].creds.password, argv1[i * 3 + 1], password_len > 32 ? 32 : password_len);
            memcpy(credentials[i].region, argv1[i * 3 + 2], region_len > 2 ? 2 : region_len);
        }
    }
    spotify_update_available_regions();
    char regions_string[available_region_count*3];
    for (int i = 0; i < available_region_count; ++i) {
        regions_string[i*3] = available_regions[i*2];
        regions_string[i*3+1] = available_regions[i*2+1];
        regions_string[i*3+2] = ' ';
    }
    regions_string[available_region_count*3-1] = 0;
    JDM_INFO("Available regions (%zu): %s", available_region_count, regions_string);
    JDM_LEAVE_FUNCTION;
    return 0;
}

struct region_count_container{
    char region[2];
    int count;
};

int region_count_container_comprar(const void *a, const void *b){
    return ((const struct region_count_container*)b)->count-((const struct region_count_container*)a)->count;
}

// Puts all available regions into a list and also sorts them in terms of how many accounts use that region
void
spotify_update_available_regions() { // TODO: Make this thread safe
    JDM_ENTER_FUNCTION;
    if (available_regions){
        free(available_regions);
        available_regions = NULL;
    }
    available_region_count = 0;
    struct region_count_container regions_container[credentials_count];
    for (int i = 0; i < credentials_count; ++i) {
        // Check if region already included
        for (int j = 0; j < available_region_count; ++j) {
            if (regions_container[j].region[0] == credentials[i].region[0] && regions_container[j].region[1] == credentials[i].region[1]){
                regions_container[j].count++;
                goto loop_end;
            }
        }

        regions_container[available_region_count].region[0] = credentials[i].region[0];
        regions_container[available_region_count].region[1] = credentials[i].region[1];
        regions_container[available_region_count].count = 1;
        available_region_count++;
        loop_end:;
    }
    qsort(regions_container, available_region_count, sizeof(*regions_container), region_count_container_comprar);
    top_region[0] = regions_container[0].region[0];
    top_region[1] = regions_container[0].region[1];

    available_regions = calloc(available_region_count, sizeof(char)*2);
    for (int i = 0; i < available_region_count; ++i) {
        available_regions[i*2] = regions_container[i].region[0];
        available_regions[i*2+1] = regions_container[i].region[1];
    }
    JDM_LEAVE_FUNCTION;
}

void
spotify_clean(struct session_pool *pool) {
    for (int i = 0; i < SESSION_POOL_MAX; ++i) {
        clean_element(&pool->elements[i]);
    }
}

void spotify_free_global() {
    JDM_ENTER_FUNCTION;
    free(credentials);
    credentials = NULL;
    pthread_mutex_destroy(&credentials_mutex);
    librespotc_deinit();
    free(available_regions);
    JDM_LEAVE_FUNCTION;
}
