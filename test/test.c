#include <event2/event.h>
#include <event2/bufferevent.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#define PORT 5394
#define MAX_BYTES_PER_READ 1024 * 8 // Same amount used internally by librespot-c

#define printf(fmt, ...) fprintf(stdout, __FILE__ ":%d:%s(): " fmt, __LINE__, __func__, ##__VA_ARGS__)

struct userp {
    FILE *fp;
    struct event_base *base;
    size_t file_len;
    size_t progress;
    char track[23];
};

enum error_type{
    ET_NO_ERROR,
    ET_SPOTIFY,
    ET_SPOTIFY_INTERNAL,
    ET_HTTP,
    ET_FULL
};

typedef enum PacketType {
    MUSIC_DATA = 0,
    MUSIC_INFO = 1,
    PLAYLIST_INFO = 2,
    ALBUM_INFO = 3,
    RECOMMENDATIONS = 4,
    ARTIST_INFO = 5,
    SEARCH = 6,
    AVAILABLE_REGIONS = 7,
} PacketType;

void
read_cb(struct bufferevent *bev, void *ptr) {
    struct userp *userp = (struct userp *) ptr;
    char tmp[MAX_BYTES_PER_READ];
    size_t n;
    bool i = false;
    while (1) {
        n = bufferevent_read(bev, tmp, sizeof(tmp));
        if (n <= 0)
            break; /* No more data. */

        if (!userp->file_len) {
            enum error_type err = (enum error_type) tmp[0];
            userp->file_len = *((size_t *) &tmp[1]);
            printf("Ready to receive %lu bytes of data\n", userp->file_len);
            if (err != ET_NO_ERROR){
                printf("Received error\n");
            }

            fwrite(tmp + sizeof(userp->file_len) + 1, sizeof(*tmp), n - sizeof(userp->file_len) - 1, userp->fp);
            userp->progress += n - sizeof(userp->file_len) - 1;
            continue;
        }

        userp->progress += n;

        fwrite(tmp, sizeof(*tmp), n, userp->fp);
    }
    if (userp->progress == userp->file_len){
        printf("Done\n");
        bufferevent_free(bev);
        event_base_loopexit(userp->base, NULL);
    }
}

void eventcb(struct bufferevent *bev, short events, void *ptr) {
    struct userp *userp = (struct userp *) ptr;
    if (events & BEV_EVENT_CONNECTED) {
        /* We're connected to 127.0.0.1:8080.   Ordinarily we'd do
           something here, like start reading or writing. */
//        struct evbuffer *output = bufferevent_get_output(bev);
        bufferevent_write(bev, userp->track, sizeof(userp->track));
        printf("Connected and wrote\n");

    } else if (events & BEV_EVENT_TIMEOUT){
        struct event_base *base = userp->base;
        printf("Timeout! Closing\n");
        printf("Closing\n");
        bufferevent_free(bev);
        event_base_loopexit(base, NULL);
    } else if (events & BEV_EVENT_ERROR) {
        struct event_base *base = userp->base;
        if (events & BEV_EVENT_ERROR) {
            int err = bufferevent_socket_get_dns_error(bev);
            if (err)
                printf("DNS error: %s\n", evutil_gai_strerror(err));
        }
        printf("Closing\n");
        bufferevent_free(bev);
        event_base_loopexit(base, NULL);
    }
}

int main(int argc, char **argv) {
    struct event_base *base;
    struct bufferevent *bev;
    struct sockaddr_in sin;
    struct userp userp;
    struct timeval timeout;

    if (argc < 2) return -1;

    timeout.tv_sec = 30;
    timeout.tv_usec = 0;

    srand(clock());
    char *fname = calloc(16 + strlen(argv[1]), sizeof(*fname));
    int n = (int) ((rand() / (float) RAND_MAX) * 9999.f);
    snprintf(fname, 16 + strlen(argv[1]), "test-%s-%d.ogg", argv[1], n);

    userp.fp = fopen(fname, "w");
    userp.file_len = 0;
    userp.progress = 0;
    memset(userp.track, 0, sizeof(userp.track));
    /*userp.track[1] = 2;
    userp.track[2] = 0;
    memcpy(&userp.track[3], argv[1], 22);
    memcpy(&userp.track[3+22], argv[2], 22);*/
    userp.track[0] = MUSIC_INFO;
    memcpy(&userp.track[1], argv[1], 22);

    base = event_base_new();
    userp.base = base;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
    sin.sin_port = htons(PORT); /* Port */

    bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);

    bufferevent_set_timeouts(bev, &timeout, NULL);
    bufferevent_setcb(bev, read_cb, NULL, eventcb, &userp);
    bufferevent_enable(bev, EV_READ);
    bufferevent_setwatermark(bev, EV_READ, 20, 0);

    if (bufferevent_socket_connect(bev,
                                   (struct sockaddr *) &sin, sizeof(sin)) < 0) {
        /* Error starting connection */
        bufferevent_free(bev);
        return -1;
    }

    event_base_dispatch(base);
    fclose(userp.fp);
    return 0;
}