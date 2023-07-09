/*
 * The MIT License (MIT)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */


/*
Illustration of the general flow, where receive and writing the result are async
operations. For some commands, e.g. open and seek, the entire sequence is
encapsulated in a sync command, which doesn't return until final "done, error or
timeout". The command play is async, so all "done/error/timeout" is returned via
callbacks. Also, play will loop the flow, i.e. after writing a chunk of data it
will go back and ask for the next chunk of data from Spotify.

In some cases there is no result to write, or no reponse expected, but then the
events for proceeding are activated directly.

    |---next----*------------next-------------*----------next----------*
    v           |                             |                        |
----------> start/send  ------------------> recv ----------------> write result
^               |            ^                |       ^                |
|---reconnect---*            |------wait------*       |------wait------*
                |                             |                        |
                v                             v                        v
           done/error                done/error/timeout           done/error

"next": on success, continue with next command
"wait": waiting for more data or for write to become possible
"timeout": receive or write took too long to complete
*/
#include <jdm.h>

#include "librespot-c-internal.h"
#include "connection.h"
#include "channel.h"

// #define DEBUG_DISCONNECT 1

/* -------------------------------- Globals --------------------------------- */

// Shared
struct sp_callbacks sp_cb;
struct sp_sysinfo sp_sysinfo;
const char *sp_errmsg;

static bool sp_initialized;

static struct timeval sp_response_timeout_tv = {SP_AP_TIMEOUT_SECS, 0};

#ifdef DEBUG_DISCONNECT
static int debug_disconnect_counter;
#endif

// Forwards
static int
request_make(enum sp_msg_type type, struct sp_session *session);


/* -------------------------------- Session --------------------------------- */

static void
session_free(struct sp_session *session) {
    if (!session)
        return;
    JDM_ENTER_FUNCTION;

    channel_free_all(session);

    ap_disconnect(&session->conn);

    event_free(session->continue_ev);
    session->continue_ev = NULL;

    free(session->ap_avoid);
    free(session);
    JDM_LEAVE_FUNCTION;
}

static void
session_cleanup(struct sp_session *session) {
    struct sp_session *s;

    if (!session)
        return;
    JDM_ENTER_FUNCTION;
    session_free(session);
    JDM_LEAVE_FUNCTION;
}

static int
session_new(struct sp_session **out, event_callback_fn cb, const char *username, const char *password,
            const char *stored_cred, size_t stored_cred_len, const char *token, struct event_base *evbase) {
    JDM_ENTER_FUNCTION;
    struct sp_session *session;
    int ret;

    session = calloc(1, sizeof(struct sp_session));
    if (!session)
        RETURN_ERROR(SP_ERR_OOM, "Out of memory creating session");

    session->evbase = evbase;
    session->continue_ev = evtimer_new(evbase, cb, session);
    if (!session->continue_ev)
        RETURN_ERROR(SP_ERR_OOM, "Out of memory creating session event");

    snprintf(session->credentials.username, sizeof(session->credentials.username), "%s", username);

    if (stored_cred) {
        if (stored_cred_len > sizeof(session->credentials.stored_cred))
            RETURN_ERROR(SP_ERR_INVALID, "Invalid stored credential");

        session->credentials.stored_cred_len = stored_cred_len;
        memcpy(session->credentials.stored_cred, stored_cred, session->credentials.stored_cred_len);
    } else if (token) {
        if (strlen(token) > sizeof(session->credentials.token))
            RETURN_ERROR(SP_ERR_INVALID, "Invalid token");

        session->credentials.token_len = strlen(token);
        memcpy(session->credentials.token, token, session->credentials.token_len);
    } else {
        snprintf(session->credentials.password, sizeof(session->credentials.password), "%s", password);
    }

    session->bitrate_preferred = SP_BITRATE_DEFAULT;

    *out = session;

    JDM_LEAVE_FUNCTION;
    return 0;

    error:
    session_free(session);
    JDM_LEAVE_FUNCTION;
    return ret;
}

static int
session_check(struct sp_session *session) {
    return session == NULL;
}

static void
session_return(struct sp_session *session, enum sp_error err) {
    if (err < 0) return;
    JDM_ENTER_FUNCTION;

    /*ret = commands_exec_returnvalue(session);
    if (ret == 0) // Here we are async, i.e. no pending command
    {
        // track_write() completed, close the write end which means reader will
        // get an EOF
        if (channel && channel->state == SP_CHANNEL_STATE_PLAYING && err == SP_OK_DONE)
            channel_stop(channel); //
    }*/
    if (session->cmd_data.cb) session->cmd_data.cb(session->cmd_data.retval, session->cmd_data.userp);
    JDM_LEAVE_FUNCTION;
//    commands_exec_end(sp_cmdbase, err, session);
}

#define ERROR_ENTRY(x) [x+10]=#x

// Disconnects after an error situation. If it is a failed login then the
// session, otherwise we end download and disconnect.
static void
session_error(struct sp_session *session, enum sp_error err) {
    JDM_ENTER_FUNCTION;
    static const char *err_c[] = {
            ERROR_ENTRY(SP_OK_OTHER),
            ERROR_ENTRY(SP_OK_WAIT),
            ERROR_ENTRY(SP_OK_DATA),
            ERROR_ENTRY(SP_OK_DONE),
            ERROR_ENTRY(SP_ERR_OOM),
            ERROR_ENTRY(SP_ERR_INVALID),
            ERROR_ENTRY(SP_ERR_DECRYPTION),
            ERROR_ENTRY(SP_ERR_WRITE),
            ERROR_ENTRY(SP_ERR_NOCONNECTION),
            ERROR_ENTRY(SP_ERR_OCCUPIED),
            ERROR_ENTRY(SP_ERR_NOSESSION),
            ERROR_ENTRY(SP_ERR_LOGINFAILED),
            ERROR_ENTRY(SP_ERR_TIMEOUT),
            ERROR_ENTRY(SP_ERR_TRACK_NOT_FOUND),
    };
    JDM_WARN("Session error: %s - %s (%d) (occurred before msg %d, queue %d)", err_c[err + 10], sp_errmsg, err,
                 session->msg_type_next, session->msg_type_queued);

    session_return(session, err);

    if (!session->is_logged_in) {
        if (session->error_callback) session->error_callback(session, err, session->err_userp);
        JDM_LEAVE_FUNCTION;
        return;
    }

    channel_free_all(session);
    session->now_streaming_channel = NULL;

    ap_disconnect(&session->conn);
    if (session->error_callback) session->error_callback(session, err, session->err_userp);
    JDM_LEAVE_FUNCTION;
}

// Called if an access point disconnects. Will clear current connection and
// start a flow where the same request will be made to another access point.
static void
session_retry(struct sp_session *session) {
    JDM_ENTER_FUNCTION;
    struct sp_channel *channel = session->now_streaming_channel;
    enum sp_msg_type type = session->msg_type_last;
    const char *ap_address = ap_address_get(&session->conn);
    int ret;

    JDM_WARN("Retrying after disconnect (occurred at msg %d): %s\n", type, sp_errmsg);

    channel_retry(channel);

    free(session->ap_avoid);
    session->ap_avoid = strdup(ap_address);

    ap_disconnect(&session->conn);

    // If we were in the middle of a handshake when disconnected we must restart
    if (msg_is_handshake(type))
        type = MSG_TYPE_CLIENT_HELLO;

    ret = request_make(type, session);
    if (ret < 0)
        session_error(session, ret);
    JDM_LEAVE_FUNCTION;
}

/* ------------------------ Main sequence control --------------------------- */

// This callback must determine if a new request should be made, or if we are
// done and should return to caller
static void
continue_cb(int fd, short what, void *arg) {
    JDM_ENTER_FUNCTION;
    struct sp_session *session = arg;
    enum sp_msg_type type = MSG_TYPE_NONE;
    int ret;

    // type_next has priority, since this is what we use to chain a sequence, e.g.
    // the handshake sequence. type_queued is what comes after, e.g. first a
    // handshake (type_next) and then a chunk request (type_queued)
    if (session->msg_type_next != MSG_TYPE_NONE) {
//      sp_cb.logmsg(">>> msg_next >>>\n");

        type = session->msg_type_next;
        session->msg_type_next = MSG_TYPE_NONE;
    } else if (session->msg_type_queued != MSG_TYPE_NONE) {
//      sp_cb.logmsg(">>> msg_queued >>>\n");

        type = session->msg_type_queued;
        session->msg_type_queued = MSG_TYPE_NONE;
    }

    if (type != MSG_TYPE_NONE) {
        ret = request_make(type, session);
        if (ret < 0)
            session_error(session, ret);
    } else
        session_return(session, SP_OK_DONE); // All done, yay!
    JDM_LEAVE_FUNCTION;
}

// This callback is triggered by response_cb when the message response handler
// said that there was data to write. If not all data can be written in one pass
// it will re-add the event.
static void
audio_write_cb(int fd, short what, void *arg) {
    JDM_ENTER_FUNCTION;
    struct sp_session *session = arg;
    struct sp_channel *channel = session->now_streaming_channel;
    int ret;

    if (!channel)
        RETURN_ERROR(SP_ERR_INVALID, "Write result request, but not streaming right now");

    ret = channel_data_write(channel);
    switch (ret) {
        case SP_OK_WAIT:
            event_add(channel->audio_write_ev, NULL);
            break;
        case SP_OK_DONE:
            event_active(session->continue_ev, 0, 0);
            break;
        default:
            goto error;
    }

    JDM_LEAVE_FUNCTION;
    return;

    error:
    JDM_LEAVE_FUNCTION;
    session_error(session, ret);
}

static void
timeout_cb(int fd, short what, void *arg) {
    JDM_ENTER_FUNCTION;
    struct sp_session *session = arg;

    sp_errmsg = "Timeout waiting for Spotify response";

    session_error(session, SP_ERR_TIMEOUT);
    JDM_LEAVE_FUNCTION;
}

static void
response_cb(struct bufferevent *bev, void *arg) {
    JDM_ENTER_FUNCTION;
    struct sp_session *session = arg;
    struct sp_connection *conn = &session->conn;
    struct sp_channel *channel = session->now_streaming_channel;
    int ret;

    /*if (what == EV_READ) {
        ret = evbuffer_read(conn->incoming, fd, -1);
#ifdef DEBUG_DISCONNECT
        debug_disconnect_counter++;
        if (debug_disconnect_counter == 1000)
      {
        sp_cb.logmsg("Simulating a disconnection from the access point (last request type was %d)\n", session->msg_type_last);
        ret = 0;
      }
#endif

        if (ret == 0)
            RETURN_ERROR(SP_ERR_NOCONNECTION, "The access point disconnected");
        else if (ret < 0)
            RETURN_ERROR(SP_ERR_NOCONNECTION, "Connection to Spotify returned an error");

//      sp_cb.logmsg("Received data len %d\n", ret);
    }*/

    ret = response_read(session);
    switch (ret) {
        case SP_OK_WAIT: // Incomplete, wait for more data
            break;
        case SP_OK_DATA:
            if (channel->state == SP_CHANNEL_STATE_PLAYING && !channel->file.end_of_file)
                session->msg_type_next = MSG_TYPE_CHUNK_REQUEST;

            event_del(conn->timeout_ev);
            event_add(channel->audio_write_ev, NULL);
            break;
        case SP_OK_DONE: // Got the response we expected, but possibly more to process
            if (evbuffer_get_length(bufferevent_get_input(bev)) > 0)
                response_cb(bev, arg);

            event_del(conn->timeout_ev);
            event_active(session->continue_ev, 0, 0);
            break;
        case SP_OK_OTHER: // Not the response we were waiting for, check for other
            if (evbuffer_get_length(bufferevent_get_input(bev)) > 0)
                response_cb(bev, arg);
            break;
        default:
            event_del(conn->timeout_ev);
            goto error;
    }

    JDM_LEAVE_FUNCTION;
    return;

    error:
    if (ret == SP_ERR_NOCONNECTION)
        session_retry(session);
    else
        session_error(session, ret);
    JDM_LEAVE_FUNCTION;
}

static int
relogin(enum sp_msg_type type, struct sp_session *session) {
    JDM_ENTER_FUNCTION;
    int ret;

    ret = request_make(MSG_TYPE_CLIENT_HELLO, session);
    if (ret < 0)
        RETURN_ERROR(ret, sp_errmsg);

    // In case we lost connection to the AP we have to make a new handshake for
    // the non-handshake message types. So queue the message until the handshake
    // is complete.
    session->msg_type_queued = type;
    JDM_LEAVE_FUNCTION;
    return 0;

    error:
    JDM_LEAVE_FUNCTION;
    return ret;
}

static int
request_make(enum sp_msg_type type, struct sp_session *session) {
    JDM_ENTER_FUNCTION;
    struct sp_message msg;
    struct sp_connection *conn = &session->conn;
    struct sp_conn_callbacks cb = {session->evbase, response_cb, timeout_cb};
    int ret;

//    sp_cb.logmsg("Making request %d\n", type);

    // Make sure the connection is in a state suitable for sending this message
    ret = ap_connect(&session->conn, type, &session->cooldown_ts, session->ap_avoid, &cb, session);
    if (ret == SP_OK_WAIT)
        return relogin(type, session); // Can't proceed right now, the handshake needs to complete first
    else if (ret < 0)
        RETURN_ERROR(ret, sp_errmsg);

    ret = msg_make(&msg, type, session);
    if (ret < 0)
        RETURN_ERROR(SP_ERR_INVALID, "Error constructing message to Spotify");

    if (msg.encrypt)
        conn->is_encrypted = true;

    ret = msg_send(&msg, conn);
    if (ret < 0)
        RETURN_ERROR(ret, sp_errmsg);

    // Only start timeout timer if a response is expected, otherwise go straight
    // to next message
    if (msg.response_handler)
        event_add(conn->timeout_ev, &sp_response_timeout_tv);
    else
        event_active(session->continue_ev, 0, 0);

    session->msg_type_last = type;
    session->msg_type_next = msg.type_next;
    session->response_handler = msg.response_handler;

    JDM_LEAVE_FUNCTION;
    return 0;

    error:
    JDM_LEAVE_FUNCTION;
    return ret;
}


/* ----------------------------- Implementation ----------------------------- */
struct track_pause_close_wrapper{
    struct cmd_data orig;
    struct sp_session *session;
};
void
track_close(int ret, void *userp);


// This command is async
static int
track_write(struct sp_session *session) {
    JDM_ENTER_FUNCTION;
    struct sp_channel *channel;
    int ret;
    memset(&session->cmd_data, 0, sizeof(session->cmd_data));

    channel = session->now_streaming_channel;
    if (!channel || channel->state == SP_CHANNEL_STATE_UNALLOCATED)
        RETURN_ERROR(SP_ERR_INVALID, "No active channel to play, has track been opened?");

    channel_play(channel);

    ret = request_make(MSG_TYPE_CHUNK_REQUEST, session);
    if (ret < 0)
        RETURN_ERROR(ret, sp_errmsg);

    JDM_LEAVE_FUNCTION;
    return 0;

    error:
    JDM_ERROR("Error %d: %s", ret, sp_errmsg);

    JDM_LEAVE_FUNCTION;
    return 1;
}

static int
track_pause(struct cmd_data *data, struct sp_session *session, bool close) {
    JDM_ENTER_FUNCTION;
    struct sp_channel *channel;
    int ret;
    struct track_pause_close_wrapper *wrapper = NULL;
    if(close){
        wrapper = calloc(1, sizeof(*wrapper));
        wrapper->session = session;
        if(data) memcpy(&wrapper->orig, data, sizeof(*data));
        session->cmd_data.cb = track_close;
        session->cmd_data.userp = wrapper;
    }else{
        memcpy(&session->cmd_data, data, sizeof(*data));
    }

    channel = session->now_streaming_channel;
    if (!channel || channel->state == SP_CHANNEL_STATE_UNALLOCATED)
        RETURN_ERROR(SP_ERR_INVALID, "No active channel to pause, has track been opened?");

    // If we are playing we are in the process of downloading a chunk, and in that
    // case we need that to complete before doing anything else with the channel,
    // e.g. reset it as track_close() does.
    if (channel->state != SP_CHANNEL_STATE_PLAYING) {
        return 0;
    }

    channel_pause(channel);
    session->msg_type_next = MSG_TYPE_NONE;

    JDM_LEAVE_FUNCTION;
    return 0;

    error:
    free(wrapper);
    memset(&session->cmd_data, 0, sizeof(session->cmd_data));
    JDM_LEAVE_FUNCTION;
    return 1;
}

static int
track_seek(struct cmd_data *cmd_data, struct sp_session *session, size_t seek_pos) {
    JDM_ENTER_FUNCTION;
    struct sp_channel *channel;
    int ret;
    memcpy(&session->cmd_data, cmd_data, sizeof(*cmd_data));

    channel = session->now_streaming_channel;
    if (!channel)
        RETURN_ERROR(SP_ERR_INVALID, "No active channel to seek, has track been opened?");
    else if (channel->state != SP_CHANNEL_STATE_OPENED)
        RETURN_ERROR(SP_ERR_INVALID, "Seeking during playback not currently supported");

    // This operation is not safe during chunk downloading because it changes the
    // AES decryptor to match the new position. It also flushes the pipe.
    channel_seek(channel, seek_pos);

    ret = request_make(MSG_TYPE_CHUNK_REQUEST, session);
    if (ret < 0)
        RETURN_ERROR(ret, sp_errmsg);

    JDM_LEAVE_FUNCTION;
    return 0;

    error:
    JDM_LEAVE_FUNCTION;
    return 1;
}

void
track_close(int ret, void *userp) {
    JDM_ENTER_FUNCTION;
    struct track_pause_close_wrapper *wrapper = (struct track_pause_close_wrapper*) userp;
    struct sp_session *session = wrapper->session;

    channel_stop(session->now_streaming_channel);
    channel_free(session->now_streaming_channel);
    session->now_streaming_channel = NULL;

    if (wrapper->orig.cb) wrapper->orig.cb(ret, wrapper->orig.userp);
    free(wrapper);
    JDM_LEAVE_FUNCTION;
}

static int
media_open(struct sp_session *session, const char *path, struct cmd_data *cmd_data) {
    JDM_ENTER_FUNCTION;
    struct sp_channel *channel = NULL;
    enum sp_msg_type type;
    int ret;

    ret = session_check(session);
    if (ret < 0)
        RETURN_ERROR(SP_ERR_NOSESSION, "Cannot open media, session is invalid");

    memcpy(&session->cmd_data, cmd_data, sizeof(*cmd_data));

    if (session->now_streaming_channel)
        RETURN_ERROR(SP_ERR_OCCUPIED, "Already getting media");

    ret = channel_new(&channel, session, path, session->evbase, audio_write_cb, SP_MEDIA_TRACK);
    if (ret < 0)
        RETURN_ERROR(SP_ERR_OOM, "Could not setup a channel");

    session->cmd_data.retval = channel->audio_fd[0];

    // Must be set before calling request_make() because this info is needed for
    // making the request
    session->now_streaming_channel = channel;

    if (channel->file.media_type == SP_MEDIA_TRACK)
        type = MSG_TYPE_MERCURY_TRACK_GET;
    else if (channel->file.media_type == SP_MEDIA_EPISODE)
        type = MSG_TYPE_MERCURY_EPISODE_GET;
    else
        RETURN_ERROR(SP_ERR_INVALID, "Unknown media type in Spotify path");

    // Kicks of a sequence where we first get file info, then get the AES key and
    // then the first chunk (incl. headers)
    ret = request_make(type, session);
    if (ret < 0)
        RETURN_ERROR(ret, sp_errmsg);

    JDM_LEAVE_FUNCTION;
    return 0;

    error:
    if (channel) {
        session->now_streaming_channel = NULL;
        channel_free(channel);
    }
    JDM_LEAVE_FUNCTION;
    return 1;
}

static int
login(struct sp_session **session, struct cmd_data *cmd, const char *username, const char *password,
      const char *stored_cred, size_t stored_cred_len, const char *token, size_t token_len,
      struct event_base *evbase) {
    JDM_ENTER_FUNCTION;
    int ret;

    ret = session_new(session, continue_cb, username, password, stored_cred, stored_cred_len, token, evbase);
    if (ret < 0)
        goto error;
    memcpy(&(*session)->cmd_data, cmd, sizeof(*cmd));

    ret = request_make(MSG_TYPE_CLIENT_HELLO, *session);
    if (ret < 0)
        goto error;

    JDM_LEAVE_FUNCTION;
    return 0; // Pending command_exec_sync, i.e. response from Spotify

    error:
    session_cleanup(*session);

    JDM_LEAVE_FUNCTION;
    return 1;
}

static int
logout(struct sp_session *session) {
    JDM_ENTER_FUNCTION;
    int ret;
    memset(&session->cmd_data, 0, sizeof(session->cmd_data));

    ret = session_check(session);
    if (ret < 0)
        RETURN_ERROR(SP_ERR_NOSESSION, "Session has disappeared, cannot logout");

    session_cleanup(session);

    error:
    JDM_LEAVE_FUNCTION;
    return 0;
}

static int
bitrate_set(struct sp_session *session, enum sp_bitrates bitrate) {
    JDM_ENTER_FUNCTION;
    int ret;
    memset(&session->cmd_data, 0, sizeof(session->cmd_data));

    if (bitrate == SP_BITRATE_ANY)
        bitrate = SP_BITRATE_DEFAULT;

    ret = session_check(session);
    if (ret < 0)
        RETURN_ERROR(SP_ERR_NOSESSION, "Session has disappeared, cannot set bitrate");

    session->bitrate_preferred = bitrate;

    error:
    JDM_LEAVE_FUNCTION;
    return 0;
}


/* ---------------------------------- API ----------------------------------- */

int
librespotc_open(const char *path, struct sp_session *session, cmd_callback cmd_cb, void *cmd_arg) {
    struct cmd_data data = {
            .cb = cmd_cb,
            .userp = cmd_arg
    };
    return media_open(session, path, &data);
}

int
librespotc_seek(struct sp_session *session, size_t pos, cmd_callback cmd_cb, void *cmd_arg) {
    struct cmd_data data = {
            .cb = cmd_cb,
            .userp = cmd_arg
    };
    return track_seek(&data, session, pos);
}

// Starts writing audio for the caller to read from the file descriptor
int
librespotc_write(struct sp_session *session) {
    return track_write(session);
}

int
librespotc_close(struct sp_session *session) {
    return track_pause(NULL, session, true);
}

int
librespotc_login_password(const char *username, const char *password, struct sp_session **session, cmd_callback cmd_cb,
                          void *cb_arg, struct event_base *evbase) {
    struct cmd_data data = {
            .cb = cmd_cb,
            .userp = cb_arg
    };

    return login(session, &data, username, password, NULL, 0, NULL, 0, evbase);
}

int
librespotc_login_stored_cred(const char *username, const char *stored_cred, size_t stored_cred_len,
                             struct sp_session **session, cmd_callback cmd_cb, void *cb_arg,
                             struct event_base *evbase) {
    struct cmd_data data = {
            .cb = cmd_cb,
            .userp = cb_arg
    };

    return login(session, &data, username, NULL, stored_cred, stored_cred_len, NULL, 0, evbase);
}

/*void
librespotc_login_token(const char *username, const char *token, struct sp_session **session,
                       struct event_base *evbase) {
    struct sp_cmdargs *cmdargs;

    cmdargs = calloc(1, sizeof(struct sp_cmdargs));

    assert(cmdargs);

    cmdargs->username = username;
    cmdargs->token = token;
    cmdargs->session_out = session;
    cmdargs->evbase = evbase;

    commands_exec_sync(sp_cmdbase, login, login_bh, cmdargs, SP_CMD_DATA_EMPTY);
}*/

int
librespotc_logout(struct sp_session *session) {
    return logout(session);
}

size_t
librespotc_get_filelen(struct sp_session *session) {
    return 4 * session->now_streaming_channel->file.len_words - SP_OGG_HEADER_LEN;
}

int
librespotc_bitrate_set(struct sp_session *session, enum sp_bitrates bitrate) {
    return bitrate_set(session, bitrate);
}

const char *
librespotc_last_errmsg(void) {
    return sp_errmsg ? sp_errmsg : "(no error)";
}

static void
system_info_set(struct sp_sysinfo *si_out, struct sp_sysinfo *si_user) {
    JDM_ENTER_FUNCTION;
    memcpy(si_out, si_user, sizeof(struct sp_sysinfo));

    if (si_out->client_name[9] == '\0')
        snprintf(si_out->client_name, sizeof(si_out->client_name), SP_CLIENT_NAME_DEFAULT);
    if (si_out->client_version[9] == '\0')
        snprintf(si_out->client_version, sizeof(si_out->client_version), SP_CLIENT_VERSION_DEFAULT);
    if (si_out->client_build_id[9] == '\0')
        snprintf(si_out->client_build_id, sizeof(si_out->client_build_id), SP_CLIENT_BUILD_ID_DEFAULT);
    JDM_LEAVE_FUNCTION;
}

int
librespotc_init(struct sp_sysinfo *sysinfo, struct sp_callbacks *callbacks) {
    JDM_ENTER_FUNCTION;
    int ret;

    if (sp_initialized)
        RETURN_ERROR(SP_ERR_INVALID, "librespot-c already initialized");

    sp_cb = *callbacks;
    sp_initialized = true;

    system_info_set(&sp_sysinfo, sysinfo);
    connection_init_lock();
    crypto_init();

    JDM_LEAVE_FUNCTION;
    return 0;

    error:
    librespotc_deinit();
    JDM_LEAVE_FUNCTION;
    return ret;
}

void
librespotc_deinit() {
    JDM_ENTER_FUNCTION;
    sp_initialized = false;
    memset(&sp_cb, 0, sizeof(struct sp_callbacks));
    connection_free_lock();
    JDM_LEAVE_FUNCTION;
}

int
librespotc_get_session_fd(struct sp_session *session) {
    if (!session || !session->now_streaming_channel) return -1;
    return session->now_streaming_channel->audio_fd[0];
}

void
librespotc_session_error_cb(struct sp_session *session, sp_error_callback cb, void *userp) {
    session->err_userp = userp;
    session->error_callback = cb;
}

char*
librespotc_get_country(struct sp_session *session){
    return session->country;
}
