
#ifndef SRC_COMMANDS_H_
#define SRC_COMMANDS_H_

#include <event2/event.h>
#include "../../../src/cmd.h"

enum command_state {
    COMMAND_END = 0,
    COMMAND_PENDING = 1,
};

/*
 * Function that will be executed in the event loop thread.
 *
 * If the function has pending events to complete, it needs to return 
 * COMMAND_PENDING with 'ret' set to the number of pending events to wait for.
 *
 * If the function returns with  COMMAND_END, command execution will proceed
 * with the "bottem half" function (if passed to the command_exec function) only
 * if 'ret' is 0.
 *
 * @param arg Opaque pointer passed by command_exec_sync or command_exec_async
 * @param ret Pointer to the return value for the caller of the command
 * @return    COMMAND_END if there are no pending events (function execution is 
 *            complete) or COMMAND_PENDING if there are pending events
 */
struct command;
struct sp_session;

typedef enum command_state (*command_function)(void *arg, int *ret, struct command *cmd);

typedef void (*command_exit_cb)(void);


struct commands_base;


struct commands_base *
commands_base_new(struct event_base *evbase, command_exit_cb exit_cb, int fd);

int
commands_base_free(struct commands_base *cmdbase);

int
commands_exec_returnvalue(struct sp_session *session);

void
commands_exec_end(struct commands_base *cmdbase, int retvalue, struct sp_session *session);

int
commands_exec_sync(struct commands_base *cmdbase, command_function func, command_function func_bh, void *arg,
                   struct cmd_data data);

int
commands_exec_async(struct commands_base *cmdbase, command_function func, void *arg);

void
commands_base_destroy(struct commands_base *cmdbase);

#endif /* SRC_COMMANDS_H_ */
