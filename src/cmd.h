//
// Created by quartzy on 8/21/22.
//

#ifndef SMP_BACKEND_CMD_H
#define SMP_BACKEND_CMD_H

typedef void (*cmd_callback)(int cmd_ret, void *userp);

struct cmd_data {
    void *userp;
    int retval;
    cmd_callback cb;
};

#endif //SMP_BACKEND_CMD_H
