//
// Created by quartzy on 8/27/22.
//

#ifndef SMP_BACKEND_DEBUG_H
#define SMP_BACKEND_DEBUG_H

#include <stdio.h>

#define fprintf(stream, fmt, ...) fprintf(stream, "%lu:"__FILE__ ":%d:%s(): " fmt, pthread_self(), __LINE__, __func__, ##__VA_ARGS__)
#define printf(...) fprintf(stdout, __VA_ARGS__)

#endif //SMP_BACKEND_DEBUG_H
