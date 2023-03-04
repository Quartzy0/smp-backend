//
// Created by quartzy on 8/27/22.
//

#ifndef SMP_BACKEND_DEBUG_H
#define SMP_BACKEND_DEBUG_H

#include <stdio.h>
#include <time.h>

#define fprintf(stream, fmt, ...) do{ \
    char buf[9];                    \
    time_t timer = time(NULL);      \
    struct tm *tm_info = localtime(&timer); \
    strftime(buf, 9, "%H:%M:%S", tm_info);\
    fprintf(stream, "%s:"__FILE__ ":%d:%s(): " fmt, buf, __LINE__, __func__, ##__VA_ARGS__); \
}while(0)
#define printf(...) fprintf(stdout, __VA_ARGS__)

#endif //SMP_BACKEND_DEBUG_H
