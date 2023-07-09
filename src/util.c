//
// Created by quartzy on 4/24/23.
//

#include "util.h"
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>

void
write_error(int fd, enum error_type err, const char *msg) {
    if (fd == -1) return;
    JDM_ENTER_FUNCTION;
    char data[1 + sizeof(size_t)];
    data[0] = err;

    if (msg) {
        size_t len = strlen(msg);
        memcpy(&data[1], &len, sizeof(len));
        write(fd, data, sizeof(data));
        write(fd, msg, len * sizeof(*msg));
    } else {
        memset(&data[1], 0, sizeof(size_t));
        write(fd, data, sizeof(data));
    }
    JDM_LEAVE_FUNCTION;
}

size_t
get_dir_size(const char *path){
    DIR *dir = opendir(path);
    if(!dir) return -1;

    size_t size = 0;
    struct dirent *dp;
    struct stat file_stat;
    while((dp = readdir(dir))){
        if(dp->d_type != DT_REG) continue;
        if(!fstatat(dirfd(dir), dp->d_name, &file_stat, 0)){
            size += file_stat.st_size;
        }
    }
    closedir(dir);
    return size;
}

size_t
delete_older_files(const char *path, time_t older_than) {
    DIR *dir = opendir(path);
    if(!dir) return -1;

    size_t deleted = 0;
    time_t ctime = time(NULL);

    size_t path_len = strlen(path), filename_size = path_len + 40;
    char *filename = calloc(path_len + 40, sizeof(*filename));
    memcpy(filename, path, path_len);
    filename[path_len] = '/';

    struct dirent *dp;
    struct stat file_stat;
    while((dp = readdir(dir))){
        if(dp->d_type != DT_REG) continue;
        if(!fstatat(dirfd(dir), dp->d_name, &file_stat, 0)){
            if(ctime-file_stat.st_atim.tv_sec>older_than){
                size_t namesize = strlen(dp->d_name);
                if(filename_size-path_len-1<=namesize+1){
                    filename_size *= 2;
                    char *tmp = realloc(filename, filename_size * sizeof(*filename));
                    if(!tmp) perror("error when calling realloc()");
                    filename = tmp;
                }
                memcpy(&filename[path_len+1], dp->d_name, namesize);
                filename[path_len+1+namesize] = 0;

                remove(filename);
                deleted++;
            }
        }
    }
    closedir(dir);
    return deleted;
}

struct sdir_ent{
    char name[1024];
    struct timespec atime;
    size_t size;
};

int
sdir_ent_comprar(const void *a, const void *b){
    return (int) (((const struct sdir_ent*)a)->atime.tv_sec-((const struct sdir_ent*)b)->atime.tv_sec);
}

size_t
read_dir_files(const char *path, size_t *files_size, size_t *files_len, struct sdir_ent **files){
    JDM_ENTER_FUNCTION;
    DIR *dir = opendir(path);
    if(!dir) {
        JDM_LEAVE_FUNCTION;
        return -1;
    }

    size_t total_size = 0;

    size_t path_len = strlen(path), filename_size = path_len + 40;
    char *filename = calloc(path_len + 40, sizeof(*filename));
    memcpy(filename, path, path_len);
    filename[path_len] = '/';

    struct dirent *dp;
    struct stat file_stat;
    while((dp = readdir(dir))){
        if(dp->d_type != DT_REG) continue;
        if(!fstatat(dirfd(dir), dp->d_name, &file_stat, 0)){
            if(*files_size<=*files_len+1){
                *files_size = *files_size * 2;
                struct sdir_ent *tmp = realloc(*files, *files_size * sizeof(*tmp));
                if(!tmp) perror("error when calling realloc()");
                *files = tmp;
            }

            size_t namesize = strlen(dp->d_name);
            if(filename_size-path_len-1<=namesize+1){
                filename_size *= 2;
                char *tmp = realloc(filename, filename_size * sizeof(*filename));
                if(!tmp) perror("error when calling realloc()");
                filename = tmp;
            }
            memcpy(&filename[path_len+1], dp->d_name, namesize);
            filename[path_len+1+namesize] = 0;
            if(path_len+1+namesize+1 > sizeof((*files)[*files_size].name)) {
                total_size += file_stat.st_size;
                JDM_ERROR("Name of file was longer than 1024 characters! ('%s')", filename);
                continue;
            }

            memcpy((*files)[*files_len].name, filename, path_len+namesize+2);
            memcpy(&(*files)[*files_len].atime, &file_stat.st_atim, sizeof((*files)[*files_len].atime));
            (*files)[*files_len].size = file_stat.st_size;
            *files_len = *files_len + 1;
            total_size += file_stat.st_size;
        }
    }
    closedir(dir);
    free(filename);

    JDM_LEAVE_FUNCTION;
    return total_size;
}

size_t
delete_oldest_until_size_requirement(size_t size_requirement, ...) {
    JDM_ENTER_FUNCTION;
    size_t files_size = 100, files_len = 0;
    struct sdir_ent *files = calloc(files_size, sizeof(*files));
    size_t total_size = 0;

    va_list ap;
    va_start(ap, size_requirement);
    const char *path;
    while ((path = va_arg(ap, const char*))){
        total_size += read_dir_files(path, &files_size, &files_len, &files);
    }
    va_end(ap);

    if(total_size <= size_requirement){
        free(files);
        return 0;
    }

    if(files_size!=files_len){
        files_size = files_len;
        struct sdir_ent *tmp = realloc(files, files_size * sizeof(*tmp));
        if(!tmp) JDM_ERROR("error when calling realloc(): %s", JDM_ERRNO_MESSAGE);
        files = tmp;
    }
    qsort(files, files_len, sizeof(*files), sdir_ent_comprar);


    size_t deleted = 0;

    for (int i = 0; i < files_len; ++i) {
        remove(files[i].name);
        deleted++;
        total_size -= files[i].size;
        if(total_size<=size_requirement) break;
    }
    free(files);
    JDM_LEAVE_FUNCTION;
    return deleted;
}

/* Solution taken from: https://stackoverflow.com/a/3006416 */
#ifdef _WIN32
#include <windows.h>
#elif MACOS
#include <sys/param.h>
#include <sys/sysctl.h>
#else
#include <ctype.h>
#include <sigsegv.h>

#endif

int
get_cpu_cores() {
#ifdef WIN32
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return sysinfo.dwNumberOfProcessors;
#elif MACOS
    int nm[2];
    size_t len = 4;
    uint32_t count;

    nm[0] = CTL_HW; nm[1] = HW_AVAILCPU;
    sysctl(nm, 2, &count, &len, NULL, 0);

    if(count < 1) {
        nm[1] = HW_NCPU;
        sysctl(nm, 2, &count, &len, NULL, 0);
        if(count < 1) { count = 1; }
    }
    return count;
#else
    return sysconf(_SC_NPROCESSORS_ONLN);
#endif
}

bool
is_valid_id(uint8_t *id) {
    if (!id) return false;
    if (memchr(id, '\0', 22)) return false; // If string is shorter than the minimum length
    for (int i = 0; i < 22; ++i) {
        if (!isalnum(id[i])) return false;
    }
    return true;
}

int error_message_hook(const char *thread_name, uint32_t stack_trace_count, const char *const *stack_trace,
                       jdm_message_level level, uint32_t line, const char *file, const char *function,
                       const char *message, void *param) {
    switch (level) {
        case JDM_MESSAGE_LEVEL_NONE:
        case JDM_MESSAGE_LEVEL_DEBUG:
        case JDM_MESSAGE_LEVEL_TRACE:
        case JDM_MESSAGE_LEVEL_INFO:
        case JDM_MESSAGE_LEVEL_WARN: {
            printf("%s [%s] %s:%d %s: %s\n", jdm_message_level_str(level), thread_name, file, line, function, message);
            break;
        }
        case JDM_MESSAGE_LEVEL_ERR:
        case JDM_MESSAGE_LEVEL_CRIT: {
            fprintf(stderr, "%s [%s] %s:%d %s: %s\n", jdm_message_level_str(level), thread_name, file, line, function, message);
            for (size_t j = stack_trace_count - 1; j > 0; --j) {
                fprintf(stderr, "\t^- %s\n", stack_trace[j]);
            }
            fprintf(stderr, "\t^- %s\n", stack_trace[0]);
            break;
        }
    }
    return 0;
}

void sigsegv_handler(int sig){
    if (sig != SIGSEGV) return;

    const char*const* stack_trace;
    uint32_t stack_trace_count;
    jdm_get_stacktrace(&stack_trace, &stack_trace_count);
    const char *thread_name = jdm_get_thread_name();

    static const char sigsegv_message_prefix[] = "Fatal [";
    static const char sigsegv_message[] = "] SIGSEGV occurred. Exiting. Callstack:\n";
    write(STDERR_FILENO, sigsegv_message_prefix, sizeof(sigsegv_message_prefix));
    write(STDERR_FILENO, thread_name, strlen(thread_name));
    write(STDERR_FILENO, sigsegv_message, sizeof(sigsegv_message));

    static const char function_prefix[] = {'\t', '^', '-', ' '};
    static const char newline = '\n';
    for (uint32_t i = stack_trace_count-1; i > 0; --i) {
        write(STDERR_FILENO, function_prefix, sizeof(function_prefix));
        write(STDERR_FILENO, stack_trace[i], strlen(stack_trace[i]));
        write(STDERR_FILENO, &newline, sizeof(newline));
    }
    write(STDERR_FILENO, function_prefix, sizeof(function_prefix));
    write(STDERR_FILENO, stack_trace[0], strlen(stack_trace[0]));
    write(STDERR_FILENO, &newline, sizeof(newline));
    exit(EXIT_FAILURE);
}

int set_sigsegv_handler() {
    struct sigaction action = {
            .sa_handler = sigsegv_handler,
            .sa_mask = SIGSEGV,
            .sa_flags = 0
    };
    return sigaction(SIGSEGV, &action, NULL);
}
