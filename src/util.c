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
    DIR *dir = opendir(path);
    if(!dir) return -1;

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
                fprintf(stderr, "Name of file was longer than 1024 characters! ('%s')\n", filename);
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

    return total_size;
}

size_t
delete_oldest_until_size_requirement(size_t size_requirement, ...) {

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
        if(!tmp) perror("error when calling realloc()");
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
    return deleted;
}

/* Solution taken from: https://stackoverflow.com/a/3006416 */
#ifdef _WIN32
#include <windows.h>
#elif MACOS
#include <sys/param.h>
#include <sys/sysctl.h>
#else
#include <unistd.h>
#include <ctype.h>

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