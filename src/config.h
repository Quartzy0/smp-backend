//
// Created by quartzy on 4/27/23.
//

#ifndef SMP_BACKEND_CONFIG_H
#define SMP_BACKEND_CONFIG_H

#include <stddef.h>

struct smp_config{
    size_t total_cache_max; // If total_cache_max is set the rest of the cache restriction aren't
    size_t music_info_cache_max;
    size_t music_data_cache_max;
    size_t album_info_cache_max;
    size_t playlist_info_cache_max;

    char *global_cache_path; // If global cache path is set the rest are considered to be subdirectories of it
    char *music_info_cache_path;
    char *music_data_cache_path;
    char *album_info_cache_path;
    char *playlist_info_cache_path;

    size_t worker_threads; // In total there will be one more thread than the number of worker threads (the main thread)
};

int parse_config(const char *file, struct smp_config *config_out);
void print_config(struct smp_config *config);

#endif //SMP_BACKEND_CONFIG_H
