//
// Created by quartzy on 4/27/23.
//

#include "config.h"
#include "util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

size_t get_mul(char c) {
    switch (c) {
        case 'k':
        case 'K':
            return 1024L;
        case 'm':
        case 'M':
            return 1024L * 1024L;
        case 'g':
        case 'G':
            return 1024L * 1024L * 1024L;
        case 't':
        case 'T':
            return 1024L * 1024L * 1024L * 1024L;
        case 'p':
        case 'P':
            return 1024L * 1024L * 1024L * 1024L * 1024L;
        default:
            return 1L;
    }
    return 1L;
}

size_t parse_num(const char *str) {
    char *endptr = NULL;
    size_t out = strtol(str, &endptr, 10);
    if (endptr == str) {
        return -1;
    }
    return out * get_mul(*endptr);
}

#define PARSE_NUM_PROPERTY(config, name, default_value) do{                                         \
    char *ret;                                                                                      \
    if((ret = strstr(buf, #name":"))){                                                              \
        ret += sizeof(#name":")-1;                                                                  \
        (config)->name = parse_num(ret);                                                            \
        if((config)->name == -1){                                                                   \
            fprintf(stderr, "Error when parsing config: Invalid number provided for " #name "\n");  \
        }                                                                                           \
    }else{                                                                                          \
        config_out->name = default_value;                                                           \
    }                                                                                               \
}while(0)

#define PARSE_STRING_PROPERTY(config, name, prefix, default_value) do{                              \
    char *ret, *endl;                                                                               \
    if((ret = strstr(buf, #name":"))){                                                              \
        ret += sizeof(#name":")-1;                                                                  \
        while(isspace(*ret)){ret++;}                                                                \
        endl = strchr(ret, '\n');                                                                   \
        (config)->name = malloc(endl-ret + 1);                                                      \
        memcpy((config)->name, ret, endl-ret);                                                      \
        (config)->name[endl-ret] = 0;                                                               \
    }else{                                                                                          \
        if(!(prefix)){                                                                              \
            (config)->name = (default_value) ? strdup(default_value) : NULL;                        \
            break;                                                                                  \
        }                                                                                           \
        if(!(default_value)){                                                                       \
            (config)->name = strdup(prefix);                                                        \
            break;                                                                                  \
        }                                                                                           \
        size_t prefix_len = strlen(prefix), def_len = strlen(default_value);                        \
        (config)->name = malloc(prefix_len + def_len + 1);                                          \
        memcpy((config)->name, prefix, prefix_len);                                                 \
        memcpy(&(config)->name[prefix_len], default_value, def_len);                                \
        (config)->name[prefix_len+def_len] = 0;                                                     \
    }                                                                                               \
}while(0)

int
parse_config(const char *file, struct smp_config *config_out) {
    FILE *fp = fopen(file, "r");
    size_t file_len = 1;
    if (fp){
        fseek(fp, 0, SEEK_END);
        file_len = ftell(fp);
        rewind(fp);
    }
    char buf[file_len];
    if(file_len != 1){
        fread(buf, file_len, 1, fp);
        fclose(fp);
    }else{
        memset(buf, 0, file_len);
    }

    PARSE_NUM_PROPERTY(config_out, total_cache_max, -1);
    if (config_out->total_cache_max == -1) {
        PARSE_NUM_PROPERTY(config_out, music_info_cache_max, -1);
        PARSE_NUM_PROPERTY(config_out, music_data_cache_max, -1);
        PARSE_NUM_PROPERTY(config_out, album_info_cache_max, -1);
        PARSE_NUM_PROPERTY(config_out, playlist_info_cache_max, -1);
    }
    PARSE_STRING_PROPERTY(config_out, global_cache_path, NULL, NULL);
    if (!config_out->global_cache_path) {
        PARSE_STRING_PROPERTY(config_out, music_info_cache_path, config_out->global_cache_path, "music_info");
        PARSE_STRING_PROPERTY(config_out, music_data_cache_path, config_out->global_cache_path, "music_cache");
        PARSE_STRING_PROPERTY(config_out, album_info_cache_path, config_out->global_cache_path, "album_info");
        PARSE_STRING_PROPERTY(config_out, playlist_info_cache_path, config_out->global_cache_path, "playlist_info");
    }

    int cpu_cores = get_cpu_cores();
    PARSE_NUM_PROPERTY(config_out, worker_threads, cpu_cores-1);

    return 0;
}

#define PRINT_PROPERTY_INT(g, p) printf(#p":%zu\n", (g)->p)
#define PRINT_PROPERTY_STRING(g, p) printf(#p":%s\n", (g)->p)

void
print_config(struct smp_config *config) {
    PRINT_PROPERTY_INT(config, total_cache_max);
    PRINT_PROPERTY_INT(config, music_info_cache_max);
    PRINT_PROPERTY_INT(config, music_data_cache_max);
    PRINT_PROPERTY_INT(config, album_info_cache_max);
    PRINT_PROPERTY_INT(config, playlist_info_cache_max);

    PRINT_PROPERTY_STRING(config, global_cache_path);
    PRINT_PROPERTY_STRING(config, music_info_cache_path);
    PRINT_PROPERTY_STRING(config, music_data_cache_path);
    PRINT_PROPERTY_STRING(config, album_info_cache_path);
    PRINT_PROPERTY_STRING(config, playlist_info_cache_path);

    PRINT_PROPERTY_INT(config, worker_threads);
}

void free_config(struct smp_config *config) {
    free(config->global_cache_path);
    free(config->album_info_cache_path);
    free(config->playlist_info_cache_path);
    free(config->music_data_cache_path);
    free(config->music_info_cache_path);
    memset(config, 0, sizeof(*config));
}
