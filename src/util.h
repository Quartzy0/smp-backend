//
// Created by quartzy on 4/24/23.
//

#ifndef SMP_BACKEND_UTIL_H
#define SMP_BACKEND_UTIL_H

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

size_t get_dir_size(const char *path);

size_t delete_older_files(const char *path, time_t older_than);

// The parameters after size_requirements are all expected to be const char* and the last one should be NULL
size_t delete_oldest_until_size_requirement(size_t size_requirement, ...);

int get_cpu_cores();

bool is_valid_id(uint8_t *id);

#endif //SMP_BACKEND_UTIL_H
