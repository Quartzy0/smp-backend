//
// Created by quartzy on 8/23/22.
//

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "vec.h"

#define CHECK_ERROR(expr) { \
    if((expr) != 0) {       \
        perror(#expr " (was non 0)"); \
        return -1;\
    }                            \
}

int
vec_init(struct vec *vec) {
    vec->size = VEC_INITIAL_SIZE;
    vec->el = calloc(VEC_INITIAL_SIZE, sizeof(*vec->el));
    CHECK_ERROR(!vec->el);
    vec->len = 0;
    CHECK_ERROR(pthread_mutex_init(&vec->mutex, NULL));
    return 0;
}

int
vec_init_with_size(struct vec *vec, size_t initial) {
    vec->size = initial;
    vec->el = calloc(initial, sizeof(*vec->el));
    CHECK_ERROR(!vec->el);
    vec->len = 0;
    CHECK_ERROR(pthread_mutex_init(&vec->mutex, NULL));
    return 0;
}

int
vec_add(struct vec *vec, void *el) {
    if (!vec) return 0;
    CHECK_ERROR(pthread_mutex_lock(&vec->mutex));
    if (vec->size <= vec->len + 1) {
        void **realloc_tmp = realloc(vec->el, vec->size + VEC_SIZE_STEP);
        CHECK_ERROR(!realloc_tmp);
        vec->el = realloc_tmp;
        vec->size += VEC_SIZE_STEP;
    }
    vec->el[vec->len++] = el;
    CHECK_ERROR(pthread_mutex_unlock(&vec->mutex));
    return 0;
}

int
vec_remove_index(struct vec *vec, size_t index) {
    if (!vec || index >= vec->len) return 1;
    CHECK_ERROR(pthread_mutex_lock(&vec->mutex));
    memmove(&vec->el[index], &vec->el[index + 1], sizeof(*vec->el) * (vec->len - index - 1));
    vec->len--;
    CHECK_ERROR(pthread_mutex_unlock(&vec->mutex));
    return 0;
}

int
vec_remove_element(struct vec *vec, void *el) {
    if (!vec || !el) return 1;
    CHECK_ERROR(pthread_mutex_lock(&vec->mutex));
    size_t i;
    for (i = 0; i < vec->len; ++i) {
        if (vec->el[i] == el) break;
    }
    if (i != vec->len) {
        memmove(&vec->el[i], &vec->el[i + 1], sizeof(*vec->el) * (vec->len - i - 1));
        vec->len--;
    }
    CHECK_ERROR(pthread_mutex_unlock(&vec->mutex));
    return i == vec->len;
}

int
vec_free(struct vec *vec) {
    if (!vec) return 0;
    CHECK_ERROR(pthread_mutex_destroy(&vec->mutex));
    free(vec->el);
    memset(vec, 0, sizeof(*vec));
    return 0;
}