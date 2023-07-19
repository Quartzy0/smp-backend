//
// Created by quartzy on 8/23/22.
//

#include <stdlib.h>
#include <string.h>
#define JDM_STACKTRACE
#include <jdm.h>
#include "vec.h"

#define CHECK_ERROR(expr) { \
    if((expr) != 0) {       \
        JDM_ERROR(#expr " (was non 0): %s", strerror(errno)); \
        return -1;\
    }                            \
}

int
vec_init(struct vec *vec) {
    JDM_ENTER_FUNCTION;
    vec->size = VEC_INITIAL_SIZE;
    vec->el = calloc(VEC_INITIAL_SIZE, sizeof(*vec->el));
    CHECK_ERROR(!vec->el);
    vec->len = 0;
//    CHECK_ERROR(pthread_mutex_init(&vec->mutex, NULL));
    JDM_LEAVE_FUNCTION;
    return 0;
}

int
vec_init_with_size(struct vec *vec, size_t initial) {
    JDM_ENTER_FUNCTION;
    vec->size = initial;
    vec->el = calloc(initial, sizeof(*vec->el));
    CHECK_ERROR(!vec->el);
    vec->len = 0;
//    CHECK_ERROR(pthread_mutex_init(&vec->mutex, NULL));
    JDM_LEAVE_FUNCTION;
    return 0;
}

int
vec_add(struct vec *vec, void *el) {
    if (!vec) return 0;
//    CHECK_ERROR(pthread_mutex_lock(&vec->mutex));
    JDM_ENTER_FUNCTION;
    if (vec->size <= vec->len + 1) {
        void **realloc_tmp = realloc(vec->el, (vec->size + VEC_SIZE_STEP) * sizeof(*realloc_tmp));
        CHECK_ERROR(!realloc_tmp);
        vec->el = realloc_tmp;
        vec->size += VEC_SIZE_STEP;
    }
    vec->el[vec->len++] = el;
//    CHECK_ERROR(pthread_mutex_unlock(&vec->mutex));
    JDM_LEAVE_FUNCTION;
    return 0;
}

int
vec_remove_index(struct vec *vec, size_t index) {
    if (!vec || index >= vec->len) return 1;
//    CHECK_ERROR(pthread_mutex_lock(&vec->mutex));
    JDM_ENTER_FUNCTION;
    memmove(&vec->el[index], &vec->el[index + 1], sizeof(*vec->el) * (vec->len - index - 1));
    vec->len--;
//    CHECK_ERROR(pthread_mutex_unlock(&vec->mutex));
    JDM_LEAVE_FUNCTION;
    return 0;
}

int
vec_remove_element(struct vec *vec, void *el) {
    if (!vec || !el) return 1;
//    CHECK_ERROR(pthread_mutex_lock(&vec->mutex));
    JDM_ENTER_FUNCTION;
    size_t i;
    for (i = 0; i < vec->len; ++i) {
        if (vec->el[i] == el) break;
    }
    if (i != vec->len) {
        memmove(&vec->el[i], &vec->el[i + 1], sizeof(*vec->el) * (vec->len - i - 1));
        vec->len--;
    }
//    CHECK_ERROR(pthread_mutex_unlock(&vec->mutex));
    JDM_LEAVE_FUNCTION;
    return i == vec->len;
}

int
vec_remove_all(struct vec *vec) {
    JDM_ENTER_FUNCTION;
    memset(vec->el, 0, sizeof(*vec->el) * vec->len);
    vec->len = 0;
    JDM_LEAVE_FUNCTION;
    return 0;
}

int
vec_free(struct vec *vec) {
    if (!vec) return 0;
//    CHECK_ERROR(pthread_mutex_destroy(&vec->mutex));
    JDM_ENTER_FUNCTION;
    free(vec->el);
    memset(vec, 0, sizeof(*vec));
    JDM_LEAVE_FUNCTION;
    return 0;
}


int
vec_direct_init_with_size(struct vec_direct *vec, size_t el_size, size_t initial) {
    JDM_ENTER_FUNCTION;
    vec->size = initial;
    vec->el_size = el_size;
    vec->el = calloc(initial, vec->el_size);
    CHECK_ERROR(!vec->el);
    vec->len = 0;
//    CHECK_ERROR(pthread_mutex_init(&vec->mutex, NULL));
    JDM_LEAVE_FUNCTION;
    return 0;
}

int
vec_direct_init(struct vec_direct *vec, size_t el_size) {
    return vec_direct_init_with_size(vec, el_size, VEC_INITIAL_SIZE);
}

int
vec_direct_add(struct vec_direct *vec, void *el) {
    if (!vec) return 0;
//    CHECK_ERROR(pthread_mutex_lock(&vec->mutex));
    JDM_ENTER_FUNCTION;
    if (vec->size <= vec->len + 1) {
        void *realloc_tmp = realloc(vec->el, (vec->size + VEC_SIZE_STEP) * vec->el_size);
        CHECK_ERROR(!realloc_tmp);
        vec->el = realloc_tmp;
        vec->size += VEC_SIZE_STEP;
    }
    memcpy(vec->el + (vec->len++ * vec->el_size), el, vec->el_size);
//    CHECK_ERROR(pthread_mutex_unlock(&vec->mutex));
    JDM_LEAVE_FUNCTION;
    return 0;
}

int
vec_direct_remove_index(struct vec_direct *vec, size_t index) {
    if (!vec || index >= vec->len) return 1;
//    CHECK_ERROR(pthread_mutex_lock(&vec->mutex));
    JDM_ENTER_FUNCTION;
    memmove(vec->el + (index * vec->el_size), vec->el + ((index + 1) * vec->el_size), vec->el_size * (vec->len - index - 1));
    vec->len--;
//    CHECK_ERROR(pthread_mutex_unlock(&vec->mutex));
    JDM_LEAVE_FUNCTION;
    return 0;
}

int
vec_direct_remove_element(struct vec_direct *vec, void *el) {
    if (!vec || !el) return 1;
//    CHECK_ERROR(pthread_mutex_lock(&vec->mutex));
    JDM_ENTER_FUNCTION;
    for (size_t i = 0; i < vec->len; ++i) {
        if (!memcmp(vec->el + (i*vec->el_size), el, vec->el_size)){
            return vec_direct_remove_index(vec, i);
        }
    }
//    CHECK_ERROR(pthread_mutex_unlock(&vec->mutex));
    JDM_LEAVE_FUNCTION;
    return 1;
}

int
vec_direct_free(struct vec_direct *vec) {
    if (!vec) return 0;
//    CHECK_ERROR(pthread_mutex_destroy(&vec->mutex));
    JDM_ENTER_FUNCTION;
    free(vec->el);
    memset(vec, 0, sizeof(*vec));
    JDM_LEAVE_FUNCTION;
    return 0;
}