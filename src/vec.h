//
// Created by quartzy on 8/23/22.
//

#ifndef SMP_BACKEND_VEC_H
#define SMP_BACKEND_VEC_H

#include <pthread.h>

#ifndef VEC_INITIAL_SIZE
#define VEC_INITIAL_SIZE 50
#endif
#ifndef VEC_SIZE_STEP
#define VEC_SIZE_STEP VEC_INITIAL_SIZE
#endif

struct vec {
    void **el;
    pthread_mutex_t mutex;
    size_t len;
    size_t size;
};

int
vec_init(struct vec *vec);

int
vec_init_with_size(struct vec *vec, size_t initial);

int
vec_add(struct vec *vec, void *el);

int
vec_remove_index(struct vec *vec, size_t index);

int
vec_remove_element(struct vec *vec, void *el);

int
vec_free(struct vec *vec);

#endif //SMP_BACKEND_VEC_H
