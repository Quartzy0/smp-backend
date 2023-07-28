//
// Created by quartzy on 7/28/23.
//

#ifndef SMP_BACKEND_HASH_TABLE_H
#define SMP_BACKEND_HASH_TABLE_H

#include <stdbool.h>

#ifndef HASH_TABLE_BUCKETS
#define HASH_TABLE_BUCKETS 50
#endif

struct hash_table;

typedef int (*hash_function)(void *key);
typedef bool (*compare_function)(void *key, void *key1);
typedef void (*free_function)(void *key, void *value);

void hash_table_init(struct hash_table **table, hash_function hash, compare_function compare, free_function free_func);

void hash_table_put(struct hash_table *table, void *key, void *value);

void* hash_table_get(struct hash_table *table, void *key);

void * hash_table_remove(struct hash_table *table, void *key);

void hash_table_free(struct hash_table *table);

#endif //SMP_BACKEND_HASH_TABLE_H
