//
// Created by quartzy on 7/28/23.
//

#include <string.h>
#include <stdlib.h>
#include "hash_table.h"
#include "jdm.h"

struct hash_table{
    hash_function hash;
    compare_function compare;
    free_function free;
    bool initialized;
    struct hash_table_bucket{
        struct hash_table_element{
            void *key;
            void *value;
        } *elements;
        size_t len, size;
    } buckets[HASH_TABLE_BUCKETS];
};

void hash_table_init(struct hash_table **table, hash_function hash, compare_function compare, free_function free_func){
    if(!table || (*table && (*table)->initialized)) return;
    JDM_ENTER_FUNCTION;
    *table = calloc(1, sizeof(**table));
    (*table)->hash = hash;
    (*table)->compare = compare;
    (*table)->initialized = true;
    (*table)->free = free_func;
    JDM_LEAVE_FUNCTION;
}

void hash_table_put(struct hash_table *table, void *key, void *value){
    if (!table || !table->initialized) return;
    JDM_ENTER_FUNCTION;

    int hash = table->hash(key);

    struct hash_table_bucket *bucket = &table->buckets[hash % HASH_TABLE_BUCKETS];
    for (int i = 0; i < bucket->len; ++i) {
        if (table->compare(bucket->elements[i].key, key)){
            bucket->elements[i].key = key;
            bucket->elements[i].value = value;
            JDM_LEAVE_FUNCTION;
            return;
        }
    }

    if (bucket->len + 1 >= bucket->size){
        bucket->size = bucket->len + 10;
        struct hash_table_element *tmp = realloc(bucket->elements, bucket->size * sizeof(*bucket->elements));
        if (!tmp){
            JDM_ERROR("Error when calling realloc: %s", JDM_ERRNO_MESSAGE);
            JDM_LEAVE_FUNCTION;
            return;
        }
        bucket->elements = tmp;
    }

    bucket->elements[bucket->len].key = key;
    bucket->elements[bucket->len++].value = value;

    JDM_LEAVE_FUNCTION;
}

void* hash_table_get(struct hash_table *table, void *key){
    if (!table || !table->initialized) return NULL;
    JDM_ENTER_FUNCTION;

    int hash = table->hash(key);

    struct hash_table_bucket *bucket = &table->buckets[hash % HASH_TABLE_BUCKETS];
    for (int i = 0; i < bucket->len; ++i) {
        if (table->compare(bucket->elements[i].key, key)){
            bucket->elements[i].key = key;
            JDM_LEAVE_FUNCTION;
            return bucket->elements[i].value;
        }
    }
    JDM_LEAVE_FUNCTION;
    return NULL;
}

void * hash_table_remove(struct hash_table *table, void *key){
    JDM_ENTER_FUNCTION;
    int hash = table->hash(key);
    struct hash_table_bucket *bucket = &table->buckets[hash % HASH_TABLE_BUCKETS];
    void *val;
    for (int i = 0; i < bucket->len; ++i) {
        if (bucket->elements && table->compare(bucket->elements[i].key, key)) {
            val = bucket->elements[i].value;
            if (i != bucket->len - 1)
                memmove(&bucket->elements[i], &bucket->elements[i+1], bucket->len-(i+1));
            bucket->len--;
            JDM_LEAVE_FUNCTION;
            return val;
        }
    }
    JDM_LEAVE_FUNCTION;
    return NULL;
}

void hash_table_free(struct hash_table *table){
    if (!table || !table->initialized) return;
    JDM_ENTER_FUNCTION;

    for (int i = 0; i < HASH_TABLE_BUCKETS; ++i) {
        if (table->free){
            for (int j = 0; j < table->buckets[i].len; ++j) {
                table->free(table->buckets[i].elements[j].key, table->buckets[i].elements[j].value);
            }
        }
        free(table->buckets[i].elements);
    }
    memset(table, 0, sizeof(*table));

    JDM_LEAVE_FUNCTION;
}