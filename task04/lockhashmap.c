#include "chashmap.h"
#include "cspinlock.h"
#include <stdlib.h>
#include <stdio.h>

// node for each value in the list
typedef struct Node_HM_t {
    long m_val;
    char padding[PAD];
    struct Node_HM_t* m_next;
} Node_HM;

// one lock and sentinel per bucket
typedef struct List_t {
    Node_HM* sentinel;
    cspinlock_t* lock;
} List;

// hashmap struct
struct hm_t {
    List** buckets;
    size_t n_buckets;
};

// hash function, mixes bits for better spread
static size_t hash(long val, size_t n_buckets) {
    unsigned long x = (unsigned long)val;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = (x >> 16) ^ x;
    return x % n_buckets;
}

// allocate hashmap, each bucket gets lock and sentinel
HM* alloc_hashmap(size_t n_buckets) {
    HM* hm = malloc(sizeof(HM));
    if (!hm) return NULL;
    hm->n_buckets = n_buckets;
    hm->buckets = calloc(n_buckets, sizeof(List*));
    if (!hm->buckets) {
        free(hm);
        return NULL;
    }
    for (size_t i = 0; i < n_buckets; ++i) {
        hm->buckets[i] = malloc(sizeof(List));
        if (!hm->buckets[i]) continue;
        hm->buckets[i]->lock = cspin_alloc();
        hm->buckets[i]->sentinel = malloc(sizeof(Node_HM));
        if (!hm->buckets[i]->sentinel) continue;
        hm->buckets[i]->sentinel->m_next = NULL;
        hm->buckets[i]->sentinel->m_val = 0;
    }
    return hm;
}

// free all buckets, nodes and locks
void free_hashmap(HM* hm) {
    if (!hm) return;
    for (size_t i = 0; i < hm->n_buckets; ++i) {
        List* bucket = hm->buckets[i];
        if (bucket) {
            Node_HM* node = bucket->sentinel;
            while (node) {
                Node_HM* tmp = node->m_next;
                free(node);
                node = tmp;
            }
            cspin_free(bucket->lock);
            free(bucket);
        }
    }
    free(hm->buckets);
    free(hm);
}

// insert at head of bucket list, lock per bucket
int insert_item(HM* hm, long val) {
    if (!hm) return 1;
    size_t idx = hash(val, hm->n_buckets);
    List* bucket = hm->buckets[idx];
    if (!bucket) return 1;
    cspin_lock(bucket->lock);
    Node_HM* node = malloc(sizeof(Node_HM));
    if (!node) {
        cspin_unlock(bucket->lock);
        return 1;
    }
    node->m_val = val;
    node->m_next = bucket->sentinel->m_next;
    bucket->sentinel->m_next = node;
    cspin_unlock(bucket->lock);
    return 0;
}

// remove item if found, lock per bucket
int remove_item(HM* hm, long val) {
    if (!hm) return 1;
    size_t idx = hash(val, hm->n_buckets);
    List* bucket = hm->buckets[idx];
    if (!bucket) return 1;
    cspin_lock(bucket->lock);
    Node_HM* prev = bucket->sentinel;
    Node_HM* curr = prev->m_next;
    while (curr) {
        if (curr->m_val == val) {
            prev->m_next = curr->m_next;
            free(curr);
            cspin_unlock(bucket->lock);
            return 0;
        }
        prev = curr;
        curr = curr->m_next;
    }
    cspin_unlock(bucket->lock);
    return 1;
}

// search item, lock per bucket
int lookup_item(HM* hm, long val) {
    if (!hm) return 1;
    size_t idx = hash(val, hm->n_buckets);
    List* bucket = hm->buckets[idx];
    if (!bucket) return 1;
    cspin_lock(bucket->lock);
    Node_HM* curr = bucket->sentinel->m_next;
    while (curr) {
        if (curr->m_val == val) {
            cspin_unlock(bucket->lock);
            return 0;
        }
        curr = curr->m_next;
    }
    cspin_unlock(bucket->lock);
    return 1;
}

// print all buckets and their items, lock per bucket
void print_hashmap(HM* hm) {
    if (!hm) return;
    for (size_t i = 0; i < hm->n_buckets; ++i) {
        List* bucket = hm->buckets[i];
        printf("Bucket %zu", i + 1);
        cspin_lock(bucket->lock);
        Node_HM* curr = bucket->sentinel->m_next;
        while (curr) {
            printf(" - %ld", curr->m_val);
            curr = curr->m_next;
        }
        cspin_unlock(bucket->lock);
        printf("\n");
    }
}