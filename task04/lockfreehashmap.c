#include "chashmap.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <stdio.h>

typedef struct Node_HM_t {
    long m_val;
    char padding[PAD];
    _Atomic(struct Node_HM_t*) m_next;
} Node_HM;

typedef struct List_t {
    _Atomic(Node_HM*) sentinel;
} List;

struct hm_t {
    List** buckets;
    size_t n_buckets;
};

static size_t hash(long val, size_t n_buckets) {
    return ((unsigned long)val) % n_buckets;
}

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
        Node_HM* sentinel = malloc(sizeof(Node_HM));
        if (!sentinel) continue;
        sentinel->m_next = NULL;
        hm->buckets[i]->sentinel = sentinel;
    }
    return hm;
}

void free_hashmap(HM* hm) {
    if (!hm) return;
    for (size_t i = 0; i < hm->n_buckets; ++i) {
        List* bucket = hm->buckets[i];
        if (bucket) {
            Node_HM* node = atomic_load(&bucket->sentinel);
            while (node) {
                Node_HM* tmp = atomic_load(&node->m_next);
                free(node);
                node = tmp;
            }
            free(bucket);
        }
    }
    free(hm->buckets);
    free(hm);
}

int insert_item(HM* hm, long val) {
    if (!hm) return 1;
    size_t idx = hash(val, hm->n_buckets);
    List* bucket = hm->buckets[idx];
    if (!bucket) return 1;

    Node_HM* new_node = malloc(sizeof(Node_HM));
    if (!new_node) return 1;
    new_node->m_val = val;

    Node_HM* sentinel = atomic_load(&bucket->sentinel);

    while (1) {
        Node_HM* old_head = atomic_load(&sentinel->m_next);
        new_node->m_next = old_head;
        if (atomic_compare_exchange_weak(&sentinel->m_next, &old_head, new_node)) {
            return 0;
        }
        // CAS failed, retry
    }
}

int remove_item(HM* hm, long val) {
    if (!hm) return 1;
    size_t idx = hash(val, hm->n_buckets);
    List* bucket = hm->buckets[idx];
    if (!bucket) return 1;

    Node_HM* sentinel = atomic_load(&bucket->sentinel);
    Node_HM* prev = sentinel;
    Node_HM* curr = atomic_load(&prev->m_next);

    while (curr) {
        if (curr->m_val == val) {
            Node_HM* next = atomic_load(&curr->m_next);
            if (atomic_compare_exchange_weak(&prev->m_next, &curr, next)) {
                free(curr);
                return 0;
            }
            // CAS failed, reload curr
            curr = atomic_load(&prev->m_next);
            continue;
        }
        prev = curr;
        curr = atomic_load(&curr->m_next);
    }
    return 1;
}

int lookup_item(HM* hm, long val) {
    if (!hm) return 1;
    size_t idx = hash(val, hm->n_buckets);
    List* bucket = hm->buckets[idx];
    if (!bucket) return 1;

    Node_HM* curr = atomic_load(&bucket->sentinel)->m_next;
    while (curr) {
        if (curr->m_val == val) {
            return 0;
        }
        curr = atomic_load(&curr->m_next);
    }
    return 1;
}

void print_hashmap(HM* hm) {
    if (!hm) return;
    for (size_t i = 0; i < hm->n_buckets; ++i) {
        List* bucket = hm->buckets[i];
        printf("Bucket %zu", i + 1);
        Node_HM* curr = atomic_load(&bucket->sentinel)->m_next;
        while (curr) {
            printf(" - %ld", curr->m_val);
            curr = atomic_load(&curr->m_next);
        }
        printf("\n");
    }
}