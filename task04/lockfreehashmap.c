#include "chashmap.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <stdio.h>

// Node structure for bucket list
typedef struct Node_HM_t {
    long m_val;
    char padding[PAD];
    _Atomic(struct Node_HM_t*) m_next;
} Node_HM;

// One sentinel per bucket
typedef struct List_t {
    _Atomic(Node_HM*) sentinel;
} List;

// Hashmap struct
struct hm_t {
    List** buckets;
    size_t n_buckets;
};

// Hash function with mixing
static size_t hash(long val, size_t n_buckets) {
    unsigned long x = (unsigned long)val;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = (x >> 16) ^ x;
    return x % n_buckets;
}

// Allocate hashmap, each bucket gets its own sentinel node
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

// Free all lists and nodes after threads are finished
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

// Insert at head, lock-free using CAS, only if value is not already present
int insert_item(HM* hm, long val) {
    if (!hm) return 1;
    size_t idx = hash(val, hm->n_buckets);
    List* bucket = hm->buckets[idx];
    if (!bucket) return 1;

    Node_HM* sentinel = atomic_load(&bucket->sentinel);

    while (1) {
        // 1. Check if val already present
        Node_HM* curr = atomic_load(&sentinel->m_next);
        int found = 0;
        while (curr) {
            if (curr->m_val == val) {
                found = 1;
                break;
            }
            curr = atomic_load(&curr->m_next);
        }
        if (found) return 1; // Already present, do not insert

        // 2. Allocate and attempt CAS insert
        Node_HM* new_node = malloc(sizeof(Node_HM));
        if (!new_node) return 1;
        new_node->m_val = val;

        Node_HM* old_head = atomic_load(&sentinel->m_next);
        new_node->m_next = old_head;
        if (atomic_compare_exchange_weak(&sentinel->m_next, &old_head, new_node)) {
            return 0;
        }
        // CAS failed: another thread inserted something, possibly the same value

        // 3. Free the unused node and loop (recheck for duplicates!)
        free(new_node);
        // loop to recheck for duplicate & try again
    }
}

// Remove item, lock-free: just unlink, do NOT free node (avoid double-free)
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
            // CAS: unlink node, do not free here
            if (atomic_compare_exchange_weak(&prev->m_next, &curr, next)) {
                // do NOT free(curr);  // not safe: can lead to double-free
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

// Lookup item, lock-free traversal
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

// Print all buckets, lock-free
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