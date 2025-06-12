#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>

// Block header structure
typedef struct block {
    size_t size;          // Size of block (including header)
    int free;             // 1 if free, 0 if allocated
    struct block *next;   // Next block in heap list
    struct block *prev;   // Previous block in heap list
} block_t;

static block_t *heap_start = NULL;
static pthread_mutex_t heap_mutex = PTHREAD_MUTEX_INITIALIZER;

#define ALIGN(size) (((size) + 7) & ~7)
#define BLOCK_SIZE sizeof(block_t)

// sbrk wrapper
static void *extend_heap_size(size_t size) {
    void *p = sbrk(size);
    assert(p != (void *)-1);
    return p;
}

// Find best-fit free block
static block_t *find_free_block(size_t size) {
    block_t *current = heap_start;
    block_t *best = NULL;
    size_t best_size = (size_t)(-1);
    while (current) {
        if (current->free && current->size >= size) {
            if (current->size < best_size) {
                best = current;
                best_size = current->size;
                if (current->size == size) break; // exact fit
            }
        }
        current = current->next;
    }
    return best;
}

// Split block if too big
static void split_block(block_t *block, size_t size) {
    if (block->size >= size + BLOCK_SIZE + 8) {
        block_t *new_block = (block_t *)((char *)block + size);
        new_block->size = block->size - size;
        new_block->free = 1;
        new_block->next = block->next;
        new_block->prev = block;
        if (block->next) block->next->prev = new_block;
        block->next = new_block;
        block->size = size;
    }
}

// Coalesce adjacent free blocks (both forward and backward)
static block_t *coalesce(block_t *block) {
    // Forward
    while (block->next && block->next->free) {
        block_t *next_block = block->next;
        block->size += next_block->size;
        block->next = next_block->next;
        if (next_block->next)
            next_block->next->prev = block;
    }
    // Backward
    if (block->prev && block->prev->free) {
        block->prev->size += block->size;
        block->prev->next = block->next;
        if (block->next)
            block->next->prev = block->prev;
        block = block->prev;
    }
    return block;
}

void *malloc(size_t size) {
    if (size == 0) return NULL;
    size_t total_size = ALIGN(size + BLOCK_SIZE);

    pthread_mutex_lock(&heap_mutex);

    block_t *block = find_free_block(total_size);
    if (!block) {
        block = (block_t *)extend_heap_size(total_size);
        block->size = total_size;
        block->free = 0;
        block->next = NULL;
        block->prev = NULL;
        if (!heap_start) {
            heap_start = block;
        } else {
            block_t *last = heap_start;
            while (last->next) last = last->next;
            last->next = block;
            block->prev = last;
        }
    } else {
        block->free = 0;
        split_block(block, total_size);
    }

    pthread_mutex_unlock(&heap_mutex);

    return (char *)block + BLOCK_SIZE;
}

void free(void *ptr) {
    if (!ptr) return;
    pthread_mutex_lock(&heap_mutex);

    block_t *block = (block_t *)((char *)ptr - BLOCK_SIZE);
    block->free = 1;
    coalesce(block);

    pthread_mutex_unlock(&heap_mutex);
}

void *calloc(size_t nmemb, size_t size) {
    if (nmemb && size > (size_t)-1 / nmemb) return NULL; // overflow
    size_t total = nmemb * size;
    void *ptr = malloc(total);
    if (ptr) memset(ptr, 0, total);
    return ptr;
}

void *realloc(void *ptr, size_t size) {
    if (!ptr) return malloc(size);
    if (size == 0) {
        free(ptr);
        return NULL;
    }
    pthread_mutex_lock(&heap_mutex);

    block_t *block = (block_t *)((char *)ptr - BLOCK_SIZE);
    size_t old_user_size = block->size - BLOCK_SIZE;
    size_t new_total_size = ALIGN(size + BLOCK_SIZE);

    // Try to expand in-place
    if (new_total_size <= block->size) {
        split_block(block, new_total_size);
        pthread_mutex_unlock(&heap_mutex);
        return ptr;
    }
    // Try to merge with next if possible
    if (block->next && block->next->free &&
        block->size + block->next->size >= new_total_size) {
        // Merge
        block->size += block->next->size;
        block->next = block->next->next;
        if (block->next) block->next->prev = block;
        split_block(block, new_total_size);
        pthread_mutex_unlock(&heap_mutex);
        return ptr;
    }
    pthread_mutex_unlock(&heap_mutex);

    // Otherwise allocate new and copy
    void *new_ptr = malloc(size);
    if (new_ptr) {
        size_t min_copy = old_user_size < size ? old_user_size : size;
        memcpy(new_ptr, ptr, min_copy);
        free(ptr);
    }
    return new_ptr;
}