#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>

// block header structure
typedef struct block {
    size_t size;          // size of block (including header)
    int free;             // 1 if free, 0 if allocated
    struct block *next;   // next block in list
    struct block *prev;   // previous block in list
} block_t;

// global vars
static block_t *heap_start = NULL;
static pthread_mutex_t heap_mutex = PTHREAD_MUTEX_INITIALIZER;

// alignment macro - 8 byte align
#define ALIGN(size) (((size) + 7) & ~7)
#define BLOCK_SIZE sizeof(block_t)

// extend heap size
void *extend_heap_size(size_t size) {
    void *current_base = sbrk(0);
    void *extended = sbrk(size);
    assert(extended != (void *)-1); // Note: not thread-safe
    return extended;
}

// find free block that fits size
static block_t* find_free_block(size_t size) {
    block_t *current = heap_start;
    while (current) {
        if (current->free && current->size >= size) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

// split block if its too big
static void split_block(block_t *block, size_t size) {
    if (block->size >= size + BLOCK_SIZE + 8) {
        block_t *new_block = (block_t*)((char*)block + size);
        new_block->size = block->size - size;
        new_block->free = 1;
        new_block->next = block->next;
        new_block->prev = block;
        
        if (block->next) {
            block->next->prev = new_block;
        }
        block->next = new_block;
        block->size = size;
    }
}

// merge adjacent free blocks
static void merge_free_blocks(block_t *block) {
    // merge with next block
    if (block->next && block->next->free) {
        block->size += block->next->size;
        if (block->next->next) {
            block->next->next->prev = block;
        }
        block->next = block->next->next;
    }
    
    // merge with prev block
    if (block->prev && block->prev->free) {
        block->prev->size += block->size;
        if (block->next) {
            block->next->prev = block->prev;
        }
        block->prev->next = block->next;
    }
}

void *malloc(size_t size) {
    if (size == 0) return NULL;
    
    pthread_mutex_lock(&heap_mutex);
    
    // align size and add header
    size_t total_size = ALIGN(size + BLOCK_SIZE);
    
    // find free block
    block_t *block = find_free_block(total_size);
    
    if (!block) {
        // no suitable free block, extend heap
        block = (block_t*)extend_heap_size(total_size);
        block->size = total_size;
        block->free = 0;
        block->next = NULL;
        block->prev = NULL;
        
        // add to list
        if (!heap_start) {
            heap_start = block;
        } else {
            block_t *current = heap_start;
            while (current->next) {
                current = current->next;
            }
            current->next = block;
            block->prev = current;
        }
    } else {
        // use existing free block
        block->free = 0;
        split_block(block, total_size);
    }
    
    pthread_mutex_unlock(&heap_mutex);
    
    // return pointer after header
    return (char*)block + BLOCK_SIZE;
}

void *calloc(size_t nitems, size_t nsize) {
    size_t total = nitems * nsize;
    void *ptr = malloc(total);
    if (ptr) {
        memset(ptr, 0, total);
    }
    return ptr;
}

void free(void *ptr) {
    if (!ptr) return;
    
    pthread_mutex_lock(&heap_mutex);
    
    // get block header
    block_t *block = (block_t*)((char*)ptr - BLOCK_SIZE);
    block->free = 1;
    
    // merge with adjacent free blocks
    merge_free_blocks(block);
    
    pthread_mutex_unlock(&heap_mutex);
}

void *realloc(void *ptr, size_t size) {
    if (!ptr) {
        return malloc(size);
    }
    
    if (size == 0) {
        free(ptr);
        return NULL;
    }
    
    pthread_mutex_lock(&heap_mutex);
    
    block_t *block = (block_t*)((char*)ptr - BLOCK_SIZE);
    size_t old_size = block->size - BLOCK_SIZE;
    size_t new_total = ALIGN(size + BLOCK_SIZE);
    
    // if new size fits in current block
    if (new_total <= block->size) {
        split_block(block, new_total);
        pthread_mutex_unlock(&heap_mutex);
        return ptr;
    }
    
    pthread_mutex_unlock(&heap_mutex);
    
    // allocate new block and copy data
    void *new_ptr = malloc(size);
    if (new_ptr) {
        memcpy(new_ptr, ptr, old_size < size ? old_size : size);
        free(ptr);
    }
    
    return new_ptr;
}