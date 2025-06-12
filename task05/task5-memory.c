#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

// block header structure
typedef struct block {
    size_t size;          // size of block (including header)
    int free;             // 1 if free, 0 if allocated
    struct block *next;   // next block in list
    struct block *prev;   // previous block in list
} block_t;

// heap structure for each thread
typedef struct heap {
    block_t *start;
    pthread_mutex_t mutex;
    struct heap *next;
} heap_t;

// global vars
static heap_t *heaps = NULL;
static pthread_mutex_t heaps_mutex = PTHREAD_MUTEX_INITIALIZER;
static __thread heap_t *thread_heap = NULL;

// alignment macro - 8 byte align
#define ALIGN(size) (((size) + 7) & ~7)
#define BLOCK_SIZE sizeof(block_t)
#define MIN_BLOCK_SIZE 32

// extend heap size
void *extend_heap_size(size_t size) {
    void *current_base = sbrk(0);
    void *extended = sbrk(size);
    assert(extended != (void *)-1);
    return extended;
}

// get or create heap for current thread
static heap_t* get_thread_heap() {
    if (thread_heap) {
        return thread_heap;
    }
    
    pthread_mutex_lock(&heaps_mutex);
    
    // create new heap for this thread
    heap_t *new_heap = (heap_t*)extend_heap_size(sizeof(heap_t));
    new_heap->start = NULL;
    pthread_mutex_init(&new_heap->mutex, NULL);
    new_heap->next = heaps;
    heaps = new_heap;
    thread_heap = new_heap;
    
    pthread_mutex_unlock(&heaps_mutex);
    return new_heap;
}

// find free block that fits size
static block_t* find_free_block(heap_t *heap, size_t size) {
    block_t *current = heap->start;
    block_t *best_fit = NULL;
    size_t best_size = SIZE_MAX;
    
    while (current) {
        if (current->free && current->size >= size) {
            if (current->size < best_size) {
                best_fit = current;
                best_size = current->size;
                // exact fit
                if (current->size == size) {
                    break;
                }
            }
        }
        current = current->next;
    }
    return best_fit;
}

// split block if its too big
static void split_block(block_t *block, size_t size) {
    if (block->size >= size + BLOCK_SIZE + MIN_BLOCK_SIZE) {
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
    while (block->next && block->next->free) {
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
    
    heap_t *heap = get_thread_heap();
    pthread_mutex_lock(&heap->mutex);
    
    // align size and add header
    size_t total_size = ALIGN(size + BLOCK_SIZE);
    if (total_size < MIN_BLOCK_SIZE) {
        total_size = MIN_BLOCK_SIZE;
    }
    
    // find free block
    block_t *block = find_free_block(heap, total_size);
    
    if (!block) {
        // no suitable free block, extend heap
        size_t extend_size = total_size;
        if (extend_size < 4096) {
            extend_size = 4096; // allocate at least 4KB chunks
        }
        
        block = (block_t*)extend_heap_size(extend_size);
        block->size = extend_size;
        block->free = 0;
        block->next = NULL;
        block->prev = NULL;
        
        // add to list
        if (!heap->start) {
            heap->start = block;
        } else {
            block_t *current = heap->start;
            while (current->next) {
                current = current->next;
            }
            current->next = block;
            block->prev = current;
        }
        
        // split if we got more than needed
        split_block(block, total_size);
    } else {
        // use existing free block
        block->free = 0;
        split_block(block, total_size);
    }
    
    pthread_mutex_unlock(&heap->mutex);
    
    // return pointer after header
    return (char*)block + BLOCK_SIZE;
}

void *calloc(size_t nitems, size_t nsize) {
    // check for overflow
    if (nitems != 0 && nsize > SIZE_MAX / nitems) {
        return NULL;
    }
    
    size_t total = nitems * nsize;
    void *ptr = malloc(total);
    if (ptr) {
        memset(ptr, 0, total);
    }
    return ptr;
}

void free(void *ptr) {
    if (!ptr) return;
    
    // find which heap this belongs to
    heap_t *heap = NULL;
    pthread_mutex_lock(&heaps_mutex);
    heap_t *current_heap = heaps;
    while (current_heap) {
        if (ptr >= (void*)current_heap && 
            ptr < (void*)((char*)current_heap + 1024*1024)) { // rough check
            heap = current_heap;
            break;
        }
        current_heap = current_heap->next;
    }
    pthread_mutex_unlock(&heaps_mutex);
    
    if (!heap) {
        // fallback to thread heap
        heap = get_thread_heap();
    }
    
    pthread_mutex_lock(&heap->mutex);
    
    // get block header
    block_t *block = (block_t*)((char*)ptr - BLOCK_SIZE);
    block->free = 1;
    
    // merge with adjacent free blocks
    merge_free_blocks(block);
    
    pthread_mutex_unlock(&heap->mutex);
}

void *realloc(void *ptr, size_t size) {
    if (!ptr) {
        return malloc(size);
    }
    
    if (size == 0) {
        free(ptr);
        return NULL;
    }
    
    // find which heap this belongs to
    heap_t *heap = get_thread_heap();
    pthread_mutex_lock(&heap->mutex);
    
    block_t *block = (block_t*)((char*)ptr - BLOCK_SIZE);
    size_t old_size = block->size - BLOCK_SIZE;
    size_t new_total = ALIGN(size + BLOCK_SIZE);
    if (new_total < MIN_BLOCK_SIZE) {
        new_total = MIN_BLOCK_SIZE;
    }
    
    // if new size fits in current block
    if (new_total <= block->size) {
        split_block(block, new_total);
        pthread_mutex_unlock(&heap->mutex);
        return ptr;
    }
    
    // try to merge with next block if its free
    if (block->next && block->next->free && 
        block->size + block->next->size >= new_total) {
        block->size += block->next->size;
        if (block->next->next) {
            block->next->next->prev = block;
        }
        block->next = block->next->next;
        split_block(block, new_total);
        pthread_mutex_unlock(&heap->mutex);
        return ptr;
    }
    
    pthread_mutex_unlock(&heap->mutex);
    
    // allocate new block and copy data
    void *new_ptr = malloc(size);
    if (new_ptr) {
        size_t copy_size = old_size < size ? old_size : size;
        memcpy(new_ptr, ptr, copy_size);
        free(ptr);
    }
    
    return new_ptr;
}