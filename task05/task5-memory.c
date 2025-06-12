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
    uint32_t magic;       // Magic number for validation
} block_t;

// Heap metadata
typedef struct {
    void *start;          // Start of heap
    void *end;            // End of heap
    block_t *first_block; // First block in heap
} heap_info_t;

static heap_info_t heap = {NULL, NULL, NULL};
static pthread_mutex_t heap_mutex = PTHREAD_MUTEX_INITIALIZER;

#define ALIGN(size) (((size) + 7) & ~7)
#define BLOCK_SIZE sizeof(block_t)
#define MIN_BLOCK_SIZE 32
#define MAGIC_FREE 0xDEADBEEF
#define MAGIC_ALLOC 0xABCDEF00

// Validate block header
static int is_valid_block(block_t *block) {
    if (!block) return 0;
    if ((void*)block < heap.start || (void*)block >= heap.end) return 0;
    if (block->magic != MAGIC_FREE && block->magic != MAGIC_ALLOC) return 0;
    if (block->size < BLOCK_SIZE || block->size > (size_t)((char*)heap.end - (char*)block)) return 0;
    return 1;
}

// sbrk wrapper with heap tracking
static void *extend_heap_size(size_t size) {
    void *old_end = sbrk(0);
    void *new_mem = sbrk(size);
    if (new_mem == (void*)-1) {
        return NULL;
    }
    
    if (!heap.start) {
        heap.start = new_mem;
    }
    heap.end = sbrk(0);
    return new_mem;
}

// Find best-fit free block
static block_t *find_free_block(size_t size) {
    block_t *current = heap.first_block;
    block_t *best = NULL;
    size_t best_size = SIZE_MAX;
    
    while (current && is_valid_block(current)) {
        if (current->free && current->magic == MAGIC_FREE && current->size >= size) {
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
    if (!is_valid_block(block) || block->size < size + BLOCK_SIZE + MIN_BLOCK_SIZE) {
        return;
    }
    
    block_t *new_block = (block_t *)((char *)block + size);
    new_block->size = block->size - size;
    new_block->free = 1;
    new_block->magic = MAGIC_FREE;
    new_block->next = block->next;
    new_block->prev = block;
    
    if (block->next && is_valid_block(block->next)) {
        block->next->prev = new_block;
    }
    block->next = new_block;
    block->size = size;
}

// Coalesce adjacent free blocks
static block_t *coalesce(block_t *block) {
    if (!is_valid_block(block)) return block;
    
    // Forward coalescing
    while (block->next && is_valid_block(block->next) && 
           block->next->free && block->next->magic == MAGIC_FREE) {
        block_t *next_block = block->next;
        block->size += next_block->size;
        block->next = next_block->next;
        if (next_block->next && is_valid_block(next_block->next)) {
            next_block->next->prev = block;
        }
    }
    
    // Backward coalescing
    if (block->prev && is_valid_block(block->prev) && 
        block->prev->free && block->prev->magic == MAGIC_FREE) {
        block_t *prev_block = block->prev;
        prev_block->size += block->size;
        prev_block->next = block->next;
        if (block->next && is_valid_block(block->next)) {
            block->next->prev = prev_block;
        }
        block = prev_block;
    }
    
    return block;
}

void *malloc(size_t size) {
    if (size == 0) return NULL;
    
    size_t total_size = ALIGN(size + BLOCK_SIZE);
    if (total_size < MIN_BLOCK_SIZE) {
        total_size = MIN_BLOCK_SIZE;
    }

    pthread_mutex_lock(&heap_mutex);

    block_t *block = find_free_block(total_size);
    if (!block) {
        // Extend heap - allocate at least 4KB chunks
        size_t extend_size = total_size;
        if (extend_size < 4096) {
            extend_size = 4096;
        }
        
        block = (block_t *)extend_heap_size(extend_size);
        if (!block) {
            pthread_mutex_unlock(&heap_mutex);
            return NULL;
        }
        
        block->size = extend_size;
        block->free = 0;
        block->magic = MAGIC_ALLOC;
        block->next = NULL;
        block->prev = NULL;
        
        // Add to heap list
        if (!heap.first_block) {
            heap.first_block = block;
        } else {
            block_t *last = heap.first_block;
            while (last->next && is_valid_block(last->next)) {
                last = last->next;
            }
            last->next = block;
            block->prev = last;
        }
        
        // Split if we allocated more than needed
        if (block->size > total_size) {
            split_block(block, total_size);
        }
    } else {
        block->free = 0;
        block->magic = MAGIC_ALLOC;
        split_block(block, total_size);
    }

    pthread_mutex_unlock(&heap_mutex);

    return (char *)block + BLOCK_SIZE;
}

void free(void *ptr) {
    if (!ptr) return;
    
    pthread_mutex_lock(&heap_mutex);

    block_t *block = (block_t *)((char *)ptr - BLOCK_SIZE);
    
    // Validate block before freeing
    if (!is_valid_block(block) || block->magic != MAGIC_ALLOC || block->free) {
        pthread_mutex_unlock(&heap_mutex);
        return; // Invalid block or double free
    }
    
    block->free = 1;
    block->magic = MAGIC_FREE;
    coalesce(block);

    pthread_mutex_unlock(&heap_mutex);
}

void *calloc(size_t nmemb, size_t size) {
    // Check for overflow
    if (nmemb != 0 && size > SIZE_MAX / nmemb) {
        return NULL;
    }
    
    size_t total = nmemb * size;
    void *ptr = malloc(total);
    if (ptr) {
        memset(ptr, 0, total);
    }
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
    
    // Validate block
    if (!is_valid_block(block) || block->magic != MAGIC_ALLOC || block->free) {
        pthread_mutex_unlock(&heap_mutex);
        return NULL;
    }
    
    size_t old_user_size = block->size - BLOCK_SIZE;
    size_t new_total_size = ALIGN(size + BLOCK_SIZE);
    if (new_total_size < MIN_BLOCK_SIZE) {
        new_total_size = MIN_BLOCK_SIZE;
    }

    // If new size fits in current block
    if (new_total_size <= block->size) {
        split_block(block, new_total_size);
        pthread_mutex_unlock(&heap_mutex);
        return ptr;
    }

    // Try to merge with next block if it's free
    if (block->next && is_valid_block(block->next) && 
        block->next->free && block->next->magic == MAGIC_FREE &&
        block->size + block->next->size >= new_total_size) {
        
        // Merge with next block
        block->size += block->next->size;
        if (block->next->next && is_valid_block(block->next->next)) {
            block->next->next->prev = block;
        }
        block->next = block->next->next;
        split_block(block, new_total_size);
        pthread_mutex_unlock(&heap_mutex);
        return ptr;
    }

    pthread_mutex_unlock(&heap_mutex);

    // Allocate new block and copy data
    void *new_ptr = malloc(size);
    if (new_ptr) {
        size_t copy_size = old_user_size < size ? old_user_size : size;
        memcpy(new_ptr, ptr, copy_size);
        free(ptr);
    }
    return new_ptr;
}

// OG Interface....
void *extend_heap_size(size_t size) {
    void *current_base = sbrk(0);
    void *extended = sbrk(size);
    assert(extended != (void *)-1);
    return extended;
}