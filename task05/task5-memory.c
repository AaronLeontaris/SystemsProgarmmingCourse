#include <pthread.h>
#include <stdint.h> // For uint32_t, uintptr_t
#include <stddef.h> // For size_t, NULL
#include <unistd.h> // For sbrk
#include <string.h> // For memset, memcpy
// #include <assert.h> // We will remove assert in extend_heap_size

// Block header structure
typedef struct block {
    size_t size;           // Size of block (including header)
    int free;              // 1 if free, 0 if allocated
    struct block *next;    // Next block in heap list
    struct block *prev;    // Previous block in heap list
    uint32_t magic;        // Magic number for validation
} block_t;

// Global heap tracking
static block_t *heap_list_start = NULL; // Start of our linked list of blocks
static void *heap_actual_start = NULL;  // Actual start address from sbrk
static void *heap_actual_end = NULL;    // Actual current end address from sbrk

static pthread_mutex_t heap_mutex = PTHREAD_MUTEX_INITIALIZER;

// Alignment and size definitions
#define ALIGN(size) (((size) + 7) & ~7) // Align to 8 bytes
#define BLOCK_HEADER_SIZE sizeof(block_t)
#define MIN_SPLIT_SIZE (BLOCK_HEADER_SIZE) // Smallest a split-off remainder can be

// Magic numbers
#define MAGIC_ALLOC 0xABCDEF00 // For allocated blocks
#define MAGIC_FREE  0xDEADBEEF // For free blocks

// Helper: sbrk wrapper
static void *extend_heap_sbrk(size_t size) {
    void *p = sbrk(size);
    if (p == (void *)-1) {
        return NULL; // sbrk failed
    }
    if (heap_actual_start == NULL) { // First time sbrk is called successfully
        heap_actual_start = p;
    }
    heap_actual_end = sbrk(0); // Update current program break
    return p;
}

// Helper: Validate a block
static int is_valid_block_ptr(block_t *block) {
    if (!block) return 0;
    // Check if block pointer is within the sbrk-managed heap region
    if (heap_actual_start && heap_actual_end) {
        if ((void *)block < heap_actual_start || (void *)block >= heap_actual_end) {
            return 0; // Block pointer out of heap bounds
        }
        // Check if block data extends beyond heap
        if ((char *)block + block->size > (char *)heap_actual_end) {
             return 0;
        }
    } else if (heap_actual_start && !heap_actual_end) { // Heap started but end not set (should not happen if sbrk wrapper is used)
        return 0;
    }


    // Check magic numbers
    if (block->magic != MAGIC_ALLOC && block->magic != MAGIC_FREE) {
        return 0;
    }
    // Check minimum size
    if (block->size < BLOCK_HEADER_SIZE) {
        return 0;
    }
    return 1;
}

// Find best-fit free block
static block_t *find_best_fit_free_block(size_t size) {
    block_t *current = heap_list_start;
    block_t *best_match = NULL;
    size_t best_match_size = (size_t)-1; // Equivalent to SIZE_MAX

    while (current) {
        if (current->free && current->magic == MAGIC_FREE && current->size >= size) {
            if (current->size < best_match_size) {
                best_match = current;
                best_match_size = current->size;
                if (current->size == size) break; // Exact fit is the best
            }
        }
        current = current->next;
    }
    return best_match;
}

// Split block if it's too big for the requested size
static void split_block_if_needed(block_t *block, size_t requested_size) {
    // Only split if the remaining part is large enough to be a new block
    if (block->size >= requested_size + MIN_SPLIT_SIZE) {
        block_t *new_splinter = (block_t *)((char *)block + requested_size);
        new_splinter->size = block->size - requested_size;
        new_splinter->free = 1;
        new_splinter->magic = MAGIC_FREE; // New splinter is free
        new_splinter->next = block->next;
        new_splinter->prev = block;

        if (block->next) {
            block->next->prev = new_splinter;
        }
        block->next = new_splinter;
        block->size = requested_size; // Original block is now smaller
    }
}

// Coalesce adjacent free blocks (merges with next, then with previous)
static block_t *coalesce_block_with_neighbors(block_t *block) {
    // Coalesce with next block if it's free
    if (block->next && block->next->free && block->next->magic == MAGIC_FREE) {
        // is_valid_block_ptr(block->next) could be added for extra safety
        block->size += block->next->size;
        block->next = block->next->next;
        if (block->next) {
            block->next->prev = block;
        }
    }

    // Coalesce with previous block if it's free
    if (block->prev && block->prev->free && block->prev->magic == MAGIC_FREE) {
        // is_valid_block_ptr(block->prev) could be added for extra safety
        block->prev->size += block->size;
        block->prev->next = block->next;
        if (block->next) {
            block->next->prev = block->prev;
        }
        block = block->prev; // The coalesced block starts at the previous block's address
    }
    return block;
}

// --- Public API ---

void *malloc(size_t user_size) {
    if (user_size == 0) return NULL;

    size_t total_block_size = ALIGN(user_size + BLOCK_HEADER_SIZE);

    pthread_mutex_lock(&heap_mutex);

    block_t *block = find_best_fit_free_block(total_block_size);
    if (block) { // Found a suitable free block
        block->free = 0;
        block->magic = MAGIC_ALLOC; // Mark as allocated
        split_block_if_needed(block, total_block_size);
    } else { // No suitable free block, extend the heap
        block = (block_t *)extend_heap_sbrk(total_block_size);
        if (!block) { // sbrk failed
            pthread_mutex_unlock(&heap_mutex);
            return NULL;
        }
        block->size = total_block_size; // sbrk might give more, but we use what we need for this block
                                        // This is simplified; typically sbrk gives a chunk, and that chunk becomes a block.
                                        // For this version, assume extend_heap_sbrk gives exactly total_block_size *for this new block*.
                                        // A more robust heap extension would request a larger chunk and then use it.
                                        // Let's adjust to request a larger chunk if total_block_size is small.
        size_t allocation_size_from_sbrk = total_block_size; // Simplified for now.
        // A better approach:
        // size_t extend_amount = (total_block_size > 4096) ? total_block_size : 4096;
        // block = (block_t *)extend_heap_sbrk(extend_amount);
        // if (!block) ...
        // block->size = extend_amount;
        // Then split_block_if_needed(block, total_block_size) would create a free remainder.
        // For now, sticking closer to the original simpler extension:
        
        block->free = 0;
        block->magic = MAGIC_ALLOC;
        block->next = NULL;
        block->prev = NULL; // Will be set below

        if (!heap_list_start) { // First block in the heap
            heap_list_start = block;
        } else { // Append to the end of the list
            block_t *last = heap_list_start;
            while (last->next) {
                last = last->next;
            }
            last->next = block;
            block->prev = last;
        }
        // If sbrk gave more than total_block_size, split_block_if_needed would handle it here
        // but current extend_heap_sbrk is simplified to give exact needed size for the new block.
    }

    pthread_mutex_unlock(&heap_mutex);
    return (char *)block + BLOCK_HEADER_SIZE; // Return pointer to payload
}

void free(void *ptr) {
    if (!ptr) return;

    pthread_mutex_lock(&heap_mutex);

    block_t *block_header = (block_t *)((char *)ptr - BLOCK_HEADER_SIZE);

    // Validate the block before freeing
    if (!is_valid_block_ptr(block_header) || block_header->magic != MAGIC_ALLOC || block_header->free) {
        pthread_mutex_unlock(&heap_mutex);
        // Consider error: invalid pointer, double free, or not allocated by this malloc
        return;
    }

    block_header->free = 1;
    block_header->magic = MAGIC_FREE; // Mark as free
    coalesce_block_with_neighbors(block_header);

    pthread_mutex_unlock(&heap_mutex);
}

void *calloc(size_t nmemb, size_t user_size_per_item) {
    // Check for multiplication overflow
    if (nmemb > 0 && user_size_per_item > (size_t)-1 / nmemb) return NULL;

    size_t total_user_size = nmemb * user_size_per_item;
    if (total_user_size == 0) return NULL; // Or return a unique pointer as per some standards

    void *ptr = malloc(total_user_size);
    if (ptr) {
        memset(ptr, 0, total_user_size); // Initialize to zero
    }
    return ptr;
}

void *realloc(void *ptr, size_t new_user_size) {
    if (!ptr) return malloc(new_user_size); // If ptr is NULL, behaves like malloc

    if (new_user_size == 0) { // If size is 0, behaves like free
        free(ptr);
        return NULL;
    }

    pthread_mutex_lock(&heap_mutex);

    block_t *block_header = (block_t *)((char *)ptr - BLOCK_HEADER_SIZE);

    if (!is_valid_block_ptr(block_header) || block_header->magic != MAGIC_ALLOC || block_header->free) {
        pthread_mutex_unlock(&heap_mutex);
        return NULL; // Invalid block
    }

    size_t old_block_total_size = block_header->size;
    size_t old_user_size = old_block_total_size - BLOCK_HEADER_SIZE;
    size_t new_total_block_size = ALIGN(new_user_size + BLOCK_HEADER_SIZE);

    // Case 1: Shrinking or new size fits within current block (after potential split)
    if (new_total_block_size <= old_block_total_size) {
        split_block_if_needed(block_header, new_total_block_size);
        // block_header->magic remains MAGIC_ALLOC
        pthread_mutex_unlock(&heap_mutex);
        return ptr; // Original pointer is still valid
    }

    // Case 2: Growing. Try to merge with next block if it's free and large enough.
    if (block_header->next && block_header->next->free && block_header->next->magic == MAGIC_FREE &&
        is_valid_block_ptr(block_header->next) && /* Safety check */
        (old_block_total_size + block_header->next->size) >= new_total_block_size) {

        block_header->size += block_header->next->size; // Absorb next block
        block_header->next = block_header->next->next;
        if (block_header->next) {
            block_header->next->prev = block_header;
        }
        // block_header->magic remains MAGIC_ALLOC
        split_block_if_needed(block_header, new_total_block_size); // Split if combined block is too large
        pthread_mutex_unlock(&heap_mutex);
        return ptr;
    }

    pthread_mutex_unlock(&heap_mutex); // Unlock before calling malloc/free for new allocation

    // Case 3: Cannot expand in place. Allocate new block, copy data, free old block.
    void *new_ptr = malloc(new_user_size); // new_user_size is payload size
    if (new_ptr) {
        memcpy(new_ptr, ptr, (old_user_size < new_user_size) ? old_user_size : new_user_size);
        free(ptr); // Free the old block
    }
    // If malloc fails, new_ptr is NULL; original block is NOT freed by this path.
    return new_ptr;
}