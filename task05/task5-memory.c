#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>   // For sbrk
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>   // For size_t

// Block header
typedef struct block {
    size_t size;          // Total size of the block (hdr and payld)
    int free;             // 1 if free, 0 if allocated
    struct block *next;   // Next block in list
    struct block *prev;   // Previous block in list
    uint32_t magic;       // Magic number for validation
} block_t;

// Heap metadata
typedef struct {
    void *start;          // Start of heap
    void *end;            // End of heap (current program break)
    block_t *first_block; // First block
    block_t *last_block;  // Last block (optimization)
} heap_info_t;

static heap_info_t heap = {NULL, NULL, NULL, NULL};
static pthread_mutex_t heap_mutex = PTHREAD_MUTEX_INITIALIZER;

// Align size to 8 bytes
#define ALIGN(size) (((size) + 7) & ~7)
// Size of block header
#define BLOCK_SIZE sizeof(block_t)
// Minimum block size (must hold a header)
#define MIN_BLOCK_SIZE (sizeof(block_t))
// Magic numbers for block validation
#define MAGIC_FREE 0xDEADBEEF
#define MAGIC_ALLOC 0xABCDEF00
// Default heap extension size
#define HEAP_EXTEND_CHUNK_SIZE (4096)


// Validates a block header
static int is_valid_block(block_t *block) {
    if (!block) return 0;

    // Check block's position relative to the heap boundaries
    if (heap.start) { // Only if heap is initialized
        if ((void*)block < heap.start) return 0; // Starts before heap
        if ((void*)block >= heap.end) return 0;  // Starts at or after heap end (no room for header)
        if ((void*)((char*)block + block->size) > heap.end) return 0; // Extends beyond heap end
    }
    // If heap.start is NULL, boundary checks are skipped (heap not yet created).

    // Check magic number and minimum size
    if (block->magic != MAGIC_FREE && block->magic != MAGIC_ALLOC) return 0;
    if (block->size < MIN_BLOCK_SIZE) return 0;

    return 1;
}

// Extends heap by 'size' bytes using sbrk()
static void *extend_heap_size(size_t size) {
    void *new_mem = sbrk(size);
    if (new_mem == (void *)-1) {
        return NULL; // sbrk failed
    }

    if (!heap.start) {
        heap.start = new_mem; // Initialize heap start
    }
    heap.end = sbrk(0); // Update heap end to new program break
    return new_mem;
}

// Finds best-fit free block for 'size' bytes
static block_t *find_free_block(size_t size) {
    block_t *current = heap.first_block;
    block_t *best_fit = NULL;
    size_t smallest_suitable_size = SIZE_MAX;

    while (current) {
        if (is_valid_block(current) && current->free && current->magic == MAGIC_FREE && current->size >= size) {
            if (current->size == size) {
                return current; // Exact fit
            }
            if (current->size < smallest_suitable_size) {
                smallest_suitable_size = current->size;
                best_fit = current;
            }
        }
        current = current->next;
    }
    return best_fit;
}

// Splits 'block_to_split' if it's larger than 'size_for_first_part'
static void split_block(block_t *block_to_split, size_t size_for_first_part) {
    size_t original_block_size = block_to_split->size;
    size_t remaining_size = original_block_size - size_for_first_part;

    if (remaining_size >= MIN_BLOCK_SIZE) { // Remainder must be large enough for a new block
        block_t *new_free_splinter = (block_t *)((char *)block_to_split + size_for_first_part);
        new_free_splinter->size = remaining_size;
        new_free_splinter->free = 1;
        new_free_splinter->magic = MAGIC_FREE;
        new_free_splinter->prev = block_to_split;
        new_free_splinter->next = block_to_split->next;

        if (block_to_split->next) {
            block_to_split->next->prev = new_free_splinter;
        } else {
            heap.last_block = new_free_splinter; // New splinter is now the last block
        }
        block_to_split->next = new_free_splinter;
        block_to_split->size = size_for_first_part; // Resize original block
    }
}

// Coalesces 'block' with adjacent free blocks
static block_t *coalesce(block_t *block) {
    if (!is_valid_block(block)) return block;

    // Coalesce with next block
    if (block->next && is_valid_block(block->next) &&
        block->next->free && block->next->magic == MAGIC_FREE) {
        block_t *next_block_ptr = block->next; // Temp pointer before modifying block->next
        block->size += next_block_ptr->size;
        block->next = next_block_ptr->next;
        if (next_block_ptr->next) {
            next_block_ptr->next->prev = block;
        } else {
            heap.last_block = block; // Merged block is now last
        }
    }

    // Coalesce with previous block
    if (block->prev && is_valid_block(block->prev) &&
        block->prev->free && block->prev->magic == MAGIC_FREE) {
        block_t *prev_block_ptr = block->prev; // Temp pointer
        prev_block_ptr->size += block->size;
        prev_block_ptr->next = block->next;
        if (block->next) {
            block->next->prev = prev_block_ptr;
        } else {
            heap.last_block = prev_block_ptr; // Merged block (prev) is now last
        }
        block = prev_block_ptr; // The coalesced block starts at prev_block_ptr
    }
    return block;
}

// Allocates 'size' bytes
void *malloc(size_t size) {
    if (size == 0) return NULL;

    size_t total_size = ALIGN(size + BLOCK_SIZE);
    if (total_size < MIN_BLOCK_SIZE) total_size = MIN_BLOCK_SIZE;

    pthread_mutex_lock(&heap_mutex);

    block_t *block_found = find_free_block(total_size);

    if (!block_found) { // No suitable free block, extend heap
        size_t extend_amount = (total_size > HEAP_EXTEND_CHUNK_SIZE) ? total_size : HEAP_EXTEND_CHUNK_SIZE;
        void *new_heap_region = extend_heap_size(extend_amount);

        if (!new_heap_region) { // sbrk failed
            pthread_mutex_unlock(&heap_mutex);
            return NULL;
        }

        block_found = (block_t *)new_heap_region;
        block_found->size = extend_amount;
        block_found->free = 0; // To be allocated
        block_found->magic = MAGIC_ALLOC;
        block_found->prev = heap.last_block;
        block_found->next = NULL;

        if (heap.last_block) {
            heap.last_block->next = block_found;
        } else { // First block in heap
            heap.first_block = block_found;
        }
        heap.last_block = block_found;

        split_block(block_found, total_size); // Split if extended chunk is larger than needed
    } else { // Found a free block
        block_found->free = 0;
        block_found->magic = MAGIC_ALLOC;
        split_block(block_found, total_size); // Split if found block is larger than needed
    }

    pthread_mutex_unlock(&heap_mutex);
    return (char *)block_found + BLOCK_SIZE; // Return pointer to payload
}

// Frees memory block pointed to by 'ptr'
void free(void *ptr) {
    if (!ptr) return;

    pthread_mutex_lock(&heap_mutex);

    block_t *block_header = (block_t *)((char *)ptr - BLOCK_SIZE);

    if (!is_valid_block(block_header) || block_header->magic != MAGIC_ALLOC || block_header->free) {
        // Invalid block, not allocated by this malloc, or double free
        pthread_mutex_unlock(&heap_mutex);
        return;
    }

    block_header->free = 1;
    block_header->magic = MAGIC_FREE;
    coalesce(block_header); // Attempt to merge with neighbors

    pthread_mutex_unlock(&heap_mutex);
}

// Allocates and zeros memory for 'nmemb' elements of 'size' bytes each
void *calloc(size_t nmemb, size_t size) {
    if (nmemb > 0 && size > SIZE_MAX / nmemb) return NULL; // Overflow check

    size_t total_bytes = nmemb * size;
    if (total_bytes == 0) return NULL;

    void *ptr = malloc(total_bytes);
    if (ptr) {
        memset(ptr, 0, total_bytes);
    }
    return ptr;
}

// Reallocates memory block 'ptr' to 'size' bytes
void *realloc(void *ptr, size_t size) {
    if (!ptr) return malloc(size); // If ptr is NULL, behaves like malloc
    if (size == 0) { // If size is 0, behaves like free
        free(ptr);
        return NULL;
    }

    pthread_mutex_lock(&heap_mutex);

    block_t *current_block = (block_t *)((char *)ptr - BLOCK_SIZE);

    if (!is_valid_block(current_block) || current_block->magic != MAGIC_ALLOC || current_block->free) {
        pthread_mutex_unlock(&heap_mutex);
        return NULL; // Invalid block
    }

    size_t new_total_size = ALIGN(size + BLOCK_SIZE);
    if (new_total_size < MIN_BLOCK_SIZE) new_total_size = MIN_BLOCK_SIZE;

    size_t old_total_size = current_block->size;
    size_t old_payload_size = old_total_size - BLOCK_SIZE;

    if (new_total_size <= old_total_size) { // Shrinking or same size
        split_block(current_block, new_total_size);
        pthread_mutex_unlock(&heap_mutex);
        return ptr;
    }

    // Trying to grow: check if next block is free and can be merged
    if (current_block->next && is_valid_block(current_block->next) && current_block->next->free &&
        (old_total_size + current_block->next->size) >= new_total_size) {
        
        block_t* next_b_ptr = current_block->next; // Temp pointer
        current_block->size += next_b_ptr->size; // Merge
        current_block->next = next_b_ptr->next;
        if (current_block->next) {
            current_block->next->prev = current_block;
        } else {
            heap.last_block = current_block;
        }
        split_block(current_block, new_total_size); // Split if combined block is too large
        pthread_mutex_unlock(&heap_mutex);
        return ptr;
    }

    pthread_mutex_unlock(&heap_mutex); // Unlock before calling malloc/free

    // Cannot expand in place, allocate new block and copy data
    void *new_ptr = malloc(size); // 'size' is payload size
    if (new_ptr) {
        memcpy(new_ptr, ptr, (old_payload_size < size) ? old_payload_size : size);
        free(ptr); // Free old block
    }
    return new_ptr; // Returns NULL if malloc failed, original block is not freed in that case
}