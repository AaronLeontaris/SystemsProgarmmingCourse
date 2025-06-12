#include <string.h>    // For memset, memcpy
#include <sys/types.h> // For size_t
#include <unistd.h>    // For sbrk
#include <pthread.h>   // For thread-safety
#include <stdint.h>    // For uint32_t
#include <stddef.h>    // For size_t, SIZE_MAX (implicitly)

// --- Block Structure and Heap Information ---

// Header for each memory block
typedef struct block {
    size_t size;           // Total size of this block (header + data area)
    int free;              // 1 if block is free, 0 if allocated
    struct block *next;    // Pointer to the next block in the list
    struct block *prev;    // Pointer to the previous block in the list
    uint32_t magic;        // Magic number for integrity checks
} block_t;

// Information about the heap
typedef struct {
    void *start;           // Start address of the heap
    void *end;             // Current end address of the heap (program break)
    block_t *first_block;  // First block in the heap's list
    block_t *last_block;   // Last block in the heap's list (for optimization)
} heap_info_t;

static heap_info_t heap = {NULL, NULL, NULL, NULL};
static pthread_mutex_t heap_mutex = PTHREAD_MUTEX_INITIALIZER;

// --- Defines and Macros ---

// Align size to be a multiple of 8 (for 8-byte payload alignment)
#define ALIGN(size) (((size) + 7) & ~7)
// Size of the block header structure
#define BLOCK_SIZE sizeof(block_t)
// Minimum size for any block (must be able to hold a header)
// A split-off remainder must be at least this large.
#define MIN_SPLIT_REMAINDER (sizeof(block_t))
// Magic numbers to help detect block corruption
#define MAGIC_FREE 0xDEADBEEF
#define MAGIC_ALLOC 0xABCDEF00
// Default size to extend heap by to reduce sbrk calls
#define HEAP_EXTEND_DEFAULT (4096)

// --- Helper Functions ---

// Checks if a block pointer and its metadata seem valid
static int is_valid_block(block_t *b) {
    if (!b) return 0;

    // Check if block is within heap boundaries (if heap is initialized)
    if (heap.start) {
        if ((void *)b < heap.start || (void *)b >= heap.end) return 0;
        if ((char *)b + b->size > (char *)heap.end) return 0; // Block data extends beyond heap
    }

    // Check magic number and minimum possible size
    if (b->magic != MAGIC_FREE && b->magic != MAGIC_ALLOC) return 0;
    if (b->size < BLOCK_SIZE) return 0; // Must be at least as big as a header

    return 1;
}

// Extends the program break (heap) by at least 'size' bytes
static void *extend_heap(size_t size) {
    void *current_brk = sbrk(0);
    void *new_brk = sbrk(size);

    if (new_brk == (void *)-1) {
        return NULL; // sbrk failed
    }

    if (!heap.start) { // First time extending
        heap.start = new_brk;
    }
    heap.end = sbrk(0); // Update current end of heap
    return new_brk;     // Return start of newly allocated region
}

// Finds a free block using best-fit strategy
// Returns NULL if no suitable block is found.
static block_t *find_best_free_block(size_t required_size) {
    block_t *current = heap.first_block;
    block_t *best_fit = NULL;
    size_t min_suitable_size = SIZE_MAX;

    while (current) {
        if (current->free && current->magic == MAGIC_FREE && current->size >= required_size) {
             // is_valid_block(current) check can be added here for extra safety if needed
            if (current->size == required_size) {
                return current; // Exact fit found
            }
            if (current->size < min_suitable_size) {
                min_suitable_size = current->size;
                best_fit = current;
            }
        }
        current = current->next;
    }
    return best_fit;
}

// Splits 'block_to_split' if it's larger than 'needed_size_for_first_part'.
// The first part takes 'needed_size_for_first_part'.
// The remainder becomes a new free block if large enough.
static void split_block_if_possible(block_t *block_to_split, size_t needed_size_for_first_part) {
    size_t original_size = block_to_split->size;
    size_t remaining_size = original_size - needed_size_for_first_part;

    // Only split if the remainder is large enough to be a new block
    if (remaining_size >= MIN_SPLIT_REMAINDER) {
        block_t *new_free_block = (block_t *)((char *)block_to_split + needed_size_for_first_part);
        new_free_block->size = remaining_size;
        new_free_block->free = 1;
        new_free_block->magic = MAGIC_FREE;
        new_free_block->prev = block_to_split;
        new_free_block->next = block_to_split->next;

        if (block_to_split->next) {
            block_to_split->next->prev = new_free_block;
        } else { // block_to_split was the last block
            heap.last_block = new_free_block;
        }

        block_to_split->next = new_free_block;
        block_to_split->size = needed_size_for_first_part; // Adjust size of the allocated part
    }
    // If not split, the allocated block uses the original larger size (internal fragmentation)
}

// Merges 'block' with adjacent free blocks (next and/or prev)
// Returns a pointer to the beginning of the (potentially larger) coalesced block.
static block_t *coalesce_free_blocks(block_t *block) {
    // Coalesce with the next block if it's free
    if (block->next && block->next->free && block->next->magic == MAGIC_FREE) {
        // is_valid_block(block->next) could be added for safety
        block_t *next_b = block->next;
        block->size += next_b->size;
        block->next = next_b->next;
        if (next_b->next) {
            next_b->next->prev = block;
        } else { // Merged block is now the last block
            heap.last_block = block;
        }
    }

    // Coalesce with the previous block if it's free
    if (block->prev && block->prev->free && block->prev->magic == MAGIC_FREE) {
        // is_valid_block(block->prev) could be added for safety
        block_t *prev_b = block->prev;
        prev_b->size += block->size;
        prev_b->next = block->next;
        if (block->next) {
            block->next->prev = prev_b;
        } else { // Merged block (prev_b) is now the last block
            heap.last_block = prev_b;
        }
        block = prev_b; // The coalesced block starts at prev_b's address
    }
    return block;
}

// --- Core Allocator Functions ---

void *malloc(size_t user_size) {
    if (user_size == 0) return NULL;

    // Calculate total block size: user data + header, then aligned.
    // Ensure total size is at least BLOCK_SIZE for the header.
    size_t total_block_size = ALIGN(user_size + BLOCK_SIZE);
    if (total_block_size < BLOCK_SIZE) total_block_size = BLOCK_SIZE; // Should not happen if user_size > 0

    pthread_mutex_lock(&heap_mutex);

    block_t *found_block = find_best_free_block(total_block_size);

    if (found_block) { // Found a suitable free block
        found_block->free = 0;
        found_block->magic = MAGIC_ALLOC;
        split_block_if_possible(found_block, total_block_size);
    } else { // No suitable free block, need to extend the heap
        size_t extend_size = (total_block_size > HEAP_EXTEND_DEFAULT) ? total_block_size : HEAP_EXTEND_DEFAULT;
        void *new_region = extend_heap(extend_size);

        if (!new_region) { // Heap extension failed
            pthread_mutex_unlock(&heap_mutex);
            return NULL;
        }

        found_block = (block_t *)new_region;
        found_block->size = extend_size;
        found_block->free = 0; // Mark as allocated (will be used)
        found_block->magic = MAGIC_ALLOC;
        found_block->prev = heap.last_block;
        found_block->next = NULL;

        if (heap.last_block) {
            heap.last_block->next = found_block;
        } else { // This is the first block in the heap
            heap.first_block = found_block;
        }
        heap.last_block = found_block; // This new chunk is now the last block

        split_block_if_possible(found_block, total_block_size);
    }

    pthread_mutex_unlock(&heap_mutex);
    // Return pointer to the data area (after the header)
    return (char *)found_block + BLOCK_SIZE;
}

void free(void *ptr) {
    if (!ptr) return; // free(NULL) is a no-op

    pthread_mutex_lock(&heap_mutex);

    block_t *block_header = (block_t *)((char *)ptr - BLOCK_SIZE);

    // Validate block before freeing
    if (!is_valid_block(block_header) || block_header->magic != MAGIC_ALLOC || block_header->free) {
        pthread_mutex_unlock(&heap_mutex);
        // Consider logging an error or aborting for invalid free
        return;
    }

    block_header->free = 1;
    block_header->magic = MAGIC_FREE;
    coalesce_free_blocks(block_header); // Attempt to merge with neighbors

    pthread_mutex_unlock(&heap_mutex);
}

void *calloc(size_t nmemb, size_t size) {
    // Check for multiplication overflow
    if (nmemb > 0 && size > SIZE_MAX / nmemb) {
        return NULL;
    }
    size_t total_user_size = nmemb * size;
    if (total_user_size == 0) {
        // Standard allows returning NULL or a unique pointer.
        // For consistency with malloc(0), returning NULL.
        return NULL;
    }

    void *ptr = malloc(total_user_size);
    if (ptr) {
        memset(ptr, 0, total_user_size); // Initialize memory to zero
    }
    return ptr;
}

void *realloc(void *ptr, size_t new_user_size) {
    if (!ptr) { // If ptr is NULL, realloc is like malloc
        return malloc(new_user_size);
    }
    if (new_user_size == 0) { // If size is 0, realloc is like free
        free(ptr);
        return NULL;
    }

    pthread_mutex_lock(&heap_mutex);

    block_t *current_block = (block_t *)((char *)ptr - BLOCK_SIZE);

    if (!is_valid_block(current_block) || current_block->magic != MAGIC_ALLOC || current_block->free) {
        pthread_mutex_unlock(&heap_mutex);
        return NULL; // Invalid block
    }

    size_t new_total_block_size = ALIGN(new_user_size + BLOCK_SIZE);
    if (new_total_block_size < BLOCK_SIZE) new_total_block_size = BLOCK_SIZE;

    size_t old_total_block_size = current_block->size;
    size_t old_user_size = old_total_block_size - BLOCK_SIZE;

    if (new_total_block_size <= old_total_block_size) {
        // New size is smaller or same; shrink block if possible by splitting
        split_block_if_possible(current_block, new_total_block_size);
        pthread_mutex_unlock(&heap_mutex);
        return ptr; // Original pointer is still valid
    }

    // Try to expand by merging with next block if it's free and large enough
    if (current_block->next && current_block->next->free && current_block->next->magic == MAGIC_FREE &&
        is_valid_block(current_block->next) && /* Safety check */
        (old_total_block_size + current_block->next->size) >= new_total_block_size) {

        block_t* next_b = current_block->next;
        current_block->size += next_b->size; // Absorb next block
        current_block->next = next_b->next;
        if (next_b->next) {
            next_b->next->prev = current_block;
        } else {
            heap.last_block = current_block; // current_block is now last
        }
        // current_block is still allocated. Split if it became too large.
        split_block_if_possible(current_block, new_total_block_size);
        pthread_mutex_unlock(&heap_mutex);
        return ptr;
    }

    pthread_mutex_unlock(&heap_mutex); // Unlock before calling malloc/free

    // Cannot expand in place: allocate new block, copy data, free old block
    void *new_ptr = malloc(new_user_size); // new_user_size is payload size
    if (new_ptr) {
        memcpy(new_ptr, ptr, (old_user_size < new_user_size) ? old_user_size : new_user_size);
        free(ptr); // Free the old block
    }
    // If malloc fails, new_ptr is NULL; original block is not freed by this path.
    return new_ptr;
}