#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>   // For sbrk
#include <pthread.h>
#include <stdint.h>
#include <stddef.h>   // For size_t
// Block header structure for managing memory segments
typedef struct block {
    size_t size;          // Total size of the block (including this header)
    int free;             // Flag: 1 if the block is free, 0 if allocated
    struct block *next;   // Pointer to the next block in the heap list
    struct block *prev;   // Pointer to the previous block in the heap list
    uint32_t magic;       // Magic number for integrity checking (debugging)
} block_t;

// Heap metadata structure
typedef struct {
    void *start;          // Start address of the heap
    void *end;            // Current end address of the heap (program break)
    block_t *first_block; // Pointer to the first block in the heap list
    block_t *last_block;  // Pointer to the last block in the heap list (optimization)
} heap_info_t;

// Global heap information, initialized to NULL/0
static heap_info_t heap = {NULL, NULL, NULL, NULL};
// Mutex for ensuring thread-safety of heap operations
static pthread_mutex_t heap_mutex = PTHREAD_MUTEX_INITIALIZER;


// Align size to 8 bytes (common requirement for payloads)
#define ALIGN(size) (((size) + 7) & ~7)
// Size of the block header
#define BLOCK_SIZE sizeof(block_t)
// Minimum size for any block (must be at least big enough for a header)
// If a block is split, the remainder must be at least this size.
#define MIN_BLOCK_SIZE (sizeof(block_t)) // Smallest manageable unit
// Magic numbers to identify block state (helps detect corruption)
#define MAGIC_FREE 0xDEADBEEF
#define MAGIC_ALLOC 0xABCDEF00
// Minimum size to extend heap by, to reduce sbrk calls
#define HEAP_EXTEND_CHUNK_SIZE (4096)


// ~~~~~~~~~~~~~~~~~~~~~~~~~ Helper Functions ~~~~~~~~~~~~~~~~~~~~~~~~~

// Validates a block header's integrity
static int is_valid_block(block_t *block) {
    if (!block) return 0; // Null pointer is not a valid block
    // Check if block pointer is within current heap boundaries
    if (heap.start && ( (void*)block < heap.start || (void*)((char*)block + block->size) > heap.end) ) {
        // Allowing block to be exactly at heap.end if its size is 0 (should not happen with valid blocks)
        // A more precise check: (void*)block < heap.start || (void*)block >= heap.end
        // And ((char*)block + block->size) > (char*)heap.end
        // For simplicity, let's stick to the original logic slightly modified:
        if ((void*)block < heap.start || (void*)block >= heap.end) return 0;
    }
    // Check for known magic numbers
    if (block->magic != MAGIC_FREE && block->magic != MAGIC_ALLOC) return 0;
    // Check if block size is reasonable
    if (block->size < BLOCK_SIZE) return 0; // Size must be at least header size
    if (heap.end && block->size > (size_t)((char*)heap.end - (char*)block)) return 0; // Block cannot extend beyond heap

    return 1;
}

// Extends the heap by at least 'size' bytes using sbrk()
// Returns a pointer to the start of the newly allocated heap area, or NULL on failure.
static void *extend_heap_size(size_t size) {
    void *current_break = sbrk(0); // Get current program break
    void *new_mem = sbrk(size);    // Attempt to extend heap

    if (new_mem == (void *)-1) {
        // sbrk failed (e.g., out of memory)
        return NULL;
    }

    if (!heap.start) {
        // First time extending heap, set its start address
        heap.start = new_mem;
    }
    // Update the end of the heap to the new program break
    heap.end = sbrk(0);
    return new_mem; // Return start of the newly allocated memory
}

// Finds the best-fit free block that can accommodate 'size' bytes
static block_t *find_free_block(size_t size) {
    block_t *current = heap.first_block;
    block_t *best_fit = NULL;
    size_t smallest_diff = SIZE_MAX; // Using SIZE_MAX from stddef.h via stdint.h

    while (current) {
        // Check if block is valid, free, and large enough
        if (is_valid_block(current) && current->free && current->magic == MAGIC_FREE && current->size >= size) {
            if (current->size == size) {
                // Exact fit found, this is the best possible
                return current;
            }
            if (current->size < smallest_diff) { // Original code used current->size < best_size
                                                 // Correct logic is to find smallest suitable block
                smallest_diff = current->size;   // Store size of this candidate
                best_fit = current;              // This is the best fit so far
            }
        }
        current = current->next;
    }
    return best_fit;
}

// Splits 'block_to_split' if it's larger than 'size_for_first_part'
// The first part (block_to_split) gets 'size_for_first_part'.
// The remainder becomes a new free block.
static void split_block(block_t *block_to_split, size_t size_for_first_part) {
    // block_to_split is the block that has been chosen for allocation.
    // size_for_first_part is the size (including header) that this allocation needs.

    size_t original_block_size = block_to_split->size;
    size_t remaining_size = original_block_size - size_for_first_part;

    // Only split if the remaining part is large enough to form a new valid block
    if (remaining_size >= MIN_BLOCK_SIZE) {
        block_t *new_free_splinter = (block_t *)((char *)block_to_split + size_for_first_part);
        new_free_splinter->size = remaining_size;
        new_free_splinter->free = 1;
        new_free_splinter->magic = MAGIC_FREE;
        new_free_splinter->prev = block_to_split;
        new_free_splinter->next = block_to_split->next;

        if (block_to_split->next) { // If block_to_split was not the last block
            block_to_split->next->prev = new_free_splinter;
        } else { // block_to_split was the last block, so new_free_splinter is now the last
            heap.last_block = new_free_splinter;
        }

        block_to_split->next = new_free_splinter;
        block_to_split->size = size_for_first_part; // Resize the original (now allocated) block
    }
    // Else: No split. The block_to_split uses its original_block_size.
    // The allocated portion effectively uses the whole block, potentially causing internal fragmentation.
    // block_to_split->size remains original_block_size in this case.
}


// Coalesces 'block' with adjacent free blocks (next and/or prev)
// Returns a pointer to the start of the coalesced block.
static block_t *coalesce(block_t *block) {
    if (!is_valid_block(block)) return block; // Should not happen with valid free operations

    // Coalesce with the next block if it's free
    if (block->next && is_valid_block(block->next) &&
        block->next->free && block->next->magic == MAGIC_FREE) {
        block_t *next_block = block->next;
        block->size += next_block->size;
        block->next = next_block->next;
        if (next_block->next) { // If there was a block after next_block
            next_block->next->prev = block;
        } else { // The merged block is now the last block
            heap.last_block = block;
        }
    }

    // Coalesce with the previous block if it's free
    if (block->prev && is_valid_block(block->prev) &&
        block->prev->free && block->prev->magic == MAGIC_FREE) {
        block_t *prev_block = block->prev;
        prev_block->size += block->size;
        prev_block->next = block->next;
        if (block->next) { // If there was a block after 'block'
            block->next->prev = prev_block;
        } else { // The merged block (prev_block) is now the last block
            heap.last_block = prev_block;
        }
        block = prev_block; // The coalesced block starts at prev_block
    }
    return block;
}

// ~~~~~~~~~~~~~~~~~~~~~~~~~ Core Allocator Functions ~~~~~~~~~~~~~~~~~~~~~~~~~

// Allocates 'size' bytes of memory
void *malloc(size_t size) {
    if (size == 0) {
        return NULL; // Standard behavior: malloc(0) can return NULL or a unique pointer
    }

    // Calculate total size needed: payload size + header size, then aligned
    size_t total_size = ALIGN(size + BLOCK_SIZE);
    // Ensure block is at least MIN_BLOCK_SIZE
    if (total_size < MIN_BLOCK_SIZE) {
        total_size = MIN_BLOCK_SIZE;
    }

    pthread_mutex_lock(&heap_mutex); // --- Lock for thread safety ---

    block_t *block_to_allocate = find_free_block(total_size);

    if (!block_to_allocate) {
        // No suitable free block found, extend the heap
        size_t extend_chunk = total_size > HEAP_EXTEND_CHUNK_SIZE ? total_size : HEAP_EXTEND_CHUNK_SIZE;
        void *new_heap_mem = extend_heap_size(extend_chunk);

        if (!new_heap_mem) {
            // sbrk failed to extend heap
            pthread_mutex_unlock(&heap_mutex); // --- Unlock ---
            return NULL;
        }

        block_to_allocate = (block_t *)new_heap_mem;
        block_to_allocate->size = extend_chunk;
        block_to_allocate->free = 0; // Will be marked allocated
        block_to_allocate->magic = MAGIC_ALLOC; // Mark as allocated for now
        block_to_allocate->prev = heap.last_block; // Link to previous last block
        block_to_allocate->next = NULL;

        if (heap.last_block) {
            heap.last_block->next = block_to_allocate;
        } else { // This is the first block in the heap
            heap.first_block = block_to_allocate;
        }
        heap.last_block = block_to_allocate; // Update the last block pointer

        // Now, split this newly extended block if it's larger than needed
        split_block(block_to_allocate, total_size);

    } else {
        // Found a suitable free block
        block_to_allocate->free = 0;
        block_to_allocate->magic = MAGIC_ALLOC;
        // Split the found block if it's larger than necessary
        split_block(block_to_allocate, total_size);
    }

    pthread_mutex_unlock(&heap_mutex); // --- Unlock ---

    // Return pointer to the payload area (after the header)
    return (char *)block_to_allocate + BLOCK_SIZE;
}

// Frees a previously allocated memory block pointed to by 'ptr'
void free(void *ptr) {
    if (!ptr) {
        return; // free(NULL) is a no-op
    }

    pthread_mutex_lock(&heap_mutex); // --- Lock for thread safety ---

    // Get the block header from the payload pointer
    block_t *block_to_free = (block_t *)((char *)ptr - BLOCK_SIZE);

    // Validate the block before freeing
    if (!is_valid_block(block_to_free) || block_to_free->magic != MAGIC_ALLOC || block_to_free->free) {
        // Invalid pointer, or block not allocated by this malloc, or double free
        pthread_mutex_unlock(&heap_mutex); // --- Unlock ---
        // Optionally: abort() or print an error for debugging
        return;
    }

    block_to_free->free = 1;
    block_to_free->magic = MAGIC_FREE;
    coalesce(block_to_free); // Attempt to merge with adjacent free blocks

    pthread_mutex_unlock(&heap_mutex); // --- Unlock ---
}

// Allocates memory for an array of 'nmemb' elements of 'size' bytes each,
// and initializes all bytes to zero.
void *calloc(size_t nmemb, size_t size) {
    // Check for multiplication overflow: nmemb * size
    if (nmemb > 0 && size > SIZE_MAX / nmemb) {
        return NULL; // Overflow would occur
    }

    size_t total_bytes = nmemb * size;
    if (total_bytes == 0) { // calloc(0, N) or calloc(N,0) should return NULL or a unique ptr
        return NULL;      // Consistent with malloc(0) returning NULL
    }

    void *ptr = malloc(total_bytes);
    if (ptr) {
        // Initialize allocated memory to zero
        memset(ptr, 0, total_bytes);
    }
    return ptr;
}

// Changes the size of the memory block pointed to by 'ptr' to 'size' bytes
void *realloc(void *ptr, size_t size) {
    if (!ptr) {
        // If ptr is NULL, realloc behaves like malloc(size)
        return malloc(size);
    }

    if (size == 0) {
        // If size is 0, realloc behaves like free(ptr) and returns NULL
        free(ptr);
        return NULL;
    }

    pthread_mutex_lock(&heap_mutex); // --- Lock for thread safety ---

    block_t *block = (block_t *)((char *)ptr - BLOCK_SIZE);

    // Validate the block
    if (!is_valid_block(block) || block->magic != MAGIC_ALLOC || block->free) {
        pthread_mutex_unlock(&heap_mutex); // --- Unlock ---
        return NULL; // Invalid block
    }

    size_t aligned_new_payload_size = ALIGN(size);
    size_t new_total_block_size = aligned_new_payload_size + BLOCK_SIZE;
     if (new_total_block_size < MIN_BLOCK_SIZE) { // Should be ALIGN(size + BLOCK_SIZE)
        new_total_block_size = MIN_BLOCK_SIZE;
    }
    // More accurate new_total_block_size calculation like in malloc:
    new_total_block_size = ALIGN(size + BLOCK_SIZE);
    if (new_total_block_size < MIN_BLOCK_SIZE) new_total_block_size = MIN_BLOCK_SIZE;


    size_t old_block_total_size = block->size;
    size_t old_payload_size = old_block_total_size - BLOCK_SIZE;


    if (new_total_block_size <= old_block_total_size) {
        // New size is smaller or same; shrink the block if possible (by splitting)
        split_block(block, new_total_block_size);
        pthread_mutex_unlock(&heap_mutex); // --- Unlock ---
        return ptr; // Original pointer is still valid
    }

    // New size is larger. Try to expand by merging with next block if it's free and large enough.
    if (block->next && is_valid_block(block->next) && block->next->free &&
        (old_block_total_size + block->next->size) >= new_total_block_size) {

        block_t* next_b = block->next;
        // Merge with next block
        block->size += next_b->size; // Increase current block's size
        block->next = next_b->next;   // Bypass the merged next_b

        if (block->next) { // If there was a block after next_b
            block->next->prev = block;
        } else { // block is now the last in the list
            heap.last_block = block;
        }
        // No need to change magic or free status of 'block' as it's still allocated.
        // Split the now larger block if it's too big for the realloc request
        split_block(block, new_total_block_size);
        pthread_mutex_unlock(&heap_mutex); // --- Unlock ---
        return ptr; // Original pointer is still valid
    }

    pthread_mutex_unlock(&heap_mutex); // --- Unlock before calling malloc/free ---

    // Cannot expand in place. Allocate new block, copy data, and free old block.
    void *new_ptr = malloc(size); // 'size' here is payload size
    if (new_ptr) {
        // Copy data from old block to new block
        // Copy up to the smaller of the old payload size and the new requested payload size
        memcpy(new_ptr, ptr, (old_payload_size < size) ? old_payload_size : size);
        free(ptr); // Free the old block
    }
    // If malloc fails, new_ptr will be NULL, and original block is not freed.
    return new_ptr;
}
