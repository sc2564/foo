// This is the MP2 of the OS class from Cornell CS4410, have fun and cheers!
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <assert.h>
#include<pthread.h>

#include "malloc.h"
#include "memreq.h"

#define Alignment 8			// initial the alignment as 8
#define align(x) (x-1)/Alignment * Alignment + Alignment			// define the alignment rule
#define max_size_t (size_t)-1			// declare the maximum number of size_t

/* A BST is used to track chucks of memory.
   Because the alignment is at least 2 bytes for no matter what kinds of machine, 
   the last bit of size in the block_header_t structure can be used to indicate 
   whether this memory chuck is free or not.
   In my implementation, if the last bit of size is 0, the memory chuck is free;
   otherwise, it is not. */
typedef struct block_header {
	struct block_header *left;
	struct block_header *right;
	size_t size;		// last bit of this size variable is used to indicate whether this memory chuck is free. 
						// 0 is free, 1 is not.
} block_header_t;

#define BLOCK_HEADER_SIZE align(sizeof(block_header_t))

static block_header_t *heap_start_point = NULL;			// declare the root of the BST data structure

// All function declared here
block_header_t *find_best_fit(size_t size);
void BST_add_node(block_header_t *header);
block_header_t *allocate_more_heap(size_t size);
void BST_delete_node(block_header_t *header);
void add_to_BST_by_given_root(block_header_t *root, block_header_t *new_node);
void BST_delete_rotate_left(block_header_t *parent, block_header_t *delete_point);
void BST_delete_rotate_right(block_header_t *parent, block_header_t *delete_point);
void node_split_addto_BST(block_header_t *header, size_t block_size);
void *malloc(size_t size);
static size_t highest(size_t in);
void* calloc(size_t number, size_t size);
void* realloc(void *ptr, size_t size);
void free(void* ptr);


// navigate the whole BST to find the best fit block and return the pointer
// best fit means creating the least amount of fragmentation if occupying that chuck of memory
block_header_t *find_best_fit(size_t size){
	block_header_t *ptr = heap_start_point;
	assert(ptr != NULL);
	block_header_t *min_ptr = NULL;
	size_t min = max_size_t; 
	while(ptr){
		if(!(ptr -> size & 1L) && ((ptr -> size & ~1L) >= size)){
			if(((ptr -> size & ~1L) - size) < min){
				min = ptr -> size & ~1L;
				min_ptr = ptr;
			}
		}
		if((ptr -> size & ~1L) > size){
			ptr = ptr -> left;
		} else{
			ptr = ptr -> right;
		}
	}
	return min_ptr;
}

void BST_add_node(block_header_t *header){
	if(heap_start_point == NULL){
		heap_start_point = header;
		return;
	}
	size_t size = header -> size;
	block_header_t *ptr = heap_start_point;
	block_header_t *left_leaf = NULL;
	block_header_t *right_leaf = NULL;
	while(ptr){
		if((ptr -> size & ~1L) > size){
			left_leaf = ptr;
			right_leaf = NULL;
			ptr = ptr -> left;
		} else{
			right_leaf = ptr;
			left_leaf = NULL;
			ptr = ptr -> right;
		}
	}
	assert(!(right_leaf == NULL && left_leaf == NULL));
	if(right_leaf == NULL){
		left_leaf -> left = header;
	}
	if(left_leaf == NULL){
		right_leaf -> right = header;
	}
	header -> left = NULL;
	header -> right = NULL;
}

block_header_t *allocate_more_heap(size_t size){
	block_header_t *current_break = (block_header_t *)get_memory(0);
	size_t block_size = align(BLOCK_HEADER_SIZE + size);
	if(get_memory(block_size) == NULL){
		errno = ENOMEM;
		//exit(1);
		return NULL;
	} else{
		current_break -> size = block_size;
		current_break -> left = NULL;
		current_break -> right = NULL;
		BST_add_node(current_break);
		return current_break;
	}
}

void BST_delete_node(block_header_t *header){
	if(header == heap_start_point){
		block_header_t *left_child = header -> left;
		block_header_t *right_child = header -> right;
		if(left_child == NULL){
			heap_start_point = right_child;
		} else if(right_child == NULL){
			heap_start_point = left_child;
		} else{
			heap_start_point = right_child;
			if(heap_start_point -> left == NULL){
				heap_start_point -> left = left_child;
			} else{
				add_to_BST_by_given_root(heap_start_point -> left, left_child);
			}
		}
	} else{	
		block_header_t *ptr = heap_start_point;
		size_t size = header -> size;
		while(ptr -> left != header && ptr -> right != header){
			if((ptr -> size & ~1L) > size){
				ptr = ptr -> left;
			} else{
				ptr = ptr -> right;
			}
		}
		if(ptr -> left == header){
			BST_delete_rotate_left(ptr, header);
		} else{
			BST_delete_rotate_right(ptr, header);
		}
	}
}

void add_to_BST_by_given_root(block_header_t *root, block_header_t *new_node){
	if(new_node == NULL){
		return;
	}
	block_header_t *ptr = root;
	block_header_t *left_leaf = NULL;
	block_header_t *right_leaf = NULL;
	size_t size = new_node -> size;
	while(ptr){
		if((ptr -> size & ~1L) > size){
			left_leaf = ptr;
			right_leaf = NULL;
			ptr = ptr -> left;
		} else{
			right_leaf = ptr;
			left_leaf = NULL;
			ptr = ptr -> right;
		}
	}
	assert(!(left_leaf == NULL && right_leaf == NULL));
	if(right_leaf == NULL){
		left_leaf -> left = new_node;
	}
	if(left_leaf == NULL){
		right_leaf -> right = new_node;
	}
}

void BST_delete_rotate_left(block_header_t *parent, block_header_t *delete_point){
	block_header_t *left_child = delete_point -> left;
	block_header_t *right_child = delete_point -> right;
	if(right_child == NULL){
		parent -> left = left_child;
	} else{
		parent -> left = right_child;
		if(right_child -> left == NULL){
			right_child -> left = left_child;
		} else{
			add_to_BST_by_given_root(right_child -> left, left_child);
		}
	}
}

void BST_delete_rotate_right(block_header_t *parent, block_header_t *delete_point){
	block_header_t *left_child = delete_point -> left;
	block_header_t *right_child = delete_point -> right;
	if(left_child == NULL){
		parent -> right = right_child;
	} else{
		parent -> right = left_child;
		if(left_child -> right == NULL){
			left_child -> right = right_child;
		} else{
			add_to_BST_by_given_root(left_child -> right, right_child);
		}
	}
}

void node_split_addto_BST(block_header_t *header, size_t block_size){
	assert(header -> size >= block_size);
	if(header -> size <= block_size + BLOCK_HEADER_SIZE){
		header -> size = header -> size | 1L;
		return;
	}
	block_header_t *new_ptr = (block_header_t *)((char *)header + block_size);
	assert(!(header -> size & 1L));
	new_ptr -> size = header -> size - block_size;
	new_ptr -> size = new_ptr -> size & ~1L;
	new_ptr -> left = NULL;
	new_ptr -> right = NULL;
	block_header_t *new_header = header;
	new_header -> size = block_size;
	new_header -> size = new_header -> size | 1L;
	new_header -> left = NULL;
	new_header -> right = NULL;
	BST_delete_node(header);
	BST_add_node(new_header);
	BST_add_node(new_ptr);
	return;
}
	
	
	
void *malloc(size_t size) {
    size_t block_size = align(BLOCK_HEADER_SIZE + size);
	if(heap_start_point != NULL){
		block_header_t *best_place = find_best_fit(block_size);
		if(best_place == NULL){
			best_place = allocate_more_heap(size);
			if(best_place == NULL){
				return NULL;
			}
			best_place -> size = best_place -> size | 1L;
		} else{
			node_split_addto_BST(best_place, block_size);
		}
		return (char *)best_place + BLOCK_HEADER_SIZE;
	} else{
		block_header_t *return_ptr = allocate_more_heap(size);
		if(return_ptr == NULL){
			return NULL;
		}
		return_ptr -> size = return_ptr -> size | 1L;
		return (char *)return_ptr + BLOCK_HEADER_SIZE;
	}
}

static size_t highest(size_t in) {
    size_t num_bits = 0;

    while (in != 0) {
        ++num_bits;
        in >>= 1;
    }

    return num_bits;
}

void* calloc(size_t number, size_t size) {
    size_t number_size = 0;
    if (number == 0 || size == 0)
	    return NULL;
    /* This prevents an integer overflow.  A size_t is a typedef to an integer
     * large enough to index all of memory.  If we cannot fit in a size_t, then
     * we need to fail.
     */
    if (highest(number) + highest(size) > sizeof(size_t) * CHAR_BIT) {
        errno = ENOMEM;
        return NULL;
    }

    number_size = number * size;
    void* ret = malloc(number_size);

    if (ret) {
        memset(ret, 0, number_size);
    }

    return ret;
}

void* realloc(void *ptr, size_t size) {
    if (ptr == NULL) {
	    return malloc(size);
	}
	if (size == 0) {
        free (ptr);
		return NULL;
	}
    size_t old_size = (((block_header_t *)(ptr) - 1) -> size) & ~1L; /* XXX Set this to the size of the buffer pointed to by ptr */
    void* ret = malloc(size);

    if (ret) {
        if (ptr) {
            memmove(ret, ptr, old_size < size ? old_size : size);
            free(ptr);
        }

        return ret;
    } else {
        errno = ENOMEM;
        return NULL;
    }
}

void free(void* ptr) {
	if(ptr == NULL){
		return;
	}
	((block_header_t *)(ptr) - 1) -> size &= ~1L;
}
