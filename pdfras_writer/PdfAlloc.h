#ifndef _H_PdfAlloc
#define _H_PdfAlloc
#pragma once

#include "PdfOS.h"
#ifdef __cplusplus
extern "C" {
#endif


typedef struct t_pdmempool t_pdmempool;

// Create and return an allocation pool, which sub-manages
// memory from the underlying 'os' platform.
extern struct t_pdmempool *pd_alloc_new_pool(t_OS *os);
typedef struct t_pdmempool* (PDFRASAPICALL *pfn_pd_alloc_new_pool)(t_OS *os);

// Return a memory block to a pool.
// ptr = a pointer previously returned by __pd_alloc and not since freed.
// Or NULL, which is ignored.
extern void pd_free(void *ptr);
typedef void (PDFRASAPICALL *pfn_pd_free)();

// Return the number of blocks currently allocated from a pool
extern size_t pd_get_block_count(t_pdmempool* pool);
typedef size_t (PDFRASAPICALL *pfn_pd_get_block_count)(t_pdmempool* pool);

// Return the total bytes currently allocated to blocks in a pool.
// Does not include any overhead, just the sum of the sizes alloc'd and not yet freed.
extern size_t pd_get_bytes_in_use(t_pdmempool* pool);
extern size_t pd_get_block_size(void* block);
typedef size_t (PDFRASAPICALL *pfn_pd_get_bytes_in_use)(t_pdmempool* pool);
typedef size_t (PDFRASAPICALL *pfn_pd_get_block_size)(void* block);

// Frees all the blocks in a pool.
// Same effect as calling pd_free on every outstanding block in the pool.
extern void pd_pool_clean(t_pdmempool* pool);
typedef void (PDFRASAPICALL *pfn_pd_pool_clean)(t_pdmempool* pool);

// (internal) Allocate a block of memory in/from an allocation pool.
// allocsys = allocation pool to allocate from/in.
// nb = number of bytes (at least) to allocate
// loc = string for tracing/debugging allocations, or NULL.
// returns: pointer to at least nb bytes of memory not in use for anything else,
// associated with the allocation pool and filled with 0's.
extern void *__pd_alloc(t_pdmempool *allocsys, size_t nb, char *allocatedBy);
/* no typedef for this one */

// Return the memory pool that a block was allocated from.
// If ptr is NULL, returns NULL.
extern t_pdmempool *pd_get_pool(void *ptr);
typedef t_pdmempool* (PDFRASAPICALL *pfn_pd_get_pool)(void *ptr);

// (internal) Return a memory block to a pool.
// ptr = a pointer previously returned by __pd_alloc and not since freed.
// Or NULL, which is ignored.
// verifyptr = if truthy and DEBUG build, do extra validation
extern void __pd_free(void *ptr, pdbool veryifyptr);
/* no typedef for this one */

// Release an allocation pool.
// This releases all memory associated with the pool back to the
// platform underlying the pool.
extern void pd_alloc_free_pool(t_pdmempool *sys);
typedef void (PDFRASAPICALL *pfn_pd_alloc_free_pool)(t_pdmempool *sys);

#define ELEMENTS(a) (sizeof(a)/sizeof((a)[0]))

// do a pd_alloc of bytes from same pool as an existing block
#define pd_alloc_same_pool(block, bytes) pd_alloc(pd_get_pool(block), bytes)

#if PDDEBUG
#define S1(x) #x
#define S2(x) S1(x)
#define LOCATION __FILE__ " : " S2(__LINE__)
#define pd_alloc(allocsys, bytes) __pd_alloc(allocsys, bytes, LOCATION)
#else
#define pd_alloc(allocsys, bytes) (__pd_alloc(allocsys, bytes, 0))
#endif

#ifdef __cplusplus
}
#endif
#endif

