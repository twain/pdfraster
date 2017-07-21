#include "PdfAlloc.h"
#include <assert.h>

struct _t_heapelem;

struct t_pdmempool {
	t_OS *os;
	struct _t_heapelem	*first;		// ptr to first block in use by this pool (or NULL if none)
	pduint32 alloc_count;			// count of allocated-and-not-yet-freed blocks in this pool
	size_t	alloc_bytes;			// total bytes currently allocated to blocks in this pool (excluding overhead)
};

typedef struct _t_heapelem
{
	t_pdmempool *pool;			// owning pool
	struct _t_heapelem	*prev;
	struct _t_heapelem	*next;
	size_t size;
#if PDDEBUG
	char *location;				// hint about where/who allocated.
#endif
	//pduint8 data[0];
} t_heapelem;

extern t_pdmempool *pd_alloc_new_pool(t_OS *os)
{
	t_pdmempool *pool = 0; 
	if (!os) return 0;

	pool = (t_pdmempool*)os->alloc(sizeof(t_pdmempool));
	if (!pool) return NULL;
	pool->os = os;
	pool->alloc_count = 0;
	pool->alloc_bytes = 0;
	pool->first = NULL;
	return pool;
}

size_t pd_get_block_count(t_pdmempool* pool)
{
	return pool->alloc_count;
}

size_t pd_get_bytes_in_use(t_pdmempool* pool)
{
	return pool->alloc_bytes;
}


void pd_free(void *ptr)
{
#if PDDEBUG
	__pd_free(ptr, 1);
#else
	__pd_free(ptr, 0);
#endif
}

t_pdmempool *pd_get_pool(void *ptr)
{
	if (!ptr) return NULL;
	int offset = sizeof(t_heapelem); // offsetof(t_heapelem, data);
	t_heapelem *elem = (t_heapelem *)(((pduint8 *)ptr) - offset);
	return elem->pool;
}

void *__pd_alloc(t_pdmempool *pool, size_t bytes, char *loc)
{

	if (!pool) return NULL;
	size_t totalBytes = bytes + sizeof(t_heapelem);
	t_heapelem *elem = (t_heapelem*)pool->os->alloc(totalBytes);
	if (!elem) return 0;

	elem->size = bytes;
	elem->pool = pool;
	// hook the new block into the pool list
	elem->prev = pool->first;
	if (elem->prev) {
		elem->prev->next = elem;
	}
	elem->next = 0;
	pool->first = elem;

	// track blocks and bytes allocated to this pool:
	pool->alloc_count++;
	pool->alloc_bytes += elem->size;
#if PDDEBUG
	elem->location = loc;
#else
	(void)loc;			// UNUSED
#endif
	// fill block with 0's
	pduint8* data = (pduint8*)elem + sizeof(t_heapelem);
	pool->os->memset(data, 0, bytes);
	return data;
}

void __pd_free(void *ptr, pdbool validate)
{
	if (ptr) {
		int offset = sizeof(t_heapelem);	// offsetof(t_heapelem, data);
		t_heapelem *elem = (t_heapelem *)(((pduint8 *)ptr) - offset);
		t_pdmempool *pool = elem->pool;
		if (validate)
		{
#if PDDEBUG
			t_heapelem *walker = pool->first;
			while (walker)
			{
				pduint8* data = (pduint8*)walker + sizeof(t_heapelem);
				if (data == ptr) break;
				walker = walker->prev;
			}
			assert(walker);
			assert(elem == walker);
#endif
		}
		if (elem == pool->first)
		{
			pool->first = elem->prev;
			if (elem->prev) elem->prev->next = 0;
		}
		else
		{
			elem->next->prev = elem->prev;
			if (elem->prev) elem->prev->next = elem->next;
		}
		pool->alloc_bytes -= elem->size;
		pool->alloc_count--;
		pool->os->memset(elem, 0, sizeof(t_heapelem) + elem->size);
		pool->os->free(elem);
	}
}

size_t pd_get_block_size(void* block)
{
	if (block) {
		int offset = sizeof(t_heapelem);	// offsetof(t_heapelem, data);
		t_heapelem *elem = (t_heapelem *)(((pduint8 *)block) - offset);
		return elem->size;
	}
	else {
		return 0;
	}
}

void pd_pool_clean(t_pdmempool* pool)
{
	if (pool) {
		while (pool->first) {
			void* block = (pduint8*)(pool->first) + sizeof(t_heapelem);
			__pd_free(block, 0);
		}
		assert(pool->first == NULL);
		assert(pool->alloc_count == 0);
		assert(pool->alloc_bytes == 0);
	}
}

void pd_alloc_free_pool(t_pdmempool *pool)
{
	if (pool) {
		t_OS *os = pool->os;
		// free any blocks left in the pool:
		pd_pool_clean(pool);
		// zero the pool (not sure why?)
		os->memset(pool, 0, sizeof(*pool));
		// then give the pool itself back to the platform
		os->free(pool);
	}
}
