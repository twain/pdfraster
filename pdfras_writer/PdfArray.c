#include "PdfArray.h"
#include <assert.h>

#define kSomeReasonableDefaultSize 12

struct t_pdarray {
	pduint32 size;				// no. of entries in use
	pduint32 maxsize;			// no. of entries allocated (data)
	t_pdvalue *data;			// storage for entries
};

t_pdarray *pd_array_new(t_pdmempool *pool, pduint32 initialSize)
{
	if (pool) {
		t_pdarray *arr = (t_pdarray *)pd_alloc(pool, sizeof(t_pdarray));
		if (arr) {
			arr->size = 0;
			initialSize = initialSize ? initialSize : kSomeReasonableDefaultSize;
			arr->data = (t_pdvalue *)pd_alloc(pool, initialSize * sizeof(t_pdvalue));
			if (arr->data) {
				arr->maxsize = initialSize;
				return arr;
			}
			// FAIL
			pd_free(arr);
		}
	}
	// Failure
	return NULL;
}

void pd_array_free(t_pdarray *arr)
{
	if (arr) {
		if (arr->data)
		{
			pd_free(arr->data);
		}
		pd_free(arr);
	}
}

void pd_array_destroy(t_pdvalue *parr)
{
	if (IS_ARRAY(*parr)) {
		int n = pd_array_count(parr->value.arrvalue);
		while (n--) {
			t_pdvalue e = pd_array_remove(parr->value.arrvalue, n);
			pd_value_free(&e);
		}
		pd_value_free(parr);
	}
}

pduint32 pd_array_count(t_pdarray *arr)
{
	return arr ? arr->size : 0;
}

pduint32 pd_array_capacity(t_pdarray *arr)
{
	return arr ? arr->maxsize : 0;
}

t_pdvalue pd_array_get(t_pdarray *arr, pduint32 index)
{
	if (arr && index < arr->size) {
		return arr->data[index];
	}
	else {
		return pderrvalue();
	}
}

void pd_array_set(t_pdarray *arr, pduint32 index, t_pdvalue value)
{
	if (arr && index < arr->size) {
		arr->data[index] = value;
	}
}

static pdbool grow_by_one(t_pdarray *arr)
{
	if (!arr) {
		return PD_FALSE;
	}
	if (arr->size == arr->maxsize) {
		// array is full, expand capacity
		pduint32 i, newSize = arr->maxsize * 5 / 2;	// reasonable?
		t_pdvalue *newData = (t_pdvalue *)pd_alloc_same_pool(arr, newSize * sizeof(t_pdvalue));
		if (!newData) {
			return PD_FALSE;			// abort! abort!
		}
		// copy data to new block
		for (i = 0; i < arr->size; i++)
		{
			newData[i] = arr->data[i];
		}
		pd_free(arr->data);
		arr->data = newData;
		arr->maxsize = newSize;
	}
	assert(arr->size < arr->maxsize);
	arr->size++;					// claim the new entry at the end
	return PD_TRUE;
}

static void copy_elements(t_pdarray *arr, pduint32 from, pduint32 size, pduint32 to)
{
	int i;
	if (to < from) {
		// moving to lower indices, copy from low to high
		// note, does nothing if size == 0.
		for (i = 0; i < (int)size; i++) {
			assert(from + i < arr->size);
			arr->data[to + i] = arr->data[from + i];
		}
	}
	else if (to > from) {
		// moving to higher indices, copy by working backwards.
		// note, does nothing if size == 0.
		for (i = size - 1; i >= 0; i--) {
			assert(to + i < arr->size);
			arr->data[to + i] = arr->data[from + i];
		}
	}
	else {
		// to == from, do nothing.
	}
}

pdbool pd_array_insert(t_pdarray *arr, pduint32 index, t_pdvalue value)
{
	if (arr && index <= arr->size) {
		if (grow_by_one(arr)) {
			assert(index < arr->size);		// thanks to grow_by_one
			copy_elements(arr, index, arr->size - index - 1, index + 1);
			arr->data[index] = value;
			return PD_TRUE;
		}
	}
	return PD_FALSE;
}

pdbool pd_array_add(t_pdarray *arr, t_pdvalue value)
{
	if (arr) {
		if (grow_by_one(arr)) {
			arr->data[arr->size - 1] = value;
			return PD_TRUE;
		}
	}
	return PD_FALSE;
}

t_pdvalue pd_array_remove(t_pdarray *arr, pduint32 index)
{
	if (arr && index < arr->size) {
		t_pdvalue val = arr->data[index];
		// shuffle entries starting at index+1 down one place:
		copy_elements(arr, index + 1, arr->size - index - 1, index);
		arr->size--;
		return val;
	}
	return pderrvalue();
}

void pd_array_foreach(t_pdarray *arr, f_pdarray_iterator iter, void *cookie)
{
	if (arr && iter && arr->size) {
		pduint32 i;
		for (i = 0; i < arr->size; i++)
		{
			if (!iter(arr, i, arr->data[i], cookie)) {
				break;
			}
		}
	}
}

t_pdarray *pd_array_build(t_pdmempool *pool, pduint32 n, t_pdvalue values[])
{
	// allocate an array with capacity for n elements
	t_pdarray *arr = pd_array_new(pool, n);
	if (arr) {
		pduint32 i;
		for (i = 0; i < n; i++)
		{
			// not very efficient...
			pd_array_add(arr, values[i]);
		}
		// we end up with an n-element array
		assert(arr->size == n);
	}
	return arr;
}

t_pdarray *pd_array_buildints(t_pdmempool *pool, pduint32 n, pdint32 values[])
{
	t_pdarray *arr = pd_array_new(pool, n);
	if (arr) {
		pduint32 i;
		for (i = 0; i < n; i++)
		{
			pd_array_add(arr, pdintvalue(values[i]));
		}
		// we end up with an n-element array
		assert(arr->size == n);
	}
	return arr;
}

t_pdarray *pd_array_buildfloats(t_pdmempool *pool, pduint32 n, double values[])
{
	t_pdarray *arr = pd_array_new(pool, n);
	if (arr) {
		pduint32 i;
		for (i = 0; i < n; i++)
		{
			double v = values[i];
			pd_array_add(arr, pdfloatvalue(v));
		}
		// we end up with an n-element array
		assert(arr->size == n);
	}
	return arr;
}
