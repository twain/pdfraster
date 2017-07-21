#ifndef _H_PdfArray
#define _H_PdfArray
#pragma once

#include "PdfOS.h"
#include "PdfValues.h"
#include "PdfAlloc.h"

// Allocate and return an array, with specified initial capacity.
extern t_pdarray *pd_array_new(t_pdmempool *alloc, pduint32 initialSize);

// Free an array.
// Note, does NOT free any objects referenced by the values in the array.
extern void pd_array_free(t_pdarray *arr);

// free an array along with all the values in the array:
void pd_array_destroy(t_pdvalue *arr);

// Return the number of in-use elements in the array AKA the length of the array.
extern pduint32 pd_array_count(t_pdarray *arr);

// Return the number of elements for which storage is currently allocated to the array.
// AKA the capacity of the array.
extern pduint32 pd_array_capacity(t_pdarray *arr);

// Return the value at index in the array.
// If arr is NULL or index is out of bounds, returns the error value.
extern t_pdvalue pd_array_get(t_pdarray *arr, pduint32 index);

// Set value at index in the array.
// If arr is NULL or index is outside the bounds of the array, does nothing.
extern void pd_array_set(t_pdarray *arr, pduint32 index, t_pdvalue value);

// Insert value at index in array.
// Returns PD_TRUE if successful, PD_FALSE otherwise.
// Fails if arr is NULL or index is outside the bounds of the array,
// OR if memory allocation fails.
extern pdbool pd_array_insert(t_pdarray *arr, pduint32 index, t_pdvalue value);

// Add a value at the end of an array.
// Returns PD_TRUE if successful, PD_FALSE otherwise.
// Fails if arr is NULL OR if memory allocation fails.
extern pdbool pd_array_add(t_pdarray *arr, t_pdvalue value);

// Remove and return the value at index in array.
// Returns the removed value if successful, an error value otherwise.
// Fails if arr is NULL or if index is outside the bounds of the array.
extern t_pdvalue pd_array_remove(t_pdarray *arr, pduint32 index);

typedef pdbool(*f_pdarray_iterator)(t_pdarray *arr, pduint32 currindex, t_pdvalue value, void *cookie);
// Call iter for each element in the array.
// iter is passed the array, the index of the element, the value of the element, and the cookie.
// Continues as long as iter returns PD_TRUE, stops if iter returns PD_FALSE.
extern void pd_array_foreach(t_pdarray *arr, f_pdarray_iterator iter, void *cookie);

// Create and return an array containing the n variable arguments (of type t_pdvalue).
// If memory allocation fails, returns the error value.
extern t_pdarray *pd_array_build(t_pdmempool *pool, pduint32 n, t_pdvalue values[]);

// Create and return an array containing the n variable arguments (of type pdint32).
// If memory allocation fails, returns the error value.
extern t_pdarray *pd_array_buildints(t_pdmempool *pool, pduint32 n, pdint32 values[]);

// Create and return an array containing the n variable arguments (of type double).
// If memory allocation fails, returns the error value.
extern t_pdarray *pd_array_buildfloats(t_pdmempool *pool, pduint32 n, double values[]);

#endif
