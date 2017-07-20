#ifndef _H_PdfDict
#define _H_PdfDict
#pragma once

#include "PdfAlloc.h"
#include "PdfValues.h"
#include "PdfHash.h"
#include "PdfStreaming.h"
#include "PdfDatasink.h"

#ifdef __cplusplus
extern "C" {
#endif

// Allocate and return a pointer to a new Dictionary object, as a t_pdvalue
// initialsize is the number of entries to reserve space for - strictly an
// optimization, since dictionaries dynamically expand as needed.
extern t_pdvalue pd_dict_new(t_pdmempool *allocsys, pdint32 initialsize);

// Release a dictionary object and any memory exclusively allocated to it.
// This does *not* release objects referenced by the dictionary that could
// potentially be referenced from outside it.
extern void pd_dict_free(t_pdvalue dict);

// Return PD_TRUE if the dictionary has an entry with the given key,
// PD_FALSE otherwise.
extern pdbool pd_dict_contains(t_pdvalue dict, t_pdatom key);

// Find the key in the dict and return the corresponding value, setting *success to PD_TRUE.
// If the key is not in the dict, returns a null and sets *success to PD_FALSE.
extern t_pdvalue pd_dict_get(t_pdvalue dict, t_pdatom key, pdbool *success);

// Set the value of key in the dictionary.
// If the key is already in the dictionary, the new value replaces the old.
// Otherwise the key is inserted with the new value.
// If anything goes wrong, returns an error value.
// On success, returns the dictionary.
extern t_pdvalue pd_dict_put(t_pdvalue dict, t_pdatom key, t_pdvalue value);

// If the dictionary is a stream returns PD_TRUE, otherwise PD_FALSE.
extern pdbool pd_dict_is_stream(t_pdvalue dict);

// Return the number of entries in the dictionary.
// (If argument is not a dictionary, returns 0.)
extern int pd_dict_count(t_pdvalue dict);

// For each entry in dictionary, call iter(key, value, cookie)
// Continue as long as iter returns non-zero, stop if iter returns 0 (PD_FALSE).
// If dict is not a dictionary or iter is NULL, does nothing.
extern void pd_dict_foreach(t_pdvalue dict, f_pdhashatomtovalue_iterator iter, void *cookie);

// * internal use only *
// Return the current capacity (no. of entries allocated) in a dictionary
extern int __pd_dict_capacity(t_pdvalue dict);

///////////////////////////////////////////////////////////////////////
// Streams - which are a species of Dictionary

// signature of a function that writes data to a sink.
typedef void(*f_on_datasink_ready)(t_datasink *sink, void *eventcookie);

// Create a new PDF Stream object and return an indirect reference to it.
// "All streams shall be indirect objects"
// pool is the allocation pool to use.
// xref is the XREF table to register the Stream in, to generate the reference.
// initialsize is the number of entries to preallocate in the Stream's dictionary.
// ready is a callback that can generate the contents of the Stream when requested.
// eventcookie is a cookie to pass to the ready function.
// <returns>A Reference to the created stream</returns>
extern t_pdvalue stream_new(t_pdmempool *pool, t_pdxref *xref, pdint32 initialsize, f_on_datasink_ready ready, void *eventcookie);

extern void stream_free(t_pdvalue stream);
extern void stream_write_data(t_pdvalue stream, t_datasink* sink);

#ifdef __cplusplus
}
#endif
#endif
