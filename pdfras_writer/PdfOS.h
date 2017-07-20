#ifndef _H_PdfOS
#define _H_PdfOS
#pragma once

#include "PdfPlatform.h"

#ifdef __cplusplus
extern "C" {
#endif

// Signature of the memory allocation (malloc) function to be used by the Pdf library
typedef void *(*fAllocate)(size_t bytes);
// (The signature of) the matching free.
typedef void (*fFree)(void *ptr);

#define	REPORTING_INFO      0		// useful to know but not bad news.
#define	REPORTING_WARNING   1		// a potential problem - but execution can continue.
#define	REPORTING_COMPLIANCE 2	    // a violation of the PDF/raster specification was detected.
#define	REPORTING_API       3		// an invalid request was made to this API.
#define	REPORTING_MEMORY    4		// memory allocation failed.
#define	REPORTING_IO        5		// PDF read or write failed unexpectedly.
#define	REPORTING_LIMIT     6		// a built-in limitation of this library was exceeded.
#define	REPORTING_INTERNAL  7		// an 'impossible' internal state has been detected.
#define	REPORTING_OTHER     8		// none of the above, and the current API call cannot complete.

// Signature of the error reporting function, currently not (much?) used.
// The library calls this function to report errors, warnings and obscure information.
// Parameters:
// msg will be a 0-terminated constant string in English with no line-breaks, which
// is only valid & constant *during the call* to the error reporting function.
// In other words, if you want to use it after the call, you must make a copy.
// err is a precise/unique library-defined error code, generated at ONE spot in the library.
// level provides some hint of the kind and severity of the error.
typedef void (*fReportError)(const char* msg, int level, int err);

// Signature of the output function: Writes length bytes from data+offset, to some destination dest.
// Note: As it might change for each document written, the value of dest is provided separately.
// Returns the number of bytes written.
// A return value < length indicates an error such as device full.
typedef int (*fOutputWriter)(const pduint8 *data, pduint32 offset, pduint32 length, void *dest);

// Signature of a memory-filling function (typically, memset)
typedef void (*fMemSet)(void *ptr, pduint8 value, size_t count);

typedef struct {
	fAllocate			alloc;
	fFree				free;
	fReportError		reportError;
	fOutputWriter		writeout;
	void*				writeoutcookie;
	fMemSet				memset;
	struct t_pdmempool *allocsys;
} t_OS;

// Some useful, primitive functions provided both for the use
// of the library and for clients in case they are not readily available
// in the execution environment

extern pdint32 pdstrlen(const char *s);

// convert a signed integer to NUL-terminated string at dst.
// Can write up to 12 chars (counting the trailing NUL) at dst.
extern char *pditoa(pdint32 i, char* dst);

// use this macro to suppress "unreferenced formal parameter" warnings
#define UNUSED_FORMAL(x) ((void)(x))

#ifdef __cplusplus
}
#endif
#endif
