#ifndef _H_PdfStreaming
#define _H_PdfStreaming
#pragma once

// This module implements a logical "PDF writing" stream.
// It provides the usual formatted output functions, plus some specialized ones.
// It knows how to translate internal PDF objects and values into
// PDF file format.
// And it has special hooks to handle encryption.

#include "PdfAlloc.h"
#include "PdfValues.h"
#include "PdfSecurityHandler.h"

#ifdef __cplusplus
extern "C" {
#endif

// When writing PDF, floats (reals) are only represented
// to this many digits of precision:
#define REAL_PRECISION 10


// output event codes
typedef enum {
    PDF_EVENT_BEFORE_TRAILER,       // event before "trailer"
    PDF_EVENT_BEFORE_XREF,          // just before xref table is emitted
    PDF_EVENT_BEFORE_STARTXREF,		// just before startxref is emitted
    PDF_OUTPUT_EVENT_COUNT
} PdfOutputEventCode;

// Signature of callback that can be attached to various
// events that occur while PDF stream is being generated.
typedef int (*fOutStreamEventHandler)(t_pdoutstream *stm, void* cookie, PdfOutputEventCode eventid);

// Create a new PDF output stream
extern t_pdoutstream *pd_outstream_new(t_pdmempool *allocsys, t_OS *os);

// Destroy a PDF output stream
extern void pd_outstream_free(t_pdoutstream *stm);

// Attach an 'encrypter' to this stream.
// By default this enables encryption of the PDF written thru this stream.
extern void pd_outstream_set_encrypter(t_pdoutstream *stm, t_pdencrypter *crypt);

// Return the encrypter currently associated with a stream - or NULL if none.
extern t_pdencrypter* pd_outstream_get_encrypter(t_pdoutstream *stm);

// Write one character to a stream.
extern void pd_putc(t_pdoutstream *stm, char c);

// Write a 0-terminated C string to a stream.
// If stm is null, does nothing.
// s==NULL is treated as s==""
extern void pd_puts(t_pdoutstream *stm, char *s);

// Write a byte as two hex digits to a stream.
// Always writes 2 digits, uppercase.
// If stm is null, does nothing.
extern void pd_puthex(t_pdoutstream *stm, pduint8 b);

// Write n bytes from s+offset to a stream.
extern void pd_putn(t_pdoutstream *stm, const void *s, pduint32 offset, pduint32 n);

// Write a decimal representation of an integer to a stream.
// All possible values are handled: -2147483648 to 2147483647
// If i < 0, a '-' is prefixed.
// The output is written with the minimum number of characters needed.
extern void pd_putint(t_pdoutstream *stm, pdint32 i);

// Write a floating-point number to a stream.
// A traditional decimal fractional notation is used,
// [-]integer-part[.fraction]
// The leading minus is output iff the value f < 0.
// The fractional part is output iff the value is not integral:
// Exact integral values are output as integers.
// (-0.0 is output as "0")
// This function is not obligated to output more than REAL_PRECISION significant digits.
// The decimal separator is *always* a period, '.'.
// Given any NaN, writes "nan".
// Given an infinity, writes "inf", with a leading minus-sign if negative.
extern void pd_putfloat(t_pdoutstream *stm, pddouble f);

// Return the current offset (position) in the stream.
// (Number of bytes written to the stream since it was created.)
extern pduint32 pd_outstream_pos(t_pdoutstream *stm);

/// Write a t_pdvalue to a stream.
extern void pd_write_value(t_pdoutstream *stm, t_pdvalue value);

// Write the definition of an indirect object to a stream.
// If ref is not an indirect object OR has already been written, does nothing.
extern void pd_write_reference_declaration(t_pdoutstream *stm, t_pdvalue ref);

// Write the PDF header to the stream.
// version is a string with the header version e.g. "1.4".
extern void pd_write_pdf_header(t_pdoutstream *stm, char *version);

// Write all the stuff that goes at the end of a PDF, to a stream.
extern void pd_write_endofdocument(t_pdoutstream *stm,
	t_pdxref *xref,
	t_pdvalue catalog,
	t_pdvalue info,
	t_pdvalue trailer);

// attach an event handler to an output event on a PDF output stream.
// setting a NULL handler is valid and means 'no event handler'.
extern void pd_outstream_set_event_handler(t_pdoutstream *stm, PdfOutputEventCode eventid, fOutStreamEventHandler handler, void *cookie);

// Invoke the event handler, if any, attached to the specified event on this stream.
// The event handler is called with the stream, the cookie, the eventid, and the arglist.
extern int pd_outstream_fire_event(t_pdoutstream *stm, PdfOutputEventCode eventid);

// Set writer function.
// Return previous stored writer function.
extern fOutputWriter pd_outputstream_set_writer(t_pdoutstream* stm, fOutputWriter writer);

// Set cookie for writer handler
// Return previous stored cookie
extern void* pd_outputstream_set_cookie(t_pdoutstream* stm, void* cookie);

#ifdef __cplusplus
}
#endif
#endif
