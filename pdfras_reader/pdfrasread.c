#include "pdfrasread.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <limits.h>

#define MIN(a,b) ((a)<(b) ? (a) : (b))
#define MAX(a,b) ((a)>(b) ? (a) : (b))

// how many bytes back from EOF to read when
// checking for PDF/raster marker
#define TAILSIZE 64

///////////////////////////////////////////////////////////////////////
// Internal Constants

#define PDFRASREAD_VERSION "0.7.9.0"
// 0.7.9.0  spike   2016.09.23  look for PDF-raster marker in last TAILSIZE bytes
// 0.7.8.0  spike   2016.09.23  handle PDF comments! (treat as whitespace)
// 0.7.7.0  spike   2016.09.05  slighly improved & simplified dict & stream parsing.
// 0.7.6.0  spike   2016.09.03  /CalRGB parsing, fixed /ICCBased parse
//                              fix! trailer parse failed if NUL in last KByte.
// 0.7.5.0  spike   2016.09.02  pixel format and bits_per_component working (again)
// 0.7.4.0  spike   2016.09.01  more colorspace parsing (/CalGray)
// 0.7.3.0  spike   2016.08.23  created get_strip_info
//                              more colorspace parsing
// 0.7.2.0  spike   2016.08.21  many more error reports esp. compliance
// 0.7.1.0  spike   2016.08.18  internal clean-up, fixing failing tests
// 0.7.0.0  spike   2016.08.17  API change - require a file-size function on create.
// 0.6.0.0  spike   2016.08.14  moved this history inside the library
//                              went to a.b.c.d version
//                              added: pdfrasread_lib_version()
// 0.5  spike   2016.08.13  pdfrasread_recognize_source reports PDF/raster version
//                          new - error handling API.
// 0.4  spike	2016.07.21	first formal reporting of compliance failures
//							reader test fails down to 27.
// 0.3  spike	2016.07.19	minor API and internal improvements
// 0.2  spike	2016.07.13	revised PDF-raster marker in trailer dict.
// 0.1  spike	2015.02.11	1st version

// The highest major version of PDF/raster we can handle
#define RASREAD_MAX_MAJOR   1
// the highest minor version of the highest major version, that we can handle
#define RASREAD_MAX_MINOR   0

#define READER_SIGNATURE 0xD00D

#ifdef _DEBUG
#define CONFIGURATION "DEBUG"
#else
#define CONFIGURATION "RELEASE"
#endif

// size of buffer to use while reading & parsing PDF
// Note - making this bigger doesn't necessarily make things faster,
// because PDF jumps around a lot, and this buffer isn't used
// to read the big objects like strips.
#define BLOCK_SIZE 1024

///////////////////////////////////////////////////////////////////////
// Data Structures & Types

// Cross-reference table entry
// This is the exact byte-aligned layout present in PDF files,
// a fact that the code relies on.
typedef struct t_xref_entry {
	char		offset[10];					// 10-digit byte offset
	char		gen[6];						// space + 5-digit generation number
	char		status[2];					// " n" (in use) or " f" (free)
	char		eol[2];                     // either <space>LF or CR,LF
} t_xref_entry;

//typedef struct _ICCProfile ICCProfile;
// Hmmm, above line refers to undefined struct _ICCProfile
// So *ICCProfile is used as an opaque pointer
// But when compiled as C++ code linker complains
// so replaced it with line below
typedef void ICCProfile;

enum colorspace_style { CS_CALGRAY, CS_DEVICEGRAY, CS_CALRGB, CS_DEVICERGB, CS_ICCBASED };

typedef struct t_colorspace {
    enum colorspace_style style;
    unsigned long		bitsPerComponent;   // bits per component (All styles)
    double				whitePoint[3];
    double				blackPoint[3];
    double              gamma;              // Gamma exponent (all?)
    double              matrix[9];          // 3x3 matrix (CALRGB only)
    ICCProfile*         piccProfile;        // pointer to ICC profile (ICCBASED only)
} t_colorspace;

// All the information about a single page and the image it contains
typedef struct {
	pduint32			off;				// offset of page object in file
	double				MediaBox[4];
	RasterReaderPixelFormat	format;
    t_colorspace        cs;                 // colorspace descriptor
	unsigned long		width;
	unsigned long		height;
	unsigned long		rotation;
	double				xdpi, ydpi;
	int					strip_count;		// number of strips in this page
	size_t				max_strip_size;		// largest (raw) strip size
} t_pdfpageinfo;

// Everything you ever wanted to know about a strip
typedef struct {
    pduint32            pos;                // position of the strip (stream/dict)
    pduint32            data_pos;           // start offset of actual strip data
    long                raw_size;           // size of actual (in-file) strip data
    RasterReaderCompression   compression;        // image compression
    RasterReaderPixelFormat   format;
    t_colorspace        cs;                 // colorspace
    unsigned long       width;
    unsigned long       height;             // of this strip
} t_pdfstripinfo;

// Structure that represents a PDF/raster byte-stream that is open for reading
typedef struct t_pdfrasreader {
    int                 sig;                // safety/validity signature
	int					apiLevel;			// caller's specified API level.
	pdfras_freader		fread;				// function to read from source
    pdfras_fsizer       fsize;              // function to get size of source
	pdfras_fcloser		fclose;				// function to close source
    pdfras_err_handler  error_handler;      // external error-reporting callback
	pdbool				bOpen;				// whether this reader is open
	void*				source;				// cookie/handle to caller-defined source
	pduint32			filesize;			// source size, in bytes
    int                 major, minor;       // level of PDF/raster claimed by source
	struct {
		char			data[BLOCK_SIZE];
		pduint32		off;
		size_t			len;
	}					buffer;
	// cross-reference table
	unsigned long		numxrefs;			// number of entries in xref table
	t_xref_entry*		xrefs;				// xref table (initially NULL, freed at close)
	// page table
	long				page_count;			// actual page count, or -1 for 'unknown'
	pduint32*			page_table;			// table of page positions (freed at close)
} t_pdfrasreader;

///////////////////////////////////////////////////////////////////////
// Global (gasp!) variables

static pdfras_err_handler global_error_handler = pdfrasread_default_error_handler;

///////////////////////////////////////////////////////////////////////
// Functions

///////////////////////////////////////////////////////////////////////
// Utility Functions

#define VALID(p) ((p)!=NULL && (p)->sig==READER_SIGNATURE)

// Find last occurrence of string in data between start and end pointers, and
// return a pointer to it.  If not found, return NULL.
static const char * memrstr(const char* start, const char* end, const char * needle)
{
    size_t ncmp = strlen(needle);
    end -= ncmp;
    while (end >= start) {
        if (memcmp(end, needle, ncmp) == 0) {
            return end;
        }
        --end;
    }
    return NULL;
}

static unsigned long ulmax(unsigned long a, unsigned long b)
{
	return (a >= b) ? a : b;
}

// Utility functions, do not require a reader object
//

// colorspace equality - stricter than equivalence, we expect
// all numbers to be exactly equal, and ICC profiles
// if referenced must be EQ i.e. be the same object.
int colorspace_equal(t_colorspace c, t_colorspace d)
{
    int i;
    if (c.style != d.style) {
        return FALSE;
    }
    if (c.bitsPerComponent != d.bitsPerComponent) {
        return FALSE;
    }
    if (fabs(c.gamma - d.gamma) > 0.00001) {
        return FALSE;
    }
    for (i = 0; i < 3; i++) {
        if (fabs(c.blackPoint[i] - d.blackPoint[i]) > 0.00001 ||
            fabs(c.whitePoint[i] - d.whitePoint[i]) > 0.00001) {
            return FALSE;
        }
    }
    if (c.piccProfile != d.piccProfile) {
        return FALSE;
    }
    return TRUE;
}

int pdfras_parse_pdfr_tag(const char* tag, int* pmajor, int* pminor)
{
    assert(tag);
    if (pmajor) *pmajor = 0;
    if (pminor) *pminor = 0;
	tag += 12;
    {
        int major = 0, minor = 0;
        if (!isdigit(*tag)) return FALSE;
        while (isdigit(*tag)) {
            major = major * 10 + (*tag - '0');
            tag++;
        }
        if (*tag != '.') return FALSE;
        tag++;
        if (!isdigit(*tag)) return FALSE;
        while (isdigit(*tag)) {
            minor = minor * 10 + (*tag - '0');
            tag++;
        }
        if (*tag == 0x0D) {
            tag++;
            if (*tag == 0x0A) tag++;
        }
        else if (*tag == 0x0A) {
            tag++;
        }
        else {
            return FALSE;
        }
        if (pmajor) *pmajor = major;
        if (pminor) *pminor = minor;
    }
	return TRUE;
}

int pdfras_recognize_pdf_header(const void* sig)
{
	if (!sig) {
		return FALSE;
	}
	const char* p = (const char*)sig;
	if (0 != strncmp(p, "%PDF-1.", 7)) {
		return FALSE;
	}
	p += 7;
	if (!isdigit(*p)) return FALSE;
	while (isdigit(*p)) p++;
	if (*p == 0x0D) {
		p++;
		if (*p == 0x0A) p++;
	}
	else if (*p == 0x0A) {
		p++;
	}
	else {
		return FALSE;
	}
	return TRUE;
}

///////////////////////////////////////////////////////////////////////
// Slightly higher-level error reporting functions

static void io_error(t_pdfrasreader* reader, int code, pduint32 hint)
{
    if (VALID(reader)) {
        reader->error_handler(reader, REPORTING_IO, code, hint);
    }
    else {
        global_error_handler(NULL, REPORTING_IO, code, hint);
    }
}

static void memory_error(t_pdfrasreader* reader, pduint32 hint)
{
    if (VALID(reader)) {
        reader->error_handler(reader, REPORTING_MEMORY, READ_MEMORY_MALLOC, hint);
    }
    else {
        global_error_handler(NULL, REPORTING_MEMORY, READ_MEMORY_MALLOC, hint);
    }
}

static void internal_error(t_pdfrasreader* reader, int code, pduint32 line)
{
    if (VALID(reader)) {
        reader->error_handler(reader, REPORTING_INTERNAL, code, line);
    }
    else {
        global_error_handler(NULL, REPORTING_INTERNAL, code, line);
    }
}

static void api_error(t_pdfrasreader* reader, int code, pduint32 hint)
{
    if (VALID(reader)) {
        reader->error_handler(reader, REPORTING_API, code, hint);
    }
    else {
        global_error_handler(NULL, REPORTING_API, code, hint);
    }
}

static void informational(t_pdfrasreader* reader, int code, pduint32 offset)
{
    if (VALID(reader)) {
        reader->error_handler(reader, REPORTING_INFO, code, offset);
    }
    else {
        global_error_handler(NULL, REPORTING_INFO, code, offset);
    }
}

static void warning(t_pdfrasreader* reader, int code, pduint32 offset)
{
    if (VALID(reader)) {
        reader->error_handler(reader, REPORTING_WARNING, code, offset);
    }
    else {
        global_error_handler(NULL, REPORTING_WARNING, code, offset);
    }
}

// report a failure to comply with the PDF/raster spec, at offset in file
static void compliance(t_pdfrasreader* reader, int code, pduint32 offset)
{
    if (VALID(reader)) {
        reader->error_handler(reader, REPORTING_COMPLIANCE, code, offset);
    }
    else {
        global_error_handler(NULL, REPORTING_COMPLIANCE, code, offset);
    }
}

///////////////////////////////////////////////////////////////////////
// low-level header/trailer checking

  // read the last len bytes, or as many as there are, from the reader->source.
  // Append a trailing NUL (so tail buffer's capacity must be at least len+1)
  // Returns the actual number of bytes read into the tail buffer.
static size_t pdfras_read_tail(t_pdfrasreader* reader, char* tail, size_t len)
{
    pduint32 off = reader->filesize;
    off = (off < len) ? 0 : off - len;
    size_t step = reader->fread(reader->source, off, len, tail);
    // make sure it's NUL-terminated but remember it could contain embedded NULs.
    tail[step] = 0;
    return step;
}

int pdfrasread_recognize_source(t_pdfrasreader* reader, void* source, int* pmajor, int* pminor)
{
    char head[32+1];
    char tail[TAILSIZE+1];
    if (pmajor) *pmajor = -1;
    if (pminor) *pminor = -1;
    if (!VALID(reader)) {
        // you gave me junk
        api_error(NULL, READ_API_BAD_READER, __LINE__);
        return FALSE;
    }
    if (pdfrasread_is_open(reader)) {
        // can't do this with a reader that's currently open.
        api_error(reader, READ_API_ALREADY_OPEN, __LINE__);
        return FALSE;
    }
    // temporarily set our source so we can 
    reader->source = source;
    reader->filesize = reader->fsize(reader->source);
    // read the header
    size_t headsize = reader->fread(source, 0, sizeof head-1, head);
    assert(headsize < sizeof head);
    head[headsize] = 0;
    // read the trailer
    size_t tailsize = pdfras_read_tail(reader, tail, sizeof tail - 1);
    // OK, we're done reading
    reader->source = NULL;
    if (!pdfras_recognize_pdf_header(head)) {
        // not PDF
        return FALSE;
    }
    if (!memrstr(tail, tail+tailsize, "%%EOF")) {
        // probably not a PDF
        return FALSE;
    }
    const char* tag = memrstr(tail, tail+tailsize, "%PDF-raster-");
    if (!tag || tag == tail) {
        return FALSE;
    }
    assert(tag > tail);
    int major = 0, minor = 0;
    if ((tag[-1] != 0x0D && tag[-1] != 0x0A) ||
        !pdfras_parse_pdfr_tag(tag, &major, &minor)) {
        // not (valid) PDF/raster
        return FALSE;
    }
    // Looks like a plausible PDF/raster file with version
    if (pmajor) *pmajor = major;
    if (pminor) *pminor = minor;
    if (major < 1 || major > RASREAD_MAX_MAJOR) {
        // Looks like PDF/raster, but the
        // version is outside our comfort zone.
        return FALSE;
    }
    // All good.
    return TRUE;
}

///////////////////////////////////////////////////////////////////////
// Low-level I/O functions

// Read the next buffer-full into the buffer, or up to EOF.
// Append a NUL.
// Set *poff to the offset in the file of the first byte in the buffer.
// If nothing read (at EOF) return FALSE, otherwise return TRUE.
static int advance_buffer(t_pdfrasreader* reader, pduint32* poff)
{
    // Compute file position of next byte after current buffer:
    *poff = reader->buffer.off + reader->buffer.len;
    // Read into buffer as much as will fit (with trailing NUL) or up to EOF:
    reader->buffer.len = reader->fread(reader->source, *poff, sizeof reader->buffer.data - 1, reader->buffer.data);
    // NUL-terminate the buffer
    reader->buffer.data[reader->buffer.len] = 0;
    // TRUE if something was read, FALSE if nothing read (presumably EOF)
    return reader->buffer.len != 0;
}

static int seek_to(t_pdfrasreader* reader, pduint32 off)
{
    if (off < reader->buffer.off || off >= reader->buffer.off + reader->buffer.len) {
        reader->buffer.off = off;
        reader->buffer.len = 0;
        if (!advance_buffer(reader, &off)) {
            assert(off = reader->buffer.off + reader->buffer.len);
            return FALSE;
        }
    }
    assert(off >= reader->buffer.off);
    assert(off < reader->buffer.off + reader->buffer.len);
    return TRUE;
}


///////////////////////////////////////////////////////////////////////
// Single-character scanning methods

// Return the character at the current file position.
// Return -1 if at EOF.
// Does not move the file position.
static int peekch(t_pdfrasreader* reader, pduint32 off)
{
	if (!seek_to(reader, off)) {
		return -1;
	}
	assert(off >= reader->buffer.off);
	assert(off < reader->buffer.off + reader->buffer.len);
	return reader->buffer.data[off - reader->buffer.off];
}

// Get the next character in the file.
// Return -1 if at EOF, otherwise
// increments the file position and returns the char at the new position.
static int nextch(t_pdfrasreader* reader, pduint32* poff)
{
	if (!seek_to(reader, *poff + 1)) {
		return -1;
	}
	++*poff;
	return peekch(reader, *poff);
}

// Advance *poff over any whitespace characters.
// Return FALSE if we end up at EOF (or have a read error)
// otherwise return TRUE.
// In EITHER CASE *poff is updated to skip over any whitespace chars.
static int skip_whitespace(t_pdfrasreader* reader, pduint32* poff)
{
	if (!seek_to(reader, *poff)) {
		return FALSE;
	}
	unsigned i = (*poff - reader->buffer.off);
	assert(i <= reader->buffer.len);
    int in_comment = FALSE;
	while (TRUE) {
		if (i == reader->buffer.len) {
			if (!advance_buffer(reader, poff)) {
				// end of file
				return FALSE;
			}
			i = 0;
		}
		assert(i < reader->buffer.len);
        char ch = reader->buffer.data[i];
        if (in_comment) {
            // once in a comment, only end-of-line chars
            // (or EOF) get us out.
            if (ch == '\r' || ch == '\n') {
                in_comment = FALSE;
            }
        } else if (!isspace(ch)) {
            if (ch == '%') {
                in_comment = TRUE;
            }
            else {
                break;
            }
		}
		// advance over whitespace character:
		i++; *poff += 1;
	}
	assert(i + reader->buffer.off == *poff);
	return TRUE;
}

///////////////////////////////////////////////////////////////////////
// Single token parsing methods

// TRUE if ch is a delimiter character per PDF, FALSE otherwise
static int isdelim(int ch)
{
	switch (ch) {
	case '(':
	case ')':
	case '<':
	case '>':
	case '[':
	case ']':
	case '{':
	case '}':
	case '/':
	case '%':
		return TRUE;
	default:
		return FALSE;
	}
}

static int token_skip(t_pdfrasreader* reader, pduint32* poff)
{
	// skip over whitespace
	if (!skip_whitespace(reader, poff)) {
		// EOF hit
		return FALSE;
	}
	// skip over non-whitespace stuff (roughly, 'a token')
	unsigned i = (*poff - reader->buffer.off);
	// skip_whitespace always leaves us looking at a valid (non-whitespace) character
	// If it can't, it returns FALSE which normally indicates EOF.
	assert(i < reader->buffer.len);
	// capture the starting char of the token
	char ch0 = reader->buffer.data[i];
	while (TRUE) {
		// accept current char, look at next
		i++;
		if (i == reader->buffer.len) {
			if (!advance_buffer(reader, poff)) {
				// end of file, end of token
				break;
			}
			i = 0;
		}
		assert(i < reader->buffer.len);
		// check for a 'token break'
		char ch = reader->buffer.data[i];
		if ('/' == ch0) {
			// A Name is a solidus followed by 'regular characters'
			// terminated by delimiter or whitespace
			if (isspace(ch) || isdelim(ch)) {
				break;
			}
		}
		else if (ch0 == ch && ('<' == ch0 || '>' == ch0)) {
			// we treat << and >> as the only double-delimiter token
			i++;
			break;
		}
		// for our purposes, we consider the delimiters to
		// be tokens, even though '(' for example actually starts a string token
		else if (isdelim(ch0)) {
			break;
		}
		// token started with a regular character
		else if (isspace(ch) || isdelim(ch)) {
			// so delim or whitespace ends it
			break;
		}
		// Not a token break, accept this char and continue.
	}
	*poff = i + reader->buffer.off;;
	// position offset at start of next token
	skip_whitespace(reader, poff);
	return TRUE;
}

// If the next token is the given literal string, skip over it (and following whitespace)
// and return TRUE.  Otherwise leave the offset at the start of the (non-matching) token and
// return FALSE.  
static int token_eat(t_pdfrasreader* reader, pduint32* poff, const char* lit)
{
	// TODO: doesn't handle comments
	char ch0 = *lit;
	// skip over whitespace
	if (!skip_whitespace(reader, poff)) {
		// EOF hit
		return FALSE;
	}
	unsigned i = (*poff - reader->buffer.off);
	assert(i <= reader->buffer.len);
	while (TRUE) {
		if (i == reader->buffer.len) {
			if (!advance_buffer(reader, poff)) {
				// end of file
				return FALSE;
			}
			i = 0;
		}
		assert(i < reader->buffer.len);
		// get the current char from the stream:
		char ch = reader->buffer.data[i];
		if (0 == *lit) {
			// end of string-to-match, check for a 'token break'
			if ('/' == ch0) {
				// Name: solidus followed by 'regular characters'
				// terminated by delimiter or whitespace
				if (isspace(ch) || isdelim(ch)) {
					break;
				}
			}
			else if ('<' == ch0 || '>' == ch0) {
				// assume the match was either to '<<' or '>>'
				// in which case it doesn't matter what follows.
				break;
			}
			// for our purposes, we consider the delimiters to
			// be tokens, even though '(' for example actually starts a string token
			else if (isdelim(ch0)) {
				break;
			}
			// token started with a regular character
			else if (isspace(ch) || isdelim(ch)) {
				// so delim or whitespace ends it
				break;
			}
			return FALSE;
		}
		if (*lit++ != ch) {
			return FALSE;
		}
		i++;
	}
	*poff = i + reader->buffer.off;
	skip_whitespace(reader, poff);
	return TRUE;
}

// Peek at the next token - if it matches the given literal string, return TRUE.
// Otherwise return FALSE.
static int token_match(t_pdfrasreader* reader, pduint32 off, const char* lit)
{
    return token_eat(reader, &off, lit);
}

static int token_eol(t_pdfrasreader* reader, pduint32 *poff)
{
	int ch = peekch(reader, *poff);
	while (isspace(ch)) { ch = nextch(reader, poff); }
	// EOL is CR LF, CR or LF
	if (ch == 0x0D) {
		ch = nextch(reader, poff);
		if (ch == 0x0A) {
			nextch(reader, poff);
		}
	}
	else if (ch == 0x0A) {
		nextch(reader, poff);
	}
	else {
		// Not an EOL
		return FALSE;
	}
	return TRUE;
}

// Parse an unsigned long integer.
// Skips leading and trailing whitespace
static int token_ulong(t_pdfrasreader* reader, pduint32* poff, unsigned long *pvalue)
{
	int ch = peekch(reader, *poff);
	while (isspace(ch)) { ch = nextch(reader, poff); }
	*pvalue = 0;
	if (!isdigit(ch)) {
		return FALSE;
	}
	do {
		*pvalue = *pvalue * 10 + (ch - '0');
		ch = nextch(reader, poff);
	} while (isdigit(ch));
	while (isspace(ch)) { ch = nextch(reader, poff); }
	return TRUE;
}

// Try to parse a number token (inline)
// If successful, put the numeric value in *pdvalue, advance *poff and return TRUE.
// Ignores leading whitespace, and if successful skips over trailing whitespace.
// Otherwise leave *poff unchanged, set *pdvalue to 0 and return FALSE.
static int token_number(t_pdfrasreader* reader, pduint32 *poff, double* pdvalue)
{
	// ISO says: "...one or more decimal digits with an optional sign and a leading,
	// trailing, or embedded PERIOD (2Eh) (decimal point)."
	//
	pduint32 off = *poff;
	skip_whitespace(reader, &off);
	*pdvalue = 0.0;
	double intpart = 0.0, fraction = 0.0;
	int digits = 0, precision = 0;
	// parse leading sign, if any
	char sign = '+';
	char ch = peekch(reader, off);
	if (ch == '-' || ch == '+') { sign = ch; ch = nextch(reader, &off); }
	while (isdigit(ch)) {
		digits++;
		intpart = intpart * 10 + (ch - '0');
		ch = nextch(reader, &off);
	}
	if (ch == '.') {
		ch = nextch(reader, &off);
		while (isdigit(ch)) {
			fraction = fraction * 10 + (ch - '0');
			precision++;
			ch = nextch(reader, &off);
		}
	}
	if (digits + precision == 0) {
		// no digits, not a valid number
		assert(0.0 == *pdvalue);
		return FALSE;
	}
	*pdvalue = intpart + fraction * pow(10, -precision);
	if (sign == '-') {
		*pdvalue = -*pdvalue;
	}
	skip_whitespace(reader, &off);
	*poff = off;
	return TRUE;
}

// A literal string shall be written as an arbitrary number of characters enclosed in parentheses.
// Any characters may appear in a string except unbalanced parentheses (LEFT PARENHESIS (28h) and RIGHT PARENTHESIS (29h))
// and the backslash (REVERSE SOLIDUS (5Ch)), which shall be treated specially as described in this sub-clause.
// Balanced pairs of parentheses within a string require no special treatment.

static int token_literal_string(t_pdfrasreader* reader, pduint32* poff)
{
	pduint32 off = *poff;
	int ch = peekch(reader, off);
	if ('(' != ch) {
		return FALSE;
	}
	int nesting = 0;
	do {
		switch (ch) {
		case ')':
			--nesting;
			break;
		case '(':
			++nesting;
			break;
		case '\\':
			ch = peekch(reader, off + 1);
			if ('n' == ch || 'r' == ch || 't' == ch || 'b' == ch || 'f' == ch ||
				'(' == ch || ')' == ch || '\\' == ch) {
				// designated escapes, accept 2nd char as-is
				off++;
			}
			else if (ch >= '0' && ch <= '7') {
				// octal digit - accept it and up to 2 more
				off++; ch = peekch(reader, off + 1);
				if (ch >= '0' && ch <= '7') {
					// octal digit - accept it and up to 1 more
					off++; ch = peekch(reader, off + 1);
					if (ch >= '0' && ch <= '7') {
						// octal digit - accept it
						off++;
					}
				}
			}
			else {
				// not an escape sequence - ignore solidus
			}
			break;
		case -1:
			// invalid PDF: unexpected EOF in literal string
            compliance(reader, READ_LITSTR_EOF, *poff);
			return FALSE;
		default:
			break;
		} // switch
		ch = nextch(reader, &off);
	} while (nesting > 0);
	skip_whitespace(reader, &off);
	*poff = off;
	return TRUE;
}

static int token_hex_string(t_pdfrasreader* reader, pduint32* poff)
{
	pduint32 off = *poff;
	int ch = peekch(reader, off);
	if ('<' != ch) {
		return FALSE;
	}
	do {
		ch = nextch(reader, &off);
	} while ((ch >= '0' && ch <= '9') ||
		 (ch >= 'A' && ch <= 'F') ||
		 (ch >= 'a' && ch <= 'f') ||
		isspace(ch));
	if (ch != '>') {
		// unexpected character in hexadecimal string
        compliance(reader, READ_HEXSTR_CHAR, off);
		return FALSE;
	}
	nextch(reader, &off);
	skip_whitespace(reader, &off);
	*poff = off;
	return TRUE;
}

///////////////////////////////////////////////////////////////////////
// Xref table access

// Look up the indirect object (num,gen) in the cross-ref table and return its file position *pobjpos.
// Returns TRUE if successful,
// Returns FALSE if no xref entry found, and leaves *pobjpos unchanged.
static int xref_lookup(t_pdfrasreader* reader, unsigned num, unsigned gen, pduint32 *pobjpos)
{
	if (gen != 0) {
		// not in PDF/raster
		return FALSE;
	}
	if (!reader->xrefs) {
		// internal error: no xref table loaded
        internal_error(reader, READ_INTERNAL_XREF_TABLE, __LINE__);
		return FALSE;
	}
	if (num >= reader->numxrefs) {
		// invalid PDF: indirect object number is outside xref table
		return FALSE;
	}
	// parse the offset out of the indicated xref entry
	pduint32 off = strtoul(reader->xrefs[num].offset, NULL, 10);
	// parse & verify the start of the object definition, which should be <num> <gen> obj:
	unsigned long num2, gen2;
	if (!token_ulong(reader, &off, &num2) ||
		!token_ulong(reader, &off, &gen2) ||
		!token_eat(reader, &off, "obj") ||
		num2 != num ||
		gen2 != gen) {
		// invalid PDF: xref table entry doesn't point to object definition
        compliance(reader, READ_OBJ_DEF, off);
		return FALSE;
	}
	// got it, return the position of the stuff inside the object definition:
	*pobjpos = off;
	return TRUE;
}

///////////////////////////////////////////////////////////////////////
// object parsing methods

static int object_skip(t_pdfrasreader* reader, pduint32 *poff);
static int dictionary_lookup(t_pdfrasreader* reader, pduint32 off, const char* key, pduint32 *pvalpos);

// Parse an indirect reference and return the resolved file offset in *pobjpos.
// If successful returns TRUE (and advances *poff to point past the reference)
// If not, returns FALSE, *poff is not changed and *pobjpos is undefined.
static int parse_indirect_reference(t_pdfrasreader* reader, pduint32* poff, pduint32 *pobjpos)
{
	pduint32 off = *poff;
	unsigned long num, gen;
	if (token_ulong(reader, &off, &num) && token_ulong(reader, &off, &gen) && token_eat(reader, &off, "R")) {
		// indirect object!
        if (gen != 0) {
            compliance(reader, READ_GEN_ZERO, off);
        }
		// and we already parsed it.
		if (xref_lookup(reader, num, gen, pobjpos)) {
			*poff = off;
			return TRUE;
		}
		// invalid PDF - referenced object is not in cross-reference table
        compliance(reader, READ_NO_SUCH_XREF, *poff);
    }
	// indirect reference not found
	return FALSE;
}

// parse a direct OR indirect numeric object
// if successful place it's value in *pdvalue, update *poff and return TRUE.
// Otherwise set *pdvalue to 0, don't touch *poff and return FALSE.
static int parse_number_value(t_pdfrasreader* reader, pduint32 *poff, double* pdvalue)
{
	pduint32 off;
	// if indirect reference, skip over it
	if (parse_indirect_reference(reader, poff, &off)) {
		// and return the referenced numeric value (if any)
		return token_number(reader, &off, pdvalue);
	}
	else {
		// If it's not indirect, parse a numeric value in-line
		return token_number(reader, poff, pdvalue);
	}
}

// parse a direct OR indirect numeric value and round it to a long.
// if successful place it's value in *pvalue, update *poff and return TRUE.
// Otherwise set *pvalue to 0, don't touch *poff and return FALSE.
static int parse_long_value(t_pdfrasreader* reader, pduint32 *poff, long* pvalue)
{
	double dvalue;
	if (!parse_number_value(reader, poff, &dvalue)) {
		return FALSE;
	}
	*pvalue = (long)(dvalue + 0.5);
	return TRUE;
}

// TRUE if successful, FALSE otherwise.
static int parse_dictionary(t_pdfrasreader* reader, pduint32 *poff)
{
	pduint32 off = *poff;
	if (!token_eat(reader, &off, "<<")) {
		// not a dictionary - or is mangled
        compliance(reader, READ_DICTIONARY, off);
        return FALSE;
	}
	while (!token_eat(reader, &off, ">>")) {
        // each entry consist of a key (a /name) followed by a value.
		if ('/' != peekch(reader, off)) {
			// invalid PDF: dictionary key is not a Name
            compliance(reader, READ_DICT_NAME_KEY, off);
			return FALSE;
		}
        if (token_eat(reader, &off, "/Type")) {
            // it's the /Type entry of this dictionary/stream
            if (token_match(reader, off, "/ObjStm")) {
                // invalid PDF/raster: stream cannot /Type /ObjStm
                compliance(reader, READ_DICT_OBJSTM, off);
                return FALSE;
            }
        } else if (!token_skip(reader, &off)) {         // skip key
			// only fails at EOF
            compliance(reader, READ_DICT_EOF, *poff);
			return FALSE;
		}
        // parse & skip value
        if (!object_skip(reader, &off)) {
			// invalid PDF - already logged error
			return FALSE;
		}
	}
	*poff = off;
	return TRUE;
}

// Parse a dictionary or stream.
// If successful, return TRUE and advance *poff over the object to the next token.
// Otherwise return FALSE and leave *poff unchanged.
// If a stream is found, set *pstream to the position of the stream data, and *plen to its length in bytes.
// If a dictionary (not a stream) is found, *pstream and *plen are set to 0.
// Note however that values are only returned through pstream or plen if those are non-NULL.
static int parse_dictionary_or_stream(t_pdfrasreader* reader, pduint32 *poff, pduint32 *pstream, long* plen)
{
	pduint32 off = *poff;
    if (!parse_dictionary(reader, &off)) {
        // error already reported
		return FALSE;
	}
	if (peekch(reader, off + 0) != 's' ||
		peekch(reader, off + 1) != 't' ||
		peekch(reader, off + 2) != 'r' ||
		peekch(reader, off + 3) != 'e' ||
		peekch(reader, off + 4) != 'a' ||
		peekch(reader, off + 5) != 'm' ||
		!isspace(peekch(reader, off + 6))) {
		// Valid dictionary, but not a stream.
        // report stream pos & length as 0
        // (if caller wants them)
        if (pstream) *pstream = 0;
        if (plen) *plen = 0;
        // Update *poff to after dictionary
		*poff = off;
		return TRUE;
	}
	off += 6;
	// must be followed by exactly CRLF or LF
	char ch = peekch(reader, off);
	if (ch == 0x0D) {
		// CR must be followed by LF
		if (nextch(reader, &off) != 0x0A) {
            compliance(reader, READ_STREAM_CRLF, off);
			return FALSE;
		}
	} else if (ch != 0x0A) {
		// Alternative to CRLF is just LF
        compliance(reader, READ_STREAM_LINEBREAK, off);
		return FALSE;
	}
	// we're positioned at the LF, step over it.
	off++;
	pduint32 lenpos;
    // *poff is still start of dictionary
	if (!dictionary_lookup(reader, *poff, "/Length", &lenpos)) {
		// invalid stream: no /Length key in stream dictionary
        compliance(reader, READ_STREAM_LENGTH, *poff);
		return FALSE;
	}
	long length;
	if (!parse_long_value(reader, &lenpos, &length) || length < 0) {
        // length isn't a (non-negative) integer
        compliance(reader, READ_STREAM_LENGTH_INT, lenpos);
		return FALSE;
	}
	// step over stream data
    pduint32 endstream = off + length;
	// Parse 'endstream' keyword.
	if (!token_eat(reader, &endstream, "endstream")) {
		// invalid stream: 'endstream' not found where expected.
        // Report error at start of dictionary, it could be wrong /Length,
        // or keywords could be slightly misplaced, or who knows.
        compliance(reader, READ_STREAM_ENDSTREAM, *poff);
		return FALSE;
	}
    // return position and length of stream data:
    if (pstream) *pstream = off;
    if (plen) *plen = length;
    // update offset to just beyond "endstream" keyword:
	*poff = endstream;
	return TRUE;
}

// Parse a stream.
// If successful, return TRUE and advance *poff over the stream to the next token.
// Set *pstream to the position of the stream data, and *plen to its (raw) length in bytes.
// (Except if either pstream or plen is NULL they are ignored.)
// Otherwise, report a 'missing stream' compliance error and return FALSE, leaving *poff unchanged.
static int parse_stream(t_pdfrasreader* reader, pduint32 *poff, pduint32 *pstream, long* plen)
{
    pduint32 off = *poff;
    pduint32 datapos = 0;
    long datalen = 0;
    if (pstream) *pstream = 0;
    if (plen) *plen = 0;
    if (!parse_dictionary_or_stream(reader, &off, &datapos, &datalen)) {
        // compliance error already reported
        return FALSE;
    }
    if (datapos == 0) {
        // found a valid dictionary, but not a stream
        compliance(reader, READ_STREAM, *poff);
        return FALSE;
    }
    if (pstream) *pstream = datapos;
    if (plen) *plen = datalen;
    *poff = off;
    return TRUE;
}

static int array_lookup(t_pdfrasreader* reader, pduint32 off, const char* key)
{
	pduint32 *poff = &off;
	skip_whitespace(reader, poff);
	if (peekch(reader, *poff) != '[') {
		// not a valid array
		return FALSE;
	}
	// step over the opening '['
    nextch(reader, poff);
	while (!token_eat(reader, poff, "]")) {
		// does the key element match the key we're looking for?
		if (token_eat(reader, poff, key)) {
			return TRUE;
		}
		else if (!token_skip(reader, poff)) {
			// only fails at EOF
			return FALSE;
		}
	}
	return FALSE;
}

static int parse_array(t_pdfrasreader* reader, pduint32 *poff)
{
	skip_whitespace(reader, poff);
	if (peekch(reader, *poff) != '[') {
		// not a valid array
		return FALSE;
	}
	// step over the opening '['
    nextch(reader, poff);
	while (!token_eat(reader, poff, "]")) {
		if (!object_skip(reader, poff)) {
			// invalid array - unparseable element
            // error already reported
			return FALSE;
		}
	}
	return TRUE;
}

static int parse_colorpoint(t_pdfrasreader* reader, pduint32 *poff, double point[3], int err)
{
    skip_whitespace(reader, poff);
    if (peekch(reader, *poff) != '[') {
        // not a valid array
        compliance(reader, err, *poff);
        return FALSE;
    }
    // step over the opening '['
    nextch(reader, poff);
    int nvalues = 0;
    while (!token_eat(reader, poff, "]")) {
        if (nvalues == 3 || !token_number(reader, poff, &point[nvalues])) {
            // not a number
            compliance(reader, err, *poff);
            return FALSE;
        }
        nvalues++;
    }
    if (nvalues != 3) {
        compliance(reader, err, *poff);
        return FALSE;
    }
    return TRUE;
}

// Parse a /CalRGB /Matrix value (array of 9 numbers)
// If successful, update *poff and return TRUE.
// Otherwise report a compliance error and return FALSE with *poff unmoved.
static int parse_calrgb_matrix(t_pdfrasreader* reader, pduint32 *poff, double matrix[9])
{
    skip_whitespace(reader, poff);
    if (peekch(reader, *poff) != '[') {
        compliance(reader, READ_MATRIX, *poff);
        return FALSE;                   // not a valid array
    }
    // step over the opening '['
    nextch(reader, poff);
    int nvalues = 0;
    while (!token_eat(reader, poff, "]")) {
        if (nvalues == 9) {
            compliance(reader, READ_MATRIX_TOO_LONG, *poff);
            return FALSE;               // array is too long
        }
        if (!token_number(reader, poff, &matrix[nvalues])) {
            compliance(reader, READ_MATRIX_ELEMENT, *poff);
            return FALSE;               // element is not a number
        }
        nvalues++;
    }
    if (nvalues != 9) {
        // matrix is too short
        compliance(reader, READ_MATRIX_TOO_SHORT, *poff);
        return FALSE;                   // array is too short
    }
    return TRUE;
}

// parse & validate a /CalGray dictionary starting at *poff.
// If successful, update *poff to point to the token after the dictionary.
// Otherwise, report a compliance error and return FALSE with *poff unmoved.
static int parse_calgray_dictionary(t_pdfrasreader* reader, t_colorspace* pcs, pduint32 *poff)
{
    // TODO: check for missing or duplicate keys!
    pduint32 off = *poff;
    if (!token_eat(reader, &off, "<<")) {
        // not a dictionary - or is mangled
        compliance(reader, READ_CALGRAY_DICT, off);
        return FALSE;
    }
    while (!token_eat(reader, &off, ">>")) {
        // each entry consist of a key (a /name) followed by a value.
        if ('/' != peekch(reader, off)) {
            // invalid PDF: dictionary key is not a Name
            compliance(reader, READ_DICT_NAME_KEY, off);
            return FALSE;
        }
        if (token_eat(reader, &off, "/Gamma")) {
            // parse & check gamma value
            double dGamma;
            pduint32 valpos = off;
            if (!token_number(reader, &off, &dGamma)) {
                compliance(reader, READ_GAMMA_NUMBER, valpos);
                return FALSE;
            }
            if (fabs(dGamma - 2.2) > 0.0000001) {
                // interestingly non-fatal compliance error:
                // /Gamma must be 2.2 in bitonal and grayscale strips
                compliance(reader, READ_GAMMA_22, valpos);
            }
            pcs->gamma = 2.2;
        }
        else if (token_eat(reader, &off, "/WhitePoint")) {
            // parse & check [ r g b ]
            if (!parse_colorpoint(reader, &off, pcs->whitePoint, READ_WHITEPOINT)) {
                return FALSE;
            }
        }
        else if (token_eat(reader, &off, "/BlackPoint")) {
            // parse & check [ r g b ]
            if (!parse_colorpoint(reader, &off, pcs->blackPoint, READ_BLACKPOINT)) {
                return FALSE;
            }
        }
        else {
            compliance(reader, READ_CALGRAY_DICT, off);
            return FALSE;
        }
    }
    *poff = off;
    return TRUE;
}

// parse & validate a /CalRGB dictionary starting at *poff.
// If (and only if) successful, update *poff to point to the token after the dictionary.
static int parse_calrgb_dictionary(t_pdfrasreader* reader, t_colorspace* pcs, pduint32 *poff)
{
    // TODO: check for missing or duplicate keys!
    pduint32 off = *poff;
    if (!token_eat(reader, &off, "<<")) {
        // not a dictionary - or is mangled
        compliance(reader, READ_CALRGB_DICT, off);
        return FALSE;
    }
    while (!token_eat(reader, &off, ">>")) {
        // each entry consist of a key (a /name) followed by a value.
        if ('/' != peekch(reader, off)) {
            // invalid PDF: dictionary key is not a Name
            compliance(reader, READ_DICT_NAME_KEY, off);
            return FALSE;
        }
        if (token_eat(reader, &off, "/Gamma")) {
            // Optional for us (as in PDF)
            double dGamma;
            pduint32 valpos = off;
            if (!token_number(reader, &off, &dGamma)) {
                compliance(reader, READ_GAMMA_NUMBER, valpos);
                return FALSE;
            }
            pcs->gamma = dGamma;
        }
        else if (token_eat(reader, &off, "/WhitePoint")) {
            // Required. Value [ X Y Z ]  X and Z must be positive. Y must be 1.
            if (!parse_colorpoint(reader, &off, pcs->whitePoint, READ_WHITEPOINT)) {
                return FALSE;
            }
        }
        else if (token_eat(reader, &off, "/BlackPoint")) {
            // Optional. Value [ X Y Z ]  X and Z must be positive. Y must be 1.
            if (!parse_colorpoint(reader, &off, pcs->blackPoint, READ_BLACKPOINT)) {
                return FALSE;
            }
        }
        else if (token_eat(reader, &off, "/Matrix")) {
            // Optional.  Array of 9 numbers
            if (!parse_calrgb_matrix(reader, &off, pcs->matrix)) {
                return FALSE;
            }
        }
        else {
            compliance(reader, READ_CALRGB_DICT, off);
            return FALSE;
        }
    }
    *poff = off;
    return TRUE;
}

// Parse an ICC Profile stream.
// If successful, set *ppiccProfile to point to the loaded/decompressed profile,
// advance *poff past the stream and return TRUE.
// Otherwise, report an appropriate compliance error
// and return FALSE leaving *poff unmoved.
static int parse_icc_profile(t_pdfrasreader* reader, pduint32 *poff, ICCProfile** ppiccProfile)
{
    pduint32 off = *poff;
    *ppiccProfile = NULL;
    pduint32 datapos;
    long datalen;
    if (!parse_stream(reader, &off, &datapos, &datalen)) {
        // compliance error already reported
        return FALSE;
    }
    *ppiccProfile = (ICCProfile*)malloc((size_t)datalen);
    if (!*ppiccProfile) {
        memory_error(reader, __LINE__);
        return FALSE;
    }
    // TODO: handle decompress/decrypt of Profile!
    if (reader->fread(reader->source, datapos, datalen, (char*)*ppiccProfile) != datalen) {
        io_error(reader, READ_ICCPROFILE_READ, __LINE__);
        free(*ppiccProfile); *ppiccProfile = NULL;
        return FALSE;
    }
    // TODO: validate that the data we read is actually an ICC Profile!
    *poff = off;
    return TRUE;
}

static int parse_color_space(t_pdfrasreader* reader, pduint32 *poff, t_colorspace* pcs)
{
	// TODO: If stripno == 0, colorspace info should be undefined, ...
	// If stripno != 0, colorspace info must match what's already set in info
	if (token_eat(reader, poff, "/DeviceGray")) {
        pcs->style = CS_DEVICEGRAY;
	}
	else if (token_eat(reader, poff, "/DeviceRGB")) {
        pcs->style = CS_DEVICERGB;
	}
	else if (token_eat(reader, poff, "[")) {
		if (token_eat(reader, poff, "/CalGray")) {
            pcs->style = CS_CALGRAY;
            pduint32 dict = *poff;
            if (parse_indirect_reference(reader, poff, &dict)) {
                if (!parse_calgray_dictionary(reader, pcs, &dict)) {
                    return FALSE;
                }
            }
            else if (!parse_calgray_dictionary(reader, pcs, poff)) {
                return FALSE;
            }
        }
        else if (token_eat(reader, poff, "/CalRGB")) {
            pcs->style = CS_CALRGB;
            pduint32 dict = *poff;
            if (parse_indirect_reference(reader, poff, &dict)) {
                if (!parse_calrgb_dictionary(reader, pcs, &dict)) {
                    return FALSE;
                }
            }
            else if (!parse_calrgb_dictionary(reader, pcs, poff)) {
                return FALSE;
            }
        }
        else if (token_eat(reader, poff, "/ICCBased")) {
            pcs->style = CS_ICCBASED;
            pduint32 dict = *poff;
            // could be an indirect reference
            if (parse_indirect_reference(reader, poff, &dict)) {
                if (!parse_icc_profile(reader, &dict, &pcs->piccProfile)) {
                    return FALSE;
                }
            }
            else if (!parse_icc_profile(reader, poff, &pcs->piccProfile)) {
                return FALSE;
            }
        }
		else {
			// missing or unrecognized colorspace type
            // TODO: more specific error code?
            compliance(reader, READ_VALID_COLORSPACE, *poff);
			return FALSE;
		}
        if (!token_eat(reader, poff, "]")) {
            // invalid PDF, expected ']' at end of colorspace array
            compliance(reader, READ_COLORSPACE_ARRAY, *poff);
            return FALSE;
        }
	}
	else {
		// PDF/raster: ColorSpace must be /DeviceGray, /DeviceRGB,
        // CalGray, CalRGB, or ICCBased.
        // TODO: more specific error code?
        compliance(reader, READ_VALID_COLORSPACE, *poff);
        return FALSE;
	}
	return TRUE;
}

static int parse_media_box(t_pdfrasreader* reader, pduint32 *poff, double mediabox[4])
{
	skip_whitespace(reader, poff);
	pduint32 off = *poff;
	if (peekch(reader, off) != '[') {
        // invalid PDF: bad MediaBox
        compliance(reader, READ_MEDIABOX_ARRAY, off);
        return FALSE;
	}
	// skip over the opening '['
	if (nextch(reader, &off) < 0) {
        // invalid PDF: bad MediaBox
        compliance(reader, READ_MEDIABOX_ARRAY, off);
        return FALSE;
	}
	int i;
	for (i = 0; i < 4; i++) {
		if (!parse_number_value(reader, &off, &mediabox[i])) {
			// invalid PDF: bad MediaBox element
            compliance(reader, READ_MEDIABOX_ELEMENTS, off);
            return FALSE;
		}
	}
	if (!token_eat(reader, &off, "]")) {
		// invalid PDF: MediaBox array has more than 4 elements
        compliance(reader, READ_MEDIABOX_ARRAY, off);
        return FALSE;
	}
    if (mediabox[0] != 0 || mediabox[1] != 0) {
        compliance(reader, READ_MEDIABOX_ELEMENTS, off);
        return FALSE;
    }
    if (mediabox[3] < 0 || mediabox[4] < 0) {
        compliance(reader, READ_MEDIABOX_ELEMENTS, off);
        return FALSE;
    }
    // normalize rectangle so lower-left corner is actually lower and left etc.
	if (mediabox[0] > mediabox[2]) {
		double t = mediabox[0]; mediabox[0] = mediabox[2]; mediabox[2] = t;
	}
	if (mediabox[1] > mediabox[3]) {
		double t = mediabox[1]; mediabox[1] = mediabox[3]; mediabox[3] = t;
	}
	*poff = off;
	return TRUE;
}

// parse and ignore one PDF 'object' - an atomic object
// or dictionary/stream/array - advance *poff and return TRUE.
// If it fails, logs a compliance error and returns FALSE.
static int object_skip(t_pdfrasreader* reader, pduint32 *poff)
{
	pduint32 off = *poff;
	int ch = peekch(reader, off);
	if (-1 == ch) {
		// at EOF
        compliance(reader, READ_OBJECT_EOF, *poff);
		return FALSE;
	}
	if (isalpha(ch) ||
		'/' == ch ||
		'-' == ch || '+' == ch) {
		// keyword or Name or signed number
		return token_skip(reader, poff);
	}
	if ('(' == ch) {
		// string object
		return token_literal_string(reader, poff);
	}
	if ('<' == ch) {
		if ('<' == nextch(reader, &off)) {
			return parse_dictionary_or_stream(reader, poff, NULL, NULL);
		}
		else {
			return token_hex_string(reader, poff);
		}
	}
	if ('[' == ch) {
		return parse_array(reader, poff);
	}
	if (isdigit(ch)) {
		unsigned long num, gen;
		if (token_ulong(reader, &off, &num) && token_ulong(reader, &off, &gen) && token_eat(reader, &off, "R")) {
			// indirect object!
			// and we already parsed it.
			*poff = off;
			return TRUE;
		}
		else {
			// jus' a plain ol' number, skip over it.
			return token_skip(reader, poff);
		}
	}
	// Don't know what the h-e-double-hockey-sticks it is.
    compliance(reader, READ_OBJECT, off);
	return FALSE;
}

// Given a dictionary inline at pos, look up the specified key and return the file position of its value element.
static int dictionary_lookup(t_pdfrasreader* reader, pduint32 off, const char* key, pduint32 *pvalpos)
{
	*pvalpos = 0;
	if (!token_eat(reader, &off, "<<")) {
		// invalid dictionary
		return FALSE;
	}
	while (!token_eat(reader, &off, ">>")) {
		// does the key element match the key we're looking for?
		if (token_eat(reader, &off, key)) {
			// yes, bingo.
			// check for indirect reference
			unsigned long num, gen;
			pduint32 p = off;
			if (token_ulong(reader, &p, &num) && token_ulong(reader, &p, &gen) && token_eat(reader, &p, "R")) {
				// indirect object!
				// and we already parsed it.
				if (!xref_lookup(reader, num, gen, &off)) {
					// invalid PDF - referenced object is not in cross-reference table
                    compliance(reader, READ_NO_SUCH_XREF, off);
					return FALSE;
				}
			}
			*pvalpos = off;
			return TRUE;
		} // otherwise skip over and ignore key
		else if (!token_skip(reader, &off)) {
			// only fails at EOF
			return FALSE;
		}
		// skip over value element
		if (!object_skip(reader, &off)) {
			// invalid dictionary (invalid value)
            // error already logged.
			return FALSE;
		}
	}
	// key not found in dictionary
	return FALSE;
}

// Parse the trailer dictionary.
// TRUE if successful, FALSE otherwise
static int read_trailer_dict(t_pdfrasreader* reader, pduint32 *poff)
{
	if (!token_eat(reader, poff, "trailer")) {
		// PDF/raster restriction: trailer dictionary does not follow xref table.
        compliance(reader, READ_TRAILER, *poff);
		return FALSE;
	}
    if (!parse_dictionary(reader, poff)) {
        // error already reported
        return FALSE;
    }
    return TRUE;
}

// check an xref table for anything invalid and report the problem.
// 'off' is the offset in the file of the first entry.
// return TRUE if valid, FALSE otherwise.
// In FALSE case, logs pertinent error.
static int validate_xref_table(t_pdfrasreader* reader, pduint32 off, t_xref_entry* xrefs, unsigned long numxrefs)
{
	unsigned long e;
	// Sweep the xref table, validate entries.
	for (e = 0; e < numxrefs; e++) {
		char *offend, *genend;
		pduint32 offset = strtoul(xrefs[e].offset, &offend, 10);
		unsigned long gen = strtoul(xrefs[e].gen, &genend, 10);
		// Note, we don't check for leading 0's on offset or gen.
		if (offend != xrefs[e].gen ||
			genend != xrefs[e].status ||
			(xrefs[e].eol[0] != ' ' && xrefs[e].eol[0] != 0x0D) ||
			(xrefs[e].eol[0] != 0x0D && xrefs[e].eol[1] != 0x0A) ||
			xrefs[e].gen[0] != ' ' ||
			xrefs[e].status[0] != ' ' ||
			(xrefs[e].status[1] != 'n' && xrefs[e].status[1] != 'f')) {
			// invalid xref table entry
            compliance(reader, READ_XREF_ENTRY, off + e * 20);
            return FALSE;
		}
		if (e == 0) {
			if (xrefs[e].status[1] != 'f' || gen != 65535) {
				// object 0 must be free with gen=65535
                compliance(reader, READ_XREF_ENTRY_ZERO, off + e * 20);
                return FALSE;
			}
		}
		else {
			if (gen != 0 && xrefs[e].status[1] != 'f') {
				// PDF/raster restriction: in-use object generation must be 0
				// (free entries can have gen != 0)
                compliance(reader, READ_XREF_GEN0, off + e * 20);
                return FALSE;
			}
		}
	}
	return TRUE;
}

// Parse and load the xref table from given offset within the file.
// Returns TRUE if successful, FALSE for any error.
// All FALSE cases log a pertinent error.
static int read_xref_table(t_pdfrasreader* reader, pduint32* poff)
{
	pduint32 off = *poff;
	unsigned long firstnum, numxrefs;
	t_xref_entry* xrefs = NULL;
	if (!token_eat(reader, &off, "xref")) {
		// invalid xref table
        compliance(reader, READ_XREF, off);
		return FALSE;
	}
	// NB: token_eat skips over the whitespace (eol) after "xref"
	if (!token_ulong(reader, &off, &firstnum) || !token_ulong(reader, &off, &numxrefs)) {
		// invalid xref table
        compliance(reader, READ_XREF_HEADER, off);
		return FALSE;
	}
	// And token_ulong skips over trailing whitespace (eol) after 2nd header line
	if (firstnum != 0) {
		// invalid PDF/raster: xref table does not start with object 0.
        compliance(reader, READ_XREF_OBJECT_ZERO, *poff);
		return FALSE;
	}
	if (numxrefs < 1 || numxrefs > 8388607) {
		// looks invalid, at least per PDF 32000-1:2008
        compliance(reader, READ_XREF_NUMREFS, *poff);
		return FALSE;
	}
	size_t xref_size = 20 * numxrefs;
	xrefs = (t_xref_entry*)malloc(xref_size);
	if (!xrefs) {
		// allocation failed
        memory_error(reader, __LINE__);
		return FALSE;
	}
	// Read all the xref entries straight into memory structure
	// (PDF specifically designed for this)
	if (reader->fread(reader->source, off, xref_size, (char*)xrefs) != xref_size) {
		// invalid PDF, the xref table is cut off
		free(xrefs);
        io_error(reader, READ_XREF_TABLE, __LINE__);
        compliance(reader, READ_XREF_TABLE, off);
		return FALSE;
	}
	if (!validate_xref_table(reader, off, xrefs, numxrefs)) {
        // already logged the specific issue
		free(xrefs);
		return FALSE;
	}
	off += xref_size;
	// OK, attach xref table to reader object:
	reader->xrefs = xrefs;
	reader->numxrefs = numxrefs;
	// update caller's file position
	*poff = off;
	return TRUE;
}

// Find all the pages in the page tree rooted at off, ppn points to next page index value.
// Store each page's file position (indexed by page#) in the page table,
// increment *ppn by the number of pages found.
static int recursive_page_finder(t_pdfrasreader* reader, pduint32 off, pduint32* table, int *ppn)
{
	pduint32 p;
	assert(reader);
	assert(table);
	assert(ppn);
	assert(*ppn >= 0);

	// look for the Type key
	if (!dictionary_lookup(reader, off, "/Type", &p)) {
		// invalid PDF: page tree node is not a dictionary or lacks a /Type entry
        compliance(reader, READ_PAGE_TYPE, off);
		return FALSE;
	}
	// is it a page (leaf) node?
	if (token_eat(reader, &p, "/Page")) {
		// Found a page object!
		if (*ppn >= reader->page_count) {
			// invalid PDF: more page objects than expected in page tree
            compliance(reader, READ_PAGES_EXTRA, p);
			return FALSE;
		}
		// record page object's position, in the page table:
		table[*ppn] = off;
		*ppn += 1;					// increment the page counter
		return TRUE;
	}
	// is the Type value right for a page tree node?
	if (!token_eat(reader, &p, "/Pages")) {
		// invalid PDF: page tree node /Type is not /Pages
        compliance(reader, READ_PAGE_TYPE2, off);
		return FALSE;
	}
	pduint32 kids;
	if (!dictionary_lookup(reader, off, "/Kids", &kids)) {
		// invalid PDF: page tree node lacks a /Kids entry
        compliance(reader, READ_PAGE_KIDS, off);
		return FALSE;
	}
	// Enumerate the kids adding their counts to *pcount
	if (!token_eat(reader, &kids, "[")) {
        compliance(reader, READ_PAGE_KIDS_ARRAY, kids);
		return FALSE;
	}
	pduint32 kid;
	while (parse_indirect_reference(reader, &kids, &kid)) {
		if (!recursive_page_finder(reader, kid, table, ppn)) {
			// invalid PDF -
            // (error already reported inside recursive_page_finder)
			return FALSE;
		}
	}
	if (!token_eat(reader, &kids, "]")) {
		// invalid PDF, expected ']' at end of 'kids' array
        compliance(reader, READ_PAGE_KIDS_END, kids);
		return FALSE;
	}
	return TRUE;
} // recursive_page_finder

// Build the page table by walking the page tree from root.
// If successful, return TRUE: page table contains offset of each page object.
// Otherwise return FALSE;
static int build_page_table(t_pdfrasreader* reader, pduint32 root)
{
	assert(reader);
	assert(NULL==reader->page_table);
	assert(root > 0);
	assert(reader->page_count >= 0);

	// allocate a page table
	pduint32* pages;
	size_t ptsize = reader->page_count * sizeof *pages;
	pages = (pduint32*)malloc(ptsize);
	if (!pages) {
		// internal failure, mmemory allocation
        memory_error(reader, __LINE__);
		return FALSE;
	}
	memset(pages, 0, ptsize);

	int pageno = 0;
	if (!recursive_page_finder(reader, root, pages, &pageno)) {
		// error (already logged)
		free(pages);				// free the page table
		return FALSE;
	}
	if (pageno != reader->page_count) {
		// invalid PDF: /Count in root page node is not correct
		free(pages);				// free the page table
        compliance(reader, READ_PAGE_COUNTS, root);
		return FALSE;
	}
	// keep the filled-in page table
	reader->page_table = pages;
	return TRUE;
}

static int validate_catalog(t_pdfrasreader* reader, pduint32 catpos)
{
    pduint32 p;
    if (!dictionary_lookup(reader, catpos, "/Type", &p)) {
        // invalid PDF: catalog must have /Type /Catalog
        compliance(reader, READ_CAT_TYPE, catpos);
        return FALSE;
    }
    if (!token_eat(reader, &p, "/Catalog")) {
        // invalid PDF: catalog must have /Type /Catalog
        compliance(reader, READ_CAT_TYPE, p);
        return FALSE;
    }
    return TRUE;
}

// Return TRUE if all OK, FALSE if some problem.
static int parse_trailer(t_pdfrasreader* reader)
{
	char tail[TAILSIZE+1];
	size_t tailsize = pdfras_read_tail(reader, tail, sizeof tail - 1);
    pduint32 off = reader->filesize - tailsize;
    const char* eof = memrstr(tail, tail+tailsize, "%%EOF");
    if (!eof) {
        // invalid PDF - %%EOF not found in tail of file.
        compliance(reader, READ_FILE_EOF_MARKER, off);
        return FALSE;
    }
    // we need to find the startxref anyway, let's check now,
    // it's a good check for a valid PDF.
    const char* startxref = memrstr(tail, tail+tailsize, "startxref");
    if (!startxref) {
        // invalid PDF - startxref not found in tail of file.
        compliance(reader, READ_FILE_STARTXREF, off);
        return FALSE;
    }
    // find the PDF/raster 'tag'
    const char* tag = memrstr(tail, tail+tailsize, "%PDF-raster-");
    if (!tag || tag == tail) {
        // PDF/raster marker not found in tail of file
        compliance(reader, READ_FILE_PDFRASTER_TAG, off);
        return FALSE;
    }
    assert(tag > tail);
    if (tag[-1] != 0x0D && tag[-1] != 0x0A) {
        compliance(reader, READ_FILE_TAG_SOL, off);
        return FALSE;
    }
    // found the %PDF-raster tag
    off += tag - tail;
    if (!pdfras_parse_pdfr_tag(tag, &reader->major, &reader->minor) ||
        reader->major < 1 ||
        reader->minor < 0) {
        compliance(reader, READ_FILE_BAD_TAG, off);
		return FALSE;
	}
    // point specifically to the x.y part of the tag
    off += 12;
    if (reader->major > RASREAD_MAX_MAJOR) {
        // beyond us, we can't handle it.
        compliance(reader, READ_FILE_TOO_MAJOR, off);
        return FALSE;
    }
    if (reader->major == RASREAD_MAX_MAJOR && reader->minor > RASREAD_MAX_MINOR) {
        // minor version is above what we understand - supposedly that
        // means some nonessential new features may not work.
        warning(reader, READ_FILE_TOO_MINOR, off);
        return FALSE;
    }
    // go back to the whole tail thing for a sec...
    off = reader->filesize - tailsize;
	// Calculate the file position of the "startxref" keyword
	// and make a note of it for a bit later.
	pduint32 startxref_off = off += (startxref - tail);
	unsigned long xref_off;
	if (!token_eat(reader, &off, "startxref") || !token_ulong(reader, &off, &xref_off)) {
		// startxref not followed by unsigned int
        compliance(reader, READ_FILE_BAD_STARTXREF, off);
		return FALSE;
	}
	if (xref_off < 16 || xref_off >= reader->filesize) {
		// invalid PDF - offset to xref table is bogus
        compliance(reader, READ_FILE_BAD_STARTXREF, off);
        return FALSE;
	}
	// go there and read the xref table
	off = xref_off;
	if (!read_xref_table(reader, &off)) {
		// xref table not found or not valid
		return FALSE;
	}
	if (!token_eat(reader, &off, "trailer")) {
		// PDF/raster restriction: trailer dictionary does not follow xref table.
        compliance(reader, READ_TRAILER, off);
		return FALSE;
	}
	// find the address of the Catalog
	pduint32 catpos;
	if (!dictionary_lookup(reader, off, "/Root", &catpos)) {
		// invalid PDF: trailer dictionary must contain /Root entry
        compliance(reader, READ_ROOT, off);
		return FALSE;
	}
	// check the Catalog
    if (!validate_catalog(reader, catpos)) {
        // any errors already logged.
        return FALSE;
    }
	// Find the root node of the page tree
	pduint32 pages;
	if (!dictionary_lookup(reader, catpos, "/Pages", &pages)) {
		// invalid PDF: catalog must have a /Pages entry
        compliance(reader, READ_CAT_PAGES, catpos);
        return FALSE;
	}
	// pages points to the root Page Tree Node
	if (!dictionary_lookup(reader, pages, "/Count", &off) ||
        !parse_long_value(reader, &off, &reader->page_count) ||
        reader->page_count < 0) {
		// invalid PDF: root page node does not have valid /Count value
        compliance(reader, READ_PAGES_COUNT, pages);
		return FALSE;
	}
	// walk the page tree locating all the pages
	if (!build_page_table(reader, pages)) {
		// oops - something went wrong
        // any errors were already logged.
		return FALSE;
	}

	return TRUE;
}

static pduint32 get_page_pos(t_pdfrasreader* reader, int n)
{
	assert(reader);
	if (n < 0 || n >= pdfrasread_page_count(reader)) {
		// invalid page number
		return 0;
	}
	assert(reader->page_table);
	return reader->page_table[n];
}

// round a dpi value to an exact integer, if it's already 'really close'
static double tweak_dpi(double dpi)
{
	// I don't care what happens if dpi is negative. Don't do that!
	if (dpi+0.5 < LONG_MAX) {
		long ndpi = (long)(0.5 + dpi);
		double err = fabs(dpi - ndpi);
		if (err * 100000 < dpi) {
			dpi = ndpi;
		}
	}
	return dpi;
}

// Look up strip s in page p and return the offset of that strip-stream
static int find_strip(t_pdfrasreader* reader, int p, int s, pduint32* pstrip)
{
    // look up the file position of the nth page object:
    pduint32 page = get_page_pos(reader, p);
    if (!page) {
        api_error(reader, READ_API_NO_SUCH_PAGE, __LINE__);
        return FALSE;
    }
    pduint32 resdict;
    if (!dictionary_lookup(reader, page, "/Resources", &resdict)) {
        // bad page object, no /Resources entry
        compliance(reader, READ_RESOURCES, page);
        return FALSE;
    }
    // In the Resources dictionary find the XObject dictionary
    pduint32 xobjects;
    if (!dictionary_lookup(reader, resdict, "/XObject", &xobjects)) {
        // bad resource dictionary, no /XObject entry
        compliance(reader, READ_XOBJECT, resdict);
        return FALSE;
    }

    char stripname[32];
    sprintf(stripname, "/strip%d", s);
    if (!dictionary_lookup(reader, xobjects, stripname, pstrip)) {
        // strip not found in XObject dictionary
        api_error(reader, READ_API_NO_SUCH_STRIP, __LINE__);
        return FALSE;
    }
    return TRUE;
} // find_strip

// Given a colorspace and a bit depth (per component), infer and return the "pixel format".
// Returns RASREAD_FORMAT_NULL on error - up to caller to report the problem.
static RasterReaderPixelFormat infer_pixel_format(t_colorspace cs)
{
    RasterReaderPixelFormat format = RASREAD_FORMAT_NULL;
    //CS_CALGRAY, CS_DEVICEGRAY, CS_CALRGB, CS_DEVICERGB, CS_ICCBASED
    int depth = cs.bitsPerComponent;
    switch (cs.style) {
    case CS_CALGRAY:
    case CS_DEVICEGRAY:
        if (depth == 1) {
            format = RASREAD_BITONAL;
        }
        else if (depth == 8) {
            format = RASREAD_GRAY8;
        }
        else if (depth == 16) {
            format = RASREAD_GRAY16;
        }
        break;
    case CS_CALRGB:
    case CS_DEVICERGB:
    case CS_ICCBASED:
        if (depth == 8) {
            format = RASREAD_RGB24;
        }
        else if (depth == 16) {
            format = RASREAD_RGB48;
        }
        break;
    } // switch
    return format;
}

// return all the info about strip s on page p of an open file
static int get_strip_info(t_pdfrasreader* reader, int p, int s, t_pdfstripinfo* pinfo)
{
	// While this is not a public function, it is called by a bunch of
	// shallow public functions - that's why it reports API errors.
	if (!VALID(reader)) {
		api_error(NULL, READ_API_BAD_READER, __LINE__);
		return FALSE;
	}
	if (!pinfo) {
		api_error(reader, READ_API_NULL_PARAM, __LINE__);
		return FALSE;
	}
	if (!reader->bOpen) {
		api_error(reader, READ_API_NOT_OPEN, __LINE__);
		return FALSE;
	}
	// clear info to all 0's
	memset(pinfo, 0, sizeof *pinfo);
	// find the strip
	if (!find_strip(reader, p, s, &pinfo->pos)) {
		// no such strip - already reported appropriate error
		return FALSE;
	}
	// Parse the strip stream and locate its data
	// Among other things, this finds and checks the /Length key
	pduint32 pos = pinfo->pos;
	if (!parse_stream(reader, &pos, &pinfo->data_pos, &pinfo->raw_size)) {
		// strip stream not found or invalid
		// compliance errors have already been reported
		return FALSE;
	}
	assert(pinfo->pos != 0);
	assert(pinfo->raw_size > 0);
	pduint32 val;
	// /Type entry is optional, but if present value must be /XObject   [ISO 32000 8.9.5]
	if (dictionary_lookup(reader, pinfo->pos, "/Type", &val) && !token_match(reader, val, "/XObject")) {
		compliance(reader, READ_STRIP_TYPE_XOBJECT, pinfo->pos);
		return FALSE;
	}
	// /Subtype is mandatory and must have value /Image
	if (!dictionary_lookup(reader, pinfo->pos, "/Subtype", &val) || !token_eat(reader, &val, "/Image")) {
		// strip isn't /Subtype /Image
		compliance(reader, READ_STRIP_SUBTYPE, pinfo->pos);
		return FALSE;
	}
	// /BitsPerComponent is required (for our kind of images) and must be 1,8 or 16
	if (!dictionary_lookup(reader, pinfo->pos, "/BitsPerComponent", &val) ||
		!token_ulong(reader, &val, &pinfo->cs.bitsPerComponent) ||
		(pinfo->cs.bitsPerComponent != 1 && pinfo->cs.bitsPerComponent != 8 && pinfo->cs.bitsPerComponent != 16)) {
		// strip doesn't have valid BitsPerComponent?
		compliance(reader, READ_STRIP_BITSPERCOMPONENT, pinfo->pos);
		return FALSE;
	}
	// /Width is mandatory
	if (!dictionary_lookup(reader, pinfo->pos, "/Width", &val) || !token_ulong(reader, &val, &pinfo->width)) {
		// strip doesn't have Width?
		compliance(reader, READ_STRIP_WIDTH, pinfo->pos);
		return FALSE;
	}
	// /Height is mandatory
	if (!dictionary_lookup(reader, pinfo->pos, "/Height", &val) || !token_ulong(reader, &val, &pinfo->height)) {
		// strip doesn't have /Height with non-negative integer value
		compliance(reader, READ_STRIP_HEIGHT, pinfo->pos);
		return FALSE;
	}
	if (!dictionary_lookup(reader, pinfo->pos, "/ColorSpace", &val)) {
		// PDF/raster: image object, each strip must have a named ColorSpace
		compliance(reader, READ_STRIP_COLORSPACE, pinfo->pos);
		return FALSE;
	}
	// That's all the mandatory entries!
	if (!parse_color_space(reader, &val, &pinfo->cs)) {
		// PDF/raster: invalid color space in strip
		compliance(reader, READ_VALID_COLORSPACE, val);
		return FALSE;
	}
	pinfo->format = infer_pixel_format(pinfo->cs);
	if (pinfo->format == RASREAD_FORMAT_NULL) {
		// oops.
		compliance(reader, READ_STRIP_CS_BPC, pinfo->pos);
		return FALSE;
	}
	// Check if image strip is JPEG or G4 compressed
	if (dictionary_lookup(reader, pinfo->pos, "/Filter", &val)) {
		if (array_lookup(reader, val, "/CCITTFaxDecode")) {
			pinfo->compression = RASREAD_CCITTG4;
			if (pinfo->cs.bitsPerComponent != 1) {
				compliance(reader, READ_STRIP_BITSPERCOMPONENT, pinfo->pos);
				return FALSE;
			}
		}
		else if (array_lookup(reader, val, "/DCTDecode")) {
			pinfo->compression = RASREAD_JPEG;
			if (pinfo->cs.bitsPerComponent != 8) {
				compliance(reader, READ_STRIP_BITSPERCOMPONENT, pinfo->pos);
				return FALSE;
			}
		}
	}
    return TRUE;
} // get_strip_info

// return all the info about page p of the open file.
static int get_page_info(t_pdfrasreader* reader, int p, t_pdfpageinfo* pinfo)
{
    // While this is not a public function, it is called by a bunch of trivial
    // public functions - that's why it reports API errors.
    if (!VALID(reader)) {
        api_error(NULL, READ_API_BAD_READER, __LINE__);
        return FALSE;
	}
    if (!pinfo) {
        api_error(reader, READ_API_NULL_PARAM, __LINE__);
        return FALSE;
    }
    if (!reader->bOpen) {
        api_error(reader, READ_API_NOT_OPEN, __LINE__);
        return FALSE;
    }
    // clear info to all 0's
	memset(pinfo, 0, sizeof *pinfo);
	// If we haven't 'opened' the file, do the initial stuff now
	if (!reader->xrefs && !parse_trailer(reader)) {
		return FALSE;
	}
	// look up the file position of the nth page object:
	pduint32 page = get_page_pos(reader, p);
	if (!page) {
		// TODO: internal error
		return FALSE;
	}
	pinfo->off = page;
	pduint32 val;
	if (!dictionary_lookup(reader, page, "/Type", &val) || !token_eat(reader, &val, "/Page")) {
		// bad page object, not marked /Type /Page
		compliance(reader, READ_PAGE_TYPE, page);
		return FALSE;
	}
	// a page may be rotated for rendering, by a non-negative
	// multiple of 90 degrees (clockwise).
	// note: if not present defaults to 0.
	if (dictionary_lookup(reader, page, "/Rotate", &val)) {
		unsigned long angle;
		if (!token_ulong(reader, &val, &angle) ||
			angle % 90 != 0) {
			compliance(reader, READ_PAGE_ROTATION, val);
			return FALSE;
		}
		pinfo->rotation = angle % 360;
	}
	// similarly for mediabox
	if (!dictionary_lookup(reader, page, "/MediaBox", &val)) {
		compliance(reader, READ_PAGE_MEDIABOX, page);
		return FALSE;
	}
    if (!parse_media_box(reader, &val, pinfo->MediaBox)) {
        return FALSE;
    }
    pduint32 resdict;
	if (!dictionary_lookup(reader, page, "/Resources", &resdict)) {
		// bad page object, no /Resources entry
		compliance(reader, READ_RESOURCES, page);
		return FALSE;
	}
	// In the Resources dictionary find the XObject dictionary
	pduint32 xobjects;
	if (!dictionary_lookup(reader, resdict, "/XObject", &xobjects)) {
		// bad resource dictionary, no /XObject entry
		compliance(reader, READ_XOBJECT, resdict);
		return FALSE;
	}
	// Traverse the XObject dictionary collecting strip info
    pduint32 off = xobjects;
	if (!token_eat(reader, &off, "<<")) {
		// invalid PDF: XObject dictionary doesn't start with '<<'
		compliance(reader, READ_XOBJECT_DICT, xobjects);
		return FALSE;
	}
    // scan the /XObject dictionary once, validating entries
    // as /strip<n> and counting total entries
	int nstrips;				// strip no
    for (nstrips = 0; !token_eat(reader, &off, ">>"); nstrips++) {
        pduint32 xobj_entry = off;
        if (peekch(reader, off) != '/' ||
            nextch(reader, &off) != 's' ||
            nextch(reader, &off) != 't' ||
            nextch(reader, &off) != 'r' ||
            nextch(reader, &off) != 'i' ||
            nextch(reader, &off) != 'p' ||
            !isdigit(nextch(reader, &off))
            ) {
            // illegal entry in xobjects dictionary - only /strip<n> allowed
            compliance(reader, READ_XOBJECT_ENTRY, xobj_entry);
            return FALSE;
        }
        unsigned long stripno;
        if (!token_ulong(reader, &off, &stripno)) {
            // PDF/raster: strips must be named /strip0, /strip1, /strip2, etc.
            compliance(reader, READ_XOBJECT_ENTRY, off);
            return FALSE;
        }
        // value of the strip<n> entry must be indirect ref
        pduint32 strip;
        if (!parse_indirect_reference(reader, &off, &strip)) {
            // invalid PDF: strip entry in XObject dict isn't an indirect reference
            compliance(reader, READ_STRIP_REF, off);
            return FALSE;
        }
    }
    // then look up strips 0..nstrips-1 to make sure they are all present
    for (int stripno = 0; stripno < nstrips; stripno++) {
        t_pdfstripinfo strip;
        if (!get_strip_info(reader, p, stripno, &strip)) {
            // errors already logged
            return FALSE;
        }
        if (stripno == 0) {
            pinfo->width = strip.width;
            pinfo->format = strip.format;
            pinfo->cs = strip.cs;
            pinfo->cs.bitsPerComponent = strip.cs.bitsPerComponent;
        }
        else if (pinfo->width != strip.width) {
            // all strips on a page must have the same width
            compliance(reader, READ_STRIP_WIDTH_SAME, strip.pos);
            return FALSE;
        }
        else if (pinfo->format != strip.format) {
            // all strips on a page must have the same format
            compliance(reader, READ_STRIP_FORMAT_SAME, strip.pos);
            return FALSE;
        }
        else if (!colorspace_equal(pinfo->cs, strip.cs)) {
            // all strips on a page must have equal colorspaces
            compliance(reader, READ_STRIP_COLORSPACE_SAME, strip.pos);
            return FALSE;
        }
        // page height is sum of strip heights
        pinfo->height += strip.height;
		// max_strip_size is (surprise) the maximum of the strip sizes (in bytes)
		pinfo->max_strip_size = ulmax(pinfo->max_strip_size, (unsigned long)strip.raw_size);
		// found a valid strip, count it
		pinfo->strip_count++;
	} // for each strip
	// we have MediaBox and pixel dimensions, we can calculate DPI
	pinfo->xdpi = tweak_dpi(pinfo->width * 72.0 / (pinfo->MediaBox[2] - pinfo->MediaBox[0]));
	pinfo->ydpi = tweak_dpi(pinfo->height * 72.0 / (pinfo->MediaBox[3] - pinfo->MediaBox[1]));
	return TRUE;
}

// internal function that just passes an error through the (settable) global error handler.
static int call_global_error_handler(t_pdfrasreader* reader, int level, int code, pduint32 offset)
{
    return global_error_handler(reader, level, code, offset);
}

///////////////////////////////////////////////////////////////////////
// Top-Level Public Functions

// Create a PDF/raster reader
t_pdfrasreader* pdfrasread_create(int apiLevel, pdfras_freader readfn, pdfras_fsizer sizefn, pdfras_fcloser closefn)
{
	if (apiLevel < 1 || apiLevel > RASREAD_API_LEVEL) {
		// error, caller expects a future version of this API
        api_error(NULL, READ_API_APILEVEL, (pduint32)apiLevel);
        return NULL;
	}
    if (!readfn || !sizefn) {
        // closer can be NULL, but not these guys
        api_error(NULL, READ_API_NULL_PARAM, __LINE__);
        return NULL;
    }
    // some internal consistency checks
	if (20 != sizeof(t_xref_entry)) {
		// compilation/build error: xref entry is not exactly 20 bytes.
        internal_error(NULL, READ_INTERNAL_XREF_SIZE, sizeof(t_xref_entry));
        return NULL;
	}
	t_pdfrasreader* reader = (t_pdfrasreader*)malloc(sizeof(t_pdfrasreader));
    if (!reader) {
        memory_error(NULL, __LINE__);
        return NULL;
    }
    memset(reader, 0, sizeof *reader);
    reader->sig = READER_SIGNATURE;
    reader->apiLevel = apiLevel;
    reader->fread = readfn;
    reader->fsize = sizefn;
    reader->fclose = closefn;
    reader->error_handler = call_global_error_handler;
    reader->page_count = -1;		// Unknown
    assert(VALID(reader));
	return reader;
}

void pdfrasread_destroy(t_pdfrasreader* reader)
{
    if (!VALID(reader)) {
        api_error(NULL, READ_API_BAD_READER, __LINE__);
    } else {
        // force closed if open
        pdfrasread_close(reader);
        reader->sig = 0xDEAD;
		free(reader);
	}
}

const char* pdfrasread_lib_version(void)
{
    return PDFRASREAD_VERSION " (" CONFIGURATION ") ";
}

// Return the number of pages in the associated PDF/raster file
// -1 in case of error.
int pdfrasread_page_count(t_pdfrasreader* reader)
{
    if (!VALID(reader)) {
        api_error(NULL, READ_API_BAD_READER, __LINE__);
        return -1;
    }
    if (!reader->bOpen) {
        api_error(reader, READ_API_NOT_OPEN, __LINE__);
        return -1;
    }
    if (!reader->xrefs) {
        if (!parse_trailer(reader)) {
            return -1;
        }
    }
    return reader->page_count;
}

// Return the pixel format of the raster image of page n (indexed from 0)
RasterReaderPixelFormat pdfrasread_page_format(t_pdfrasreader* reader, int n)
{
    t_pdfpageinfo info;
    if (!get_page_info(reader, n, &info)) {
        return RASREAD_FORMAT_NULL;
    }
    return info.format;
}

int pdfrasread_page_bits_per_component(t_pdfrasreader* reader, int n)
{
    t_pdfpageinfo info;
    if (!get_page_info(reader, n, &info)) {
        return RASREAD_FORMAT_NULL;
    }
    return info.cs.bitsPerComponent;
}

// Return the pixel width of the raster image of page n
int pdfrasread_page_width(t_pdfrasreader* reader, int n)
{
    t_pdfpageinfo info;
    if (!get_page_info(reader, n, &info)) {
        return 0;
    }
    return info.width;
}

// Return the pixel height of the raster image of page n
int pdfrasread_page_height(t_pdfrasreader* reader, int n)
{
    t_pdfpageinfo info;
    if (!get_page_info(reader, n, &info)) {
        return 0;
    }
    return info.height;
}

// Return the clockwise rotation in degrees to be applied to page n
int pdfrasread_page_rotation(t_pdfrasreader* reader, int n)
{
    t_pdfpageinfo info;
    if (!get_page_info(reader, n, &info)) {
        return 0;
    }
    return info.rotation;
}

// Get the resolution in dpi of the raster image of page n
double pdfrasread_page_horizontal_dpi(t_pdfrasreader* reader, int n)
{
    t_pdfpageinfo info;
    if (!get_page_info(reader, n, &info)) {
        return 0.0;
    }
    return info.xdpi;
}

double pdfrasread_page_vertical_dpi(t_pdfrasreader* reader, int n)
{
    t_pdfpageinfo info;
    if (!get_page_info(reader, n, &info)) {
        return 0.0;
    }
    return info.ydpi;
}

// Strip reading functions
// Return the number of strips in page p
int pdfrasread_strip_count(t_pdfrasreader* reader, int p)
{
    t_pdfpageinfo info;
    if (!get_page_info(reader, p, &info)) {
        return 0;
    }
    return info.strip_count;
}

// Return the maximum raw (compressed) strip size on page p
size_t pdfrasread_max_strip_size(t_pdfrasreader* reader, int p)
{
    t_pdfpageinfo info;
    if (!get_page_info(reader, p, &info)) {
        return 0;
    }
    return info.max_strip_size;
}

// Read the raw (compressed) data of strip s on page p into buffer, not more than bufsize bytes.
// Returns the actual number of bytes read.
// A return value of 0 indicates an error.
size_t pdfrasread_read_raw_strip(t_pdfrasreader* reader, int p, int s, char* buffer, size_t bufsize)
{
    t_pdfstripinfo strip;
    if (!get_strip_info(reader, p, s, &strip)) {
        // error already reported.
        return 0;
    }
    size_t length = strip.raw_size;
    if (length > bufsize) {
        // invalid strip request, strip does not fit in buffer
        api_error(reader, READ_STRIP_BUFFER_SIZE, length);
        return 0;
    }
    if (reader->fread(reader->source, strip.data_pos, length, buffer) != length) {
        // read error, unable to read all of strip data
        io_error(reader, READ_STRIP_READ, s);
        return 0;
    }
    return length;
}

RasterReaderCompression pdfrasread_strip_compression(t_pdfrasreader* reader, int p, int s)
{
    t_pdfstripinfo strip;
    if (!get_strip_info(reader, p, s, &strip)) {
        return RASREAD_COMPRESSION_NULL;
    }
    return strip.compression;
}

static const char* error_code_description(int code)
{
    switch (code) {
    case READ_OK:                   return "OK";
    case READ_API_BAD_READER:       return "an API function was called with an invalid reader";
    case READ_API_APILEVEL:         return "pdfrasread_create called with apiLevel < 1 or > what library supports.";
    case READ_API_NULL_PARAM:       return "function called with null parameter that can't be null.";
    case READ_API_ALREADY_OPEN:     return "function called with a reader that was already open.";
    case READ_API_NOT_OPEN:         return "function called with a reader that isn't open.";
    case READ_API_NO_SUCH_PAGE:     return "function called with page index that is out-of-range";
    case READ_API_NO_SUCH_STRIP:    return "function called with strip index that is out-of-range";
    case READ_STRIP_BUFFER_SIZE:    return "strip too big to fit in provided strip buffer.";
    case READ_INTERNAL_XREF_SIZE:   return "internal build/compilation error: sizeof(xref_entry) != 20 bytes";
    case READ_INTERNAL_XREF_TABLE:  return "internal error - xref table not loaded";
    case READ_MEMORY_MALLOC:        return "malloc returned NULL - insufficient memory (or heap corrupt)";
    case READ_FILE_EOF_MARKER:      return "%%EOF not found near end of file (prob. not a PDF)";
    case READ_FILE_STARTXREF:       return "startxref not found near end of file (so prob. not a PDF)";
    case READ_FILE_BAD_STARTXREF:   return "startxref found - but invalid syntax or value";
    case READ_DICTIONARY:           return "expected a dictionary object";
    case READ_DICT_NAME_KEY:        return "every dictionary key must be a name (/xyz)";
    case READ_DICT_OBJSTM:          return "dictionary with /Type /ObjStm  S6.2 P4";
    case READ_DICT_EOF:             return "end-of-file in dictionary. where is the '>>'?";
    case READ_DICT_VALUE:           return "malformed or missing value in dictionary";
    case READ_STREAM:               return "expected a stream object";
    case READ_STREAM_CRLF:          return "stream keyword followed by CR but then no LF";
    case READ_STREAM_LINEBREAK:     return "stream keyword not followed by CRLF or LF";
    case READ_STREAM_LENGTH:        return "stream dictionary /Length entry not found";
    case READ_STREAM_LENGTH_INT:    return "stream - /Length value isn't an integer literal";
    case READ_STREAM_ENDSTREAM:     return "endstream not found where expected";
    case READ_OBJECT_EOF:           return "end-of-file where a PDF value or object was expected";
    case READ_OBJECT:               return "expected an object,no object starts with this character";
    case READ_STRIP_REF:            return "strip entry in xobject dict must be an indirect reference";
    case READ_STRIP_DICT:           return "strip must start with a dictionary";
    case READ_STRIP_MISSING:        return "missing strip entry in xobject dict";
    case READ_STRIP_TYPE_XOBJECT:   return "strip /Type is not /XObject [PDF2 8.9.5]";
    case READ_STRIP_SUBTYPE:        return "strip lacks /Subtype or its value isn't /Image";
    case READ_STRIP_BITSPERCOMPONENT: return "strip must have /BitsPerComponent value of 1, 8 or 16";
    case READ_STRIP_CS_BPC:         return "invalid combination of /ColorSpace and /BitsPerComponent in strip";
    case READ_STRIP_HEIGHT:         return "strip must have /Height entry with inline non-negative integer value";
    case READ_STRIP_WIDTH:          return "strip must have /Width entry with inline non-negative integer value";
    case READ_STRIP_WIDTH_SAME:     return "all strips on a page must have equal /Width values";
    case READ_STRIP_FORMAT_SAME:    return "all strips on a page must have the same pixel format";
    case READ_STRIP_COLORSPACE_SAME: return "all strips on a page must have equivalent colorspaces";
    case READ_STRIP_DEPTH_SAME:     return "all strips on a page must have the same BitsPerComponent";
    case READ_STRIP_COLORSPACE:     return "strip must have a /Colorspace entry";
    case READ_STRIP_LENGTH:         return "strip must have /Length with non-negative inline integer value";
    case READ_VALID_COLORSPACE:     return "colorspace must comply with spec";
    case READ_CALGRAY_DICT:         return "/CalGray not followed by valid CalGray dictionary";
    case READ_CALRGB_DICT:          return "/CalRGB not followed by valid CalRGB dictionary";
    case READ_MATRIX:               return "/CalRGB /Matrix value does not start with '['";
    case READ_MATRIX_ELEMENT:       return "/CalRGB /Matrix array element is not a number";
    case READ_MATRIX_TOO_LONG:      return "/CalRGB /Matrix array has more than 9 elements";
    case READ_MATRIX_TOO_SHORT:     return "/CalRGB /Matrix array ended with fewer than 9 elements";
    case READ_ICC_PROFILE:          return "not a valid ICC Profile stream";
    case READ_ICCPROFILE_READ:      return "read error while reading ICC Profile data";
    case READ_COLORSPACE_ARRAY:     return "colorspace array syntax error - missing closing ']'?";
    default:
        return "<no details>";
    }
}

int pdfrasread_default_error_handler(t_pdfrasreader* reader, int level, int code, pduint32 offset)
{
    const char* levelName[] = {
        "INFORMATIONAL",        // useful to know but not bad news.
        "WARNING",              // a potential problem - but execution can continue.
        "COMPLIANCE",           // a violation of the PDF/raster specification was detected.
        "INV API CALL",		    // an invalid request was made to this API.
        "MEMORY ALLOC",		    // memory allocation failed.
        "I/O ERROR",		    // low-level read or write failed unexpectedly.
        "INTERNAL LIMIT",		// a built-in limitation of this library was exceeded.
        "INTERNAL ERROR",	    // an 'impossible' internal state has been detected.
        "OTHER FATAL"		    // none of the above, current API call fails.
    };
    char marker = '*';      // for errors
    if (level == REPORTING_INFO) {
        marker = '-';
    }
    else if (level == REPORTING_WARNING) {
        marker = '?';
    }
    assert(level >= REPORTING_INFO);
    assert(level <= REPORTING_OTHER);
    level = MAX(REPORTING_INFO, MIN(REPORTING_OTHER, level));
    fprintf(stderr, "%c %13s  offset +%06u, code %d: %s\n", marker, levelName[level], offset, code, error_code_description(code));
    return 0;
}


void pdfrasread_set_error_handler(t_pdfrasreader* reader, pdfras_err_handler errhandler)
{
    if (!VALID(reader)) {
        api_error(NULL, READ_API_BAD_READER, __LINE__);
    } else {
        if (!errhandler) {
            errhandler = call_global_error_handler;
        }
        reader->error_handler = errhandler;
    }
}

void pdfrasread_set_global_error_handler(pdfras_err_handler errhandler)
{
    if (!errhandler) {
        errhandler = pdfrasread_default_error_handler;
    }
    global_error_handler = errhandler;
}

pdfras_err_handler pdfrasread_get_global_error_handler(void)
{
    return global_error_handler;
}


void pdfrasread_get_highest_pdfr_version(t_pdfrasreader* reader, int* pmajor, int* pminor)
{
    if (pmajor) *pmajor = RASREAD_MAX_MAJOR;
    if (pminor) *pminor = RASREAD_MAX_MINOR;
}

int pdfrasread_open(t_pdfrasreader* reader, void* source)
{
    if (!VALID(reader)) {
        api_error(NULL, READ_API_BAD_READER, __LINE__);
        return FALSE;
    }
	if (reader->bOpen) {
        // already open, can't open it.
        api_error(reader, READ_API_ALREADY_OPEN, __LINE__);
        return FALSE;
	}
    assert(!reader->bOpen);
	reader->source = source;
    reader->filesize = reader->fsize(reader->source);
    if (!parse_trailer(reader)) {
        // not a valid PDF/raster file
		reader->source = NULL;
	}
	else {
		reader->bOpen = PD_TRUE;
	}
	return reader->bOpen;
}

void* pdfrasread_source(t_pdfrasreader* reader)
{
    if (!VALID(reader)) {
        api_error(NULL, READ_API_BAD_READER, __LINE__);
        return NULL;
    }
    // NOTE - we don't require that the reader be currently open!
    // This returns the most recent source used with this reader, or
    // NULL if this reader has never been open.
    return reader->source;
}

int pdfrasread_is_open(t_pdfrasreader* reader)
{
    if (!VALID(reader)) {
        api_error(NULL, READ_API_BAD_READER, __LINE__);
        return FALSE;
    }
	return reader->bOpen;
}

int pdfrasread_close(t_pdfrasreader* reader)
{
    if (!VALID(reader)) {
        api_error(NULL, READ_API_BAD_READER, __LINE__);
        return FALSE;
    }
    // note, closing when reader is not open is valid, just a no-op.
    if (reader->bOpen) {
        if (reader->fclose) {
            reader->fclose(reader->source);
        }
        reader->bOpen = PD_FALSE;
    }
    // free structures that cannot be needed now
    if (reader->page_table) {
        free(reader->page_table);
        reader->page_table = NULL;
    }
    if (reader->xrefs) {
        free(reader->xrefs);
        reader->xrefs = NULL;
    }
    assert(reader->bOpen == PD_FALSE);
    return TRUE;
}
