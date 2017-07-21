#include "pdfrasread_files.h"
#include <string.h>
#include <ctype.h>
#include "PdfPlatform.h"

// Some private helper functions
static size_t file_reader(void *source, pdfpos_t offset, size_t length, char *buffer)
{
    FILE* f = (FILE*)source;
	#ifdef _WIN32
		if (0 != _fseeki64(f, offset, SEEK_SET)) {
			return 0;
		}
	#else
		if (0 != fseek(f, offset, SEEK_SET)) {
			return 0;
		}
	#endif
    return fread(buffer, sizeof(pduint8), length, f);
}

static pduint32 file_sizer(void* source)
{
    FILE* f = (FILE*)source;
    fseek(f, 0, SEEK_END);
    return (pduint32)ftell(f);
}

static void file_closer(void* source)
{
    if (source) {
        FILE* f = (FILE*)source;
        fclose(f);
    }
}

// Return TRUE if the file 'claims to be' a PDF/raster file.
// FALSE otherwise.
int pdfrasread_recognize_file(FILE* f)
{
    int bYes = FALSE;
    if (f) {
        t_pdfrasreader* reader = pdfrasread_create(RASREAD_API_LEVEL, &file_reader, &file_sizer, NULL);
        if (reader) {
            bYes = pdfrasread_recognize_source(reader, f, NULL, NULL);
            // destroy the reader
            pdfrasread_destroy(reader);
        }
    }
    return bYes;
}

// Return TRUE if the file starts with the signature of a PDF/raster file.
// FALSE otherwise.
int pdfrasread_recognize_filename(const char* fn)
{
	int bResult = FALSE;
	FILE* f = fopen(fn, "rb");
	if (f) {
		bResult = pdfrasread_recognize_file(f);
		fclose(f);
	}
	return bResult;
}

// Return the page count of the PDF/raster file f
// Does NOT close f.
int pdfrasread_page_count_file(FILE* f)
{
	int nPages = -1;
	// construct a PDF/raster reader based on the file
	t_pdfrasreader* reader = pdfrasread_create(RASREAD_API_LEVEL, &file_reader, &file_sizer, NULL);
	if (reader) {
		if (pdfrasread_open(reader, f)) {
			// count its pages
			nPages = pdfrasread_page_count(reader);
		}
		// destroy the reader
		pdfrasread_destroy(reader);
	}
	return nPages;
}

int pdfrasread_page_count_filename(const char* fn)
{
	int nPages = -1;
	FILE* f = fopen(fn, "rb");
	if (f) {
		nPages = pdfrasread_page_count_file(f);
		fclose(f);
	}
	return nPages;
}

t_pdfrasreader* pdfrasread_open_file(int apiLevel, FILE* f)
{
	t_pdfrasreader* reader = pdfrasread_create(apiLevel, &file_reader, &file_sizer, &file_closer);
	if (reader) {
		if (!pdfrasread_open(reader, f)) {
			pdfrasread_destroy(reader);
			reader = NULL;
		}
	}
	return reader;
}

t_pdfrasreader* pdfrasread_open_filename(int apiLevel, const char* fn)
{
	t_pdfrasreader* reader = NULL;
	FILE* f = fopen(fn, "rb");
	if (f) {
		// construct a PDF/raster reader based on the file
		reader = pdfrasread_open_file(apiLevel, f);
		if (!reader) {
			// open failed, we have to close the file ourselves
			fclose(f);
		}
	}
	return reader;
}
