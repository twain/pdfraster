// This is the main DLL file.

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <string.h>
#include <vcclr.h>

#include "pdfrasread.h"
#include "PdfRasterReader.h"

#define PDF_RASTER_READER_LOG
#if defined(PDF_RASTER_READER_LOG) || defined(PDF_RASTER_READER_LOG_VERBOSE) || defined(PDF_RASTER_READER_LOG_VERBOSE_VERY)
#	define LOG(x) \
	{ \
		FILE *fp; \
		fopen_s(&fp,"pdfras_reader_managed-log.txt","at"); \
		if (fp) { \
			fputs(__FUNCTION__,fp); \
			fputc(' ',fp); \
			x; \
			fputc('\n',fp); \
			fclose(fp); \
		} \
	}
#else
#	define LOG(x)
#endif

