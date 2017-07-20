#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "portability.h"
#include "test_support.h"
#include "pdfrasread.h"

#include "PdfRaster.h"
#include "PdfStandardObjects.h"

typedef struct {
	size_t		bufsize;
	pduint8*	buffer;
	unsigned	pos;
} membuf;

// platform functions
static t_OS os;
// memory buffer to capture output streams
static char output[1024];
static membuf buffer = {
	.buffer = (pduint8*)output,
	.bufsize = sizeof output,
	.pos = 0
};

///////////////////////////////////////////////////////////////////////
// Helpers and handlers

static void myMemSet(void *ptr, pduint8 value, size_t count)
{
	memset(ptr, value, count);
}

static int myOutputWriter(const pduint8 * data, pduint32 offset, pduint32 len, void *cookie)
{
	membuf* buff = (membuf *)cookie;
	if (!data) {
		len = 0;
	}
	if (len) {
		data += offset;
		memcpy(buff->buffer + buff->pos, data, len);
		buff->pos += len;
	}
	buff->buffer[buff->pos] = 0;
	return len;
}

static void *mymalloc(size_t bytes)
{
	return malloc(bytes);
}

///////////////////////////////////////////////////////////////////////

void pdfraster_minimal_file()
{
	printf("PDF/raster: minimal zero-page file\n");

	ASSERT(pd_get_block_count(os.allocsys) == 0);
	ASSERT(pd_get_bytes_in_use(os.allocsys) == 0);

	buffer.pos = 0;										// reset the memory buffer
	ASSERT(pdfr_encoder_page_count(NULL) == -1);

	// write the minimal PDF/raster file - 0 pages, nothing special set:
	t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
	ASSERT(pdfr_encoder_page_count(enc) == 0);
	pdfr_encoder_end_document(enc);

	// validate the output in various ways
	ASSERT(strlen(output) > 128);
	ASSERT(strlen(output) < 1024);
	unsigned mv;
	unsigned char binsig[8];
	ASSERT(2 == sscanf_s(output, "%%PDF-1.%u\n%%%4s\n", &mv, binsig, (unsigned int) (sizeof binsig)));
	ASSERT(mv >= 4);
	ASSERT(mv <= 8);
	ASSERT(binsig[0] > 127);
	ASSERT(binsig[1] > 127);

	ASSERT(0 == strcmp(output + strlen(output) - 6, "%%EOF\n"));

	// check for reasonable state after end_document
	ASSERT(pdfr_encoder_page_count(enc) == 0);
	ASSERT(pdfr_encoder_bytes_written(enc) == buffer.pos);

	// free all memory used by this encoder
	pdfr_encoder_destroy(enc);

	ASSERT(pd_get_block_count(os.allocsys) == 0);
	ASSERT(pd_get_bytes_in_use(os.allocsys) == 0);
}

void pdfraster_output_tests(void)
{
	printf("-----------------\n");

	os.alloc = mymalloc;
	os.free = free;
	os.memset = myMemSet;
	os.allocsys = pd_alloc_new_pool(&os);
	os.writeout = myOutputWriter;
	os.writeoutcookie = &buffer;

	pdfraster_minimal_file();
}