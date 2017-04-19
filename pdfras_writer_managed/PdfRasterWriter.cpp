// This is the main DLL file.

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <string.h>
#include <vcclr.h>

#include "PdfRaster.h"
#include "PdfRasterWriter.h"

// #define PDF_RASTER_WRITER_LOG
#if defined(PDF_RASTER_WRITER_LOG) || defined(PDF_RASTER_WRITER_LOG_VERBOSE) || defined(PDF_RASTER_WRITER_LOG_VERBOSE_VERY)
#	define LOG(x) \
	{ \
		FILE *fp; \
		fopen_s(&fp,"pdfras_writer_managed-log.txt","at"); \
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

static void *myMalloc(size_t bytes)
{
#ifdef PDF_RASTER_WRITER_LOG_VERBOSE_VERY
	LOG(fprintf(fp, "> bytes=%zu", bytes));
#endif

	void *ptr = malloc(bytes);

#ifdef PDF_RASTER_WRITER_LOG_VERBOSE_VERY
	LOG(fprintf(fp, "< ptr=0x%p", ptr));
#endif
	return ptr;
}

static void myMemSet(void *ptr, pduint8 value, size_t count)
{
#ifdef PDF_RASTER_WRITER_LOG_VERBOSE_VERY
	LOG(fprintf(fp, "> ptr=0x%p value=%u count=%zu", ptr, (unsigned) value, count));
#endif

	memset(ptr, value, count);

#ifdef PDF_RASTER_WRITER_LOG_VERBOSE_VERY
	LOG(fprintf(fp, "<"));
#endif
}

static int myOutputWriter(const pduint8 *data, pduint32 offset, pduint32 len, void *cookie)
{
#ifdef PDF_RASTER_WRITER_LOG_VERBOSE
	LOG(fprintf(fp, "> data=0x%p offset=%u len=%u cookie=0x%p", data, offset, len, cookie));
#endif

	int rv = (int)len;
	do {
		FILE *fp = (FILE *)cookie;
		if (!data || !len || !fp) {
			LOG(fprintf(fp, "- ERROR !data || !len || !fp"));
			rv = 0;
			break;
		}
		data += offset;
		size_t written = fwrite(data, 1, len, fp);
#ifdef PDF_RASTER_WRITER_LOG_VERBOSE
		LOG(fprintf(fp, "- written=%zu", written));
#endif
		if (written != len) {
			LOG(fprintf(fp, "- ERROR written(%uz) != len(%u)", written, len));
			rv = -(int)(written + 1);
		}
	} while (0);

#ifdef PDF_RASTER_WRITER_LOG_VERBOSE
	LOG(fprintf(fp, "< rv=%d", rv));
#endif
	return rv;
}

static const int MAX_ENCODERS = 32;

static struct state {
	state()
	{
		enc = nullptr;

		os.alloc = myMalloc;
		os.free = free;
		os.memset = myMemSet;
		os.writeout = myOutputWriter;
		os.reportError = nullptr;
		os.writeoutcookie = nullptr;
		os.allocsys = nullptr;
	}
	void invalidate() {
		if (os.writeoutcookie != nullptr) {
			if (fclose((FILE *)os.writeoutcookie)) {
				LOG(fprintf(fp, "- ERROR: fclose() did not return 0"));
			}
			os.writeoutcookie = nullptr;
		}
		if (enc != nullptr) {
			pdfr_encoder_destroy(enc);
			enc = nullptr;
		}
	}
	bool valid() {
		return (enc == nullptr) ? false : true;
	}
	t_OS os;
	t_pdfrasencoder *enc; //if == nullptr, the struct[i] not valid
} state[MAX_ENCODERS];

static void checkStateValid(int idx)
{
	if ((idx < 0) || (idx >= MAX_ENCODERS)) {
		LOG(fprintf(fp, "- ERROR in %s(): invalid index argument (%d) to (MAX_ENCODERS=%d)", __FUNCTION__, idx, MAX_ENCODERS));
		throw(L"invalid index argument to stateValid");
	}

	if (!state[idx].valid()) {
		LOG(fprintf(fp, "- ERROR in %s(): state[%d] not valid", __FUNCTION__, idx));
		throw(L"state[idx] not valid");
	}
}

namespace PdfRasterWriter {
	int Writer::encoder_create(int apiLevel, String^ pdfFileName)
	{
		LOG(fprintf(fp, "> apiLevel=%d", apiLevel));

		int idx;
		for (idx = 0; idx < MAX_ENCODERS; ++idx) {
			if (!state[idx].valid()) {
				break; //good, found an unused encoder struc
			}
		}
		if (idx == MAX_ENCODERS) {
			LOG(fprintf(fp, "- ERROR: too many encoders used"));
			throw(L"too many encoders used");
		}

		pin_ptr<const wchar_t> wfile = PtrToStringChars(pdfFileName);
		LOG(fprintf(fp, "- pdfFileName=\"%S\"", wfile));

		if (errno_t err = _wfopen_s((FILE **)&state[idx].os.writeoutcookie, wfile, L"wb")) {
			state[idx].os.writeoutcookie = nullptr;
			state[idx].invalidate();
			char buf[256]; buf[0] = 0; strerror_s(buf, sizeof(buf) - 1, err);
			LOG(fprintf(fp, "- ERROR: _wfopen_s() returned 0 errno=%d \"%s\"", err, buf));
			throw(L"_wfopen_s() returned 0 ");
		}

		state[idx].enc = pdfr_encoder_create(apiLevel, &state[idx].os);
		if (!state[idx].valid()) {
			state[idx].invalidate();
			LOG(fprintf(fp, "- ERROR: pdfr_encoder_create() returned nullptr"));
			throw(L"pdfr_encoder_create() returned nullptr");
		}

		LOG(fprintf(fp, "< idx=%d", idx));
		return idx;
	}

	void Writer::encoder_set_creator(int idx, String^ creator)
	{
		LOG(fprintf(fp, "> idx=%d", idx));
		checkStateValid(idx);

		char *buf = new char[creator->Length +	1];
		for (int i = 0; i < creator->Length; i++) {
			buf[i] = (char) creator[i]; //convert from wchar to char
		}
		buf[creator->Length] = 0;
		LOG(fprintf(fp, "- buf=\"%s\"", buf));

		pdfr_encoder_set_creator(state[idx].enc, buf);
		delete [] buf; buf = nullptr;
		LOG(fprintf(fp, "<"));
	}

	void Writer::encoder_set_resolution(int idx, double xdpi, double ydpi)
	{
		LOG(fprintf(fp, "> idx=%d xdpi=%f ydpi=%f", idx, xdpi, ydpi));
		checkStateValid(idx);

		pdfr_encoder_set_resolution(state[idx].enc, xdpi, ydpi);
		LOG(fprintf(fp, "<"));
	}

	void Writer::encoder_set_pixelformat(int idx, PdfRasterPixelFormat format)
	{
		LOG(fprintf(fp, "> idx=%d format=%d", idx, format));
		checkStateValid(idx);

		RasterPixelFormat f;
		switch (format) { //convert from managed enum to unmanaged enum
		case PdfRasterPixelFormat::PDFRASWR_BITONAL:
			f = PDFRAS_BITONAL;
			break;
		case PdfRasterPixelFormat::PDFRASWR_GRAYSCALE:
			f = PDFRAS_GRAY8;
			break;
		case PdfRasterPixelFormat::PDFRASWR_GRAYSCALE16:
			f = PDFRAS_GRAY16;
			break;
		case PdfRasterPixelFormat::PDFRASWR_RGB:
			f = PDFRAS_RGB24;
			break;
		case PdfRasterPixelFormat::PDFRASWR_RGB48:
			f = PDFRAS_RGB48;
			break;
		default:
			throw(L"Pixel format not recognized");
			break;
		}
		LOG(fprintf(fp, "- f=%d", f));

		pdfr_encoder_set_pixelformat(state[idx].enc, f);
		LOG(fprintf(fp, "<"));
	}

	void Writer::encoder_set_compression(int idx, PdfRasterCompression compression)
	{
		LOG(fprintf(fp, "> idx=%d compression=%d", idx, compression));
		checkStateValid(idx);

		RasterCompression c;
		switch (compression) { //convert from managed enum to unmanaged enum
		case PdfRasterCompression::PDFRASWR_UNCOMPRESSED:
			c = PDFRAS_UNCOMPRESSED;
			break;
		case PdfRasterCompression::PDFRASWR_JPEG:
			c = PDFRAS_JPEG;
			break;
		case PdfRasterCompression::PDFRASWR_CCITTG4:
			c = PDFRAS_CCITTG4;
			break;
		default:
			throw(L"Compression mode not recognized");
			break;
		}
		LOG(fprintf(fp, "- c=%d", c));

		pdfr_encoder_set_compression(state[idx].enc, c);
		LOG(fprintf(fp, "<"));
	}

	void Writer::encoder_start_page(int idx, int width)
	{
		LOG(fprintf(fp, "> idx=%d width=%d", idx, width));
		checkStateValid(idx);

		pdfr_encoder_start_page(state[idx].enc, width);
		LOG(fprintf(fp, "<"));
	}

	void Writer::encoder_write_strip(int idx, int rows, array<unsigned char>^ buf, unsigned offset, unsigned len)
	{
		LOG(fprintf(fp, "> idx=%d rows=%d buf=0x%p offset=%u len=%u", idx, rows, buf, offset, len));
		checkStateValid(idx);

		pin_ptr<unsigned char> p = &buf[offset];
		pdfr_encoder_write_strip(state[idx].enc, rows, p, len);
		LOG(fprintf(fp, "<"));
	}

	void Writer::encoder_end_page(int idx)
	{
		LOG(fprintf(fp, "> idx=%d", idx));
		checkStateValid(idx);

		pdfr_encoder_end_page(state[idx].enc);
		LOG(fprintf(fp, "<"));
	}

	void Writer::encoder_end_document(int idx)
	{
		LOG(fprintf(fp, "> idx=%d", idx));
		checkStateValid(idx);

		pdfr_encoder_end_document(state[idx].enc);
		LOG(fprintf(fp, "<"));
	}

	void Writer::encoder_destroy(int idx)
	{
		LOG(fprintf(fp, "> idx=%d", idx));
		checkStateValid(idx);

		state[idx].invalidate();
		LOG(fprintf(fp, "<"));
	}
}