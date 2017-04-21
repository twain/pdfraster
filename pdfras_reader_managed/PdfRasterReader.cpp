// This is the main DLL file.

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <string.h>
#include <vcclr.h>

#include "PdfRaster.h"
#include "pdfrasread.h"
#include "pdfrasread_files.h"
#include "PdfRasterReader.h"

// #define PDF_RASTER_READER_LOG
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

static const int MAX_DECODERS = 32;

static char *wchar2char(String ^inputwidestring)
{
	char *outputstring = new char[inputwidestring->Length + 1];
	for (int i = 0; i < inputwidestring->Length; i++) {
		outputstring[i] = (char)inputwidestring[i]; //convert from wchar to char
	}
	outputstring[inputwidestring->Length] = 0;
	return outputstring;
}

static struct state {
	state()
	{
		decoder = nullptr;
	}
	void invalidate() {
		decoder = nullptr;
	}
	bool valid() {
		return (decoder == nullptr) ? false : true;
	}
	t_pdfrasreader *decoder; //if == nullptr, the struct[i] not valid
} state[MAX_DECODERS];

static void checkStateValid(int idx)
{
	if ((idx < 0) || (idx >= MAX_DECODERS)) {
		LOG(fprintf(fp, "- ERROR in %s(): invalid index argument (%d) to (MAX_DECODERS=%d)", __FUNCTION__, idx, MAX_DECODERS));
		throw(L"invalid index argument to stateValid");
	}

	if (!state[idx].valid()) {
		LOG(fprintf(fp, "- ERROR in %s(): state[%d] not valid", __FUNCTION__, idx));
		throw(L"state[idx] not valid");
	}
}

namespace PdfRasterReader {
	int Reader::decoder_create(int apiLevel, String^ pdfFileName)
	{
		LOG(fprintf(fp, "> apiLevel=%d", apiLevel));

		int idx;
		for (idx = 0; idx < MAX_DECODERS; ++idx) {
			if (!state[idx].valid()) {
				break; //good, found an unused encoder struc
			}
		}
		if (idx == MAX_DECODERS) {
			LOG(fprintf(fp, "- ERROR: too many encoders used"));
			throw(L"too many encoders used");
		}

		char *filename = wchar2char(pdfFileName);
		LOG(fprintf(fp, "- filename=\"%s\"", filename));

		state[idx].decoder = pdfrasread_open_filename(RASREAD_API_LEVEL, filename);

		if (state[idx].decoder == nullptr) {
			state[idx].invalidate();
			char buf[256]; buf[0] = 0; strerror_s(buf, sizeof(buf) - 1, errno);
			LOG(fprintf(fp, "- ERROR: fopen() returned 0 errno=%d \"%s\"", errno, buf));
			throw(L"fopen() returned 0 ");
		}

		LOG(fprintf(fp, "< idx=%d", idx));
		return idx;
	}

	int Reader::decoder_get_page_count(int idx)
	{
		LOG(fprintf(fp, "> idx=%d", idx));
		checkStateValid(idx);

		int page_count = pdfrasread_page_count(state[idx].decoder);

		LOG(fprintf(fp, "< page_count=%d", page_count));
		return page_count;
	}

	int Reader::decoder_get_width(int idx)
	{
		LOG(fprintf(fp, "> idx=%d", idx));
		checkStateValid(idx);

		int width = pdfrasread_page_width(state[idx].decoder, 0);

		LOG(fprintf(fp, "< width=%d", width));
		return width;
	}

	int Reader::decoder_get_height(int idx)
	{
		LOG(fprintf(fp, "> idx=%d", idx));
		checkStateValid(idx);

		int height = pdfrasread_page_height(state[idx].decoder, 0);

		LOG(fprintf(fp, "< height=%d", height));
		return height;
	}

	double Reader::decoder_get_xresolution(int idx)
	{
		LOG(fprintf(fp, "> idx=%d", idx));
		checkStateValid(idx);

		double xres = pdfrasread_page_horizontal_dpi(state[idx].decoder, 0);

		LOG(fprintf(fp, "< xres=%f", xres));
		return xres;
	}

	double Reader::decoder_get_yresolution(int idx)
	{
		LOG(fprintf(fp, "> idx=%d", idx));
		checkStateValid(idx);

		double yres = pdfrasread_page_vertical_dpi(state[idx].decoder, 0);

		LOG(fprintf(fp, "< yres=%f", yres));
		return yres;
	}

	Reader::PdfRasterReaderPixelFormat Reader::decoder_get_pixelformat(int idx)
	{
		LOG(fprintf(fp, "> idx=%d", idx));
		checkStateValid(idx);

		RasterReaderPixelFormat f = pdfrasread_page_format(state[idx].decoder, 0);

		PdfRasterReaderPixelFormat format;
		switch (f) {
		case RASREAD_FORMAT_NULL: format = PdfRasterReaderPixelFormat::PDFRASREAD_FORMAT_NULL; break;
		case RASREAD_BITONAL: format = PdfRasterReaderPixelFormat::PDFRASREAD_BITONAL; break;
		case RASREAD_GRAY8: format = PdfRasterReaderPixelFormat::PDFRASREAD_GRAYSCALE; break;
		case RASREAD_GRAY16: format = PdfRasterReaderPixelFormat::PDFRASREAD_GRAYSCALE16; break;
		case RASREAD_RGB24: format = PdfRasterReaderPixelFormat::PDFRASREAD_RGB; break;
		case RASREAD_RGB48: format = PdfRasterReaderPixelFormat::PDFRASREAD_RGB48; break;
		}

		switch (format) {
		case PdfRasterReaderPixelFormat::PDFRASREAD_FORMAT_NULL: LOG(fprintf(fp, "< FORMAT_NULL")); break;
		case PdfRasterReaderPixelFormat::PDFRASREAD_BITONAL: LOG(fprintf(fp, "< BITONAL")); break;
		case PdfRasterReaderPixelFormat::PDFRASREAD_GRAYSCALE: LOG(fprintf(fp, "< GRAYSCALE")); break;
		case PdfRasterReaderPixelFormat::PDFRASREAD_GRAYSCALE16: LOG(fprintf(fp, "< GRAYSCALE16")); break;
		case PdfRasterReaderPixelFormat::PDFRASREAD_RGB: LOG(fprintf(fp, "< RGB")); break;
		case PdfRasterReaderPixelFormat::PDFRASREAD_RGB48: LOG(fprintf(fp, "< RGB48")); break;
		default: LOG(fprintf(fp, "> unknown pixel format!")); throw("unkown pixel format"); break;
		}
		return format;
	}

	Reader::PdfRasterReaderCompression Reader::decoder_get_compression(int idx)
	{
		LOG(fprintf(fp, "> idx=%d", idx));
		checkStateValid(idx);

		RasterReaderCompression c = pdfrasread_strip_compression(state[idx].decoder, 0, 0);

		PdfRasterReaderCompression compression;
		switch (c) {
		case RASREAD_COMPRESSION_NULL: compression = PdfRasterReaderCompression::PDFRASREAD_UNCOMPRESSED /*PDFRASREAD_COMPRESSION_NULL*/; break;
		case RASREAD_UNCOMPRESSED: compression = PdfRasterReaderCompression::PDFRASREAD_UNCOMPRESSED; break;
		case RASREAD_JPEG: compression = PdfRasterReaderCompression::PDFRASREAD_JPEG; break;
		case RASREAD_CCITTG4: compression = PdfRasterReaderCompression::PDFRASEARD_CCITTG4; break;
		}
		
		switch (compression) {
		case PdfRasterReaderCompression::PDFRASREAD_COMPRESSION_NULL: LOG(fprintf(fp, "< COMPRESSION_NULL")); break;
		case PdfRasterReaderCompression::PDFRASREAD_UNCOMPRESSED: LOG(fprintf(fp, "< COMPRESSION_NONE")); break;
		case PdfRasterReaderCompression::PDFRASREAD_JPEG: LOG(fprintf(fp, "< COMPRESSION_JPEG")); break;
		case PdfRasterReaderCompression::PDFRASEARD_CCITTG4: LOG(fprintf(fp, "< COMPRESSION_G4")); break;
		default: LOG(fprintf(fp, "> unknown compression type!")); throw("unkown compression type"); break;
		}
		return compression;
	}

	array<Byte>^ Reader::decoder_read_strips(int idx)
	{
		LOG(fprintf(fp, "> idx=%d", idx));
		checkStateValid(idx);

		int strip_count = pdfrasread_strip_count(state[idx].decoder, 0);
		LOG(fprintf(fp, "- strip_count=%d", strip_count));
		if (strip_count != 1) {
			throw("num strips not 1");
		}

		size_t max_strip_size = pdfrasread_max_strip_size(state[idx].decoder, 0);
		LOG(fprintf(fp, "- max_strip_size=%zu", max_strip_size));

		array<Byte>^ strip_data = gcnew array<Byte> (max_strip_size);
		pin_ptr <Byte> rawstrip = &strip_data[0];

		char *ptr_rawstrip = (char *) rawstrip;
		size_t rcvd_strip_size = pdfrasread_read_raw_strip(state[idx].decoder, 0, 0, ptr_rawstrip, max_strip_size);
		rawstrip = nullptr;
		LOG(fprintf(fp, "- rcvd_strip_size=%zu", rcvd_strip_size));

		if (max_strip_size != rcvd_strip_size) {
			throw("max_strip_size != rcvd_strip_size");
		}

		LOG(fprintf(fp, "<"));
		return strip_data;
	}

	void Reader::decoder_destroy(int idx)
	{
		LOG(fprintf(fp, "> idx=%d", idx));

		checkStateValid(idx);
		pdfrasread_close(state[idx].decoder);
		pdfrasread_destroy(state[idx].decoder);
		state[idx].invalidate();

		LOG(fprintf(fp, "<"));
	}
}