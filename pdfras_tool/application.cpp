// pdfras_tool  application.cpp

///////////////////////////////////////////////////////////////////////////////////////
//  Copyright (C) 2017 TWAIN Working Group
//
//  Permission is hereby granted, free of charge, to any person obtaining a
//  copy of this software and associated documentation files (the "Software"),
//  to deal in the Software without restriction, including without limitation
//  the rights to use, copy, modify, merge, publish, distribute, sublicense,
//  and/or sell copies of the Software, and to permit persons to whom the
//  Software is furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
//  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//  DEALINGS IN THE SOFTWARE.
///////////////////////////////////////////////////////////////////////////////////////

#include <string>
#include <iostream>

#include "os_specific.h"
#ifdef COMPILING_FOR_WIN_MSVC
#	include "io.h"
#else
#	include "unistd.h"
#endif

#include <pdfrasread.h>

#include "journal.h"
#include "error.h"
#include "handles.h"
#include "configuration.h"
#include "application.h"
#include "jpeg.h"
#include "tiff.h"

using std::cout;
using std::endl;

void application::usage() {
	cout << "usage: pdfras_tool arg1 [argN ...]" << endl;
	cout << " -d          : print details about PDFraster file" << endl;
	cout << " -i=<file>   : the PDFraster input file (required)" << endl;
	cout << " -o=<file>   : extract PDFraster image to output file (omit file extension)" << endl;
	cout << " -p=<number> : page number (default is 1)" << endl;
	ERR(CLI_ARGS_INVALID);
}

using std::stoi;
void application::parse_args(int argc, char * argv[]) {
	LOG(dbg, "> argc=%d argv[0]=\"%s\"", argc, argv[0]);

	for (int i = 1; i < argc; ++i) {
		LOG(dbg, "| parse_args()argv[%d]=\"%s\"", i, argv[i]);

		const char opt_d[] = "-d";
		const char opt_i[] = "-i=";
		const char opt_o[] = "-o=";
		const char opt_p[] = "-p=";

		if (!strcmp(argv[i], opt_d)) {
			config.op.add_print_details();
		}
		else if (!strncmp(argv[i], opt_i, sizeof(opt_i) - 1)) {
			handle.ifile.set_name(argv[i] + (sizeof(opt_i) - 1));
		}
		else if (!strncmp(argv[i], opt_p, sizeof(opt_p) - 1)) {
			config.set_page(stoi(argv[i]+ (sizeof(opt_p) - 1)));
		}
		else if (!strncmp(argv[i], opt_o, sizeof(opt_o) - 1)) {
			config.op.add_extract_image();
			handle.ofile.set_name(argv[i] + (sizeof(opt_o) - 1));
		}
		else {
			LOG(err, "| option not recognized argv[%d]=\"%s\"",i,argv[i]);
			usage();
		}
	}

	if (0 == handle.ifile.get_name().length()) // required arg
		usage();

	if (!config.is_valid())
		usage();

	LOG(dbg,"<");
	return;
}

void application::pdfr_lib_info() {
	const char* version = pdfrasread_lib_version();
	LOG(info, "X pdfrasread library version = \"%s\"", version);
}

// Some private helper functions for using the pdfras_reader library

static size_t file_reader(void *source, pdfpos_t offset, size_t length, char *buffer)
{
	if (!source)
		return 0;

	FILE* f = (FILE*)source;
	if (0 != _fseeki64(f, offset, SEEK_SET)) {
		return 0;
	}
	return fread(buffer, sizeof(pduint8), length, f);
}

static pduint32 file_sizer(void* source)
{
	if (!source)
		return 0;

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

void application::pdfr_open() {
	LOG(dbg, ">");

	handle.set_reader(pdfrasread_create(RASREAD_API_LEVEL, &file_reader, &file_sizer, &file_closer));
	if (nullptr == handle.get_reader()) {
		LOG(err, "| error creating pdfras_reader handle for \"%s\"", handle.ifile.get_name().c_str());
		ERR(PDFRAS_READER_CREATE_FAIL);
	}

	bool is_pdfr = (pdfrasread_recognize_source(handle.get_reader(), handle.ifile.get_fp(), NULL, NULL) == TRUE) ? true : false;
	if (!is_pdfr) {
		LOG(err, "| filename=\"%s\" is not a PDF/raster file", handle.ifile.get_name().c_str());
		ERR(FILE_NOT_PDF_RASTER);
	}

	if (FALSE == pdfrasread_open(handle.get_reader(), handle.ifile.get_fp())) {
		LOG(err, "| error opening pdfras_reader handle for \"%s\"", handle.ifile.get_fp());
		ERR(PDFRAS_READER_OPEN_FAIL);
	}

	LOG(dbg, "<");
}

void application::pdfr_close() {
	LOG(dbg, ">");

	if (FALSE == pdfrasread_close(handle.get_reader())) {
		LOG(err, "| error closing pdfras_reader handle for \"%s\"", handle.ifile.get_fp());
		ERR(PDFRAS_READER_CLOSE_FAIL);
	}

	LOG(dbg, "<");
}

void application::pdfr_parse_details() {
	LOG(dbg, ">");
	string str;

	page_count = pdfrasread_page_count(handle.get_reader());
	if (-1 == page_count) {
		LOG(err, "| failed getting page count for filename=\"%s\"", handle.ifile.get_name().c_str());
		ERR(PDFRAS_READER_PAGE_COUNT_FAIL);
	}
	LOG(msg, "| page count = %d", page_count);
	if (config.op.get_print_details()) {
		cout << "page count = " << page_count << endl;
	}

	if (config.get_page() > page_count) {
		LOG(err, "| -p=%d option greater than pages=%d in filename=\"%s\"", config.get_page(), page_count, handle.ifile.get_name().c_str());
		ERR(PDFRAS_READER_PAGE_OPTION_TOO_BIG);
	}

	page_strips = pdfrasread_strip_count(handle.get_reader(), config.get_page() - 1); // doc says call with page number but it's wrong
	LOG(msg, "| page_strips = %d", page_strips);
	if (page_strips <= 0) {
		LOG(err, "| failed getting page strip count for filename=\"%s\" page=%d", handle.ifile.get_name().c_str(), config.get_page());
		ERR(PDFRAS_READER_PAGE_STRIP_COUNT_FAIL);
	}
	if (config.op.get_print_details()) {
		cout << "page " << config.get_page() << " strip count = " << page_strips << endl;
	}

	page_max_strip_size = pdfrasread_max_strip_size(handle.get_reader(), config.get_page() - 1); // doc says call with page number but it's wrong
	LOG(msg, "| page_max_strip_size = %zu", page_max_strip_size);
	if (page_max_strip_size == 0) {
		LOG(err, "| failed getting maximum page strip size for filename=\"%s\" page=%d", handle.ifile.get_name().c_str(), config.get_page());
		ERR(PDFRAS_READER_PAGE_MAX_STRIP_SIZE_FAIL);
	}
	if (config.op.get_print_details()) {
		cout << "page " << config.get_page() << " maximum (raw) strip size = " << page_max_strip_size << endl;
	}

	page_pixel_format = pdfrasread_page_format(handle.get_reader(), config.get_page() - 1);
	LOG(dbg, "| page_pixel_format = %d", page_pixel_format);
	switch (page_pixel_format) {
	case RASREAD_BITONAL: str = "bitonal"; break;	// 1-bit per pixel, 0=black
	case RASREAD_GRAY8: str = "gray8";   break;	// 8-bit per pixel, 0=black
	case RASREAD_GRAY16: str = "gray16"; break;	// 16-bit per pixel, 0=black
	case RASREAD_RGB24: str = "rgb24"; break;	// 24-bit per pixel, sRGB
	case RASREAD_RGB48: str = "rgb48  "; break;	// 48-bit per pixel, sRGB
	default:
		LOG(err, "| failed getting page_pixel_format for filename=\"%s\" page=%d", handle.ifile.get_name().c_str(), config.get_page());
		ERR(PDFRAS_READER_PAGE_PIXEL_FORMAT_FAIL);
	}
	LOG(msg, "| page_pixel_format = \"%s\"", str.c_str());
	if (config.op.get_print_details()) {
		cout << "page " << config.get_page() << " pixel format = " << str << endl;
	}

	page_bit_per_component = pdfrasread_page_bits_per_component(handle.get_reader(), config.get_page() - 1);
	LOG(msg, "| page_bit_per_component = %d", page_bit_per_component);
	switch (page_bit_per_component) {
	case  1: break;
	case  8: break;
	case 16: break;
	default:
		LOG(err, "| page_bit_per_component (%d) not 1,8,16 for filename=\"%s\" page=%d", page_bit_per_component, handle.ifile.get_name().c_str(), config.get_page());
		ERR(PDFRAS_READER_PAGE_BITS_PER_COMPONENT_FAIL);
	}
	if (config.op.get_print_details()) {
		cout << "page " << config.get_page() << " bits per component = " << page_bit_per_component << endl;
	}

	page_width = pdfrasread_page_width(handle.get_reader(), config.get_page() - 1);
	LOG(msg, "| page_width = %d", page_width);
	if (page_width <= 0) {
		LOG(err, "| failed getting page width for filename=\"%s\" page=%d", handle.ifile.get_name().c_str(), config.get_page());
		ERR(PDFRAS_READER_PAGE_WIDTH_FAIL);
	}
	if (config.op.get_print_details()) {
		cout << "page " << config.get_page() << " width (pixels) = " << page_width << endl;
	}

	int s;
	page_height = 0;
	for (s = 0; s < page_strips; ++s) {
		unsigned long ph = pdfrasread_strip_height(handle.get_reader(), config.get_page() - 1, s);
		LOG(dbg, "| height of strip %d = %d", s, ph);
		if (ph == 0) {
			page_height = 0;
			break;
		}
		page_height += ph;
	}
	LOG(msg, "| page_height = %d", page_height);
	if (page_height <= 0) {
		LOG(err, "| failed getting page height for filename=\"%s\" page=%d", handle.ifile.get_name().c_str(), config.get_page());
		ERR(PDFRAS_READER_PAGE_HEIGHT_FAIL);
	}
	if (config.op.get_print_details()) {
		cout << "page " << config.get_page() << " height (pixels) = " << page_height << endl;
	}

	page_rotation = pdfrasread_page_rotation(handle.get_reader(), config.get_page() - 1);
	LOG(msg, "| page_rotation = %d", page_rotation);
	if (config.op.get_print_details()) {
		cout << "page " << config.get_page() << " rotation (degrees clockwise when displayed) = " << page_rotation << endl;
	}

	page_xdpi = pdfrasread_page_horizontal_dpi(handle.get_reader(), config.get_page() - 1);
	LOG(msg, "| page_xdpi = %f", page_xdpi);
	if (config.op.get_print_details()) {
		cout << "page " << config.get_page() << " horizontal resolution (DPI) = " << page_xdpi << endl;
	}

	page_ydpi = pdfrasread_page_vertical_dpi(handle.get_reader(), config.get_page() - 1);
	LOG(msg, "| page_ydpi = %f", page_ydpi);
	if (config.op.get_print_details()) {
		cout << "page " << config.get_page() << " vertical resolution (DPI) = " << page_ydpi << endl;
	}

	page_compression = pdfrasread_strip_compression(handle.get_reader(), config.get_page() - 1, 0); // doc says call with page number but it's wrong
	LOG(dbg, "| page_compression = %d", page_compression);
	switch (page_compression) {
	case RASREAD_COMPRESSION_NULL:
	case RASREAD_UNCOMPRESSED: str = "uncompressed"; break;
	case RASREAD_JPEG: str = "JPEG";   break;
	case RASREAD_CCITTG4: str = "CCITT Group 4 Facsimile"; break;
	default:
		LOG(err, "| failed getting page_compression for filename=\"%s\" page=%d", handle.ifile.get_name().c_str(), config.get_page());
		ERR(PDFRAS_READER_PAGE_COMPRESSION_FAIL);
	}
	LOG(msg, "| page_compression = \"%s\"", str.c_str());
	if (config.op.get_print_details()) {
		cout << "page " << config.get_page() << " compression = " << str << endl;
	}

	LOG(dbg, "<");
}

void application::pdfr_parse_image() {
	LOG(dbg, "> extract_image=\"%s\"", B2PC(config.op.get_extract_image()));

	if (page_compression == RASREAD_JPEG) {
		if (page_strips != 1) {
			for (int s = 0; s < page_strips; ++s) {
				string ofn = handle.ofile.get_name() + "-strip" + std::to_string(s);
				jpeg jpg(ofn);
				jpg.write_body(handle.get_reader(), config.get_page(), s, 1, page_max_strip_size);
			}
		}
		else {
			jpeg jpg(handle.ofile.get_name());
			jpg.write_body(handle.get_reader(), config.get_page(), 0, page_strips, page_max_strip_size);
		}
	}
	else {
		if ((page_compression == RASREAD_CCITTG4) && (page_strips != 1)) {
			for (int s = 0; s < page_strips; ++s) {
				string ofn = handle.ofile.get_name() + "-strip" + std::to_string(s);
				tiff tif(ofn);
				tif.write_header(handle.get_reader(), config.get_page(), s, 1, page_max_strip_size, page_pixel_format);
				tif.write_body(handle.get_reader(), config.get_page(), s, 1, page_max_strip_size, page_pixel_format, page_xdpi, page_ydpi);
				unsigned long strip_height = pdfrasread_strip_height(handle.get_reader(), config.get_page() - 1, s);
				long raw_size = pdfrasread_strip_raw_size(handle.get_reader(), config.get_page() - 1, s);
				tif.write_trailer(page_pixel_format, page_width, (int)strip_height, raw_size, page_compression, page_rotation);
			}
		}
		else {
			tiff tif(handle.ofile.get_name());
			tif.write_header(handle.get_reader(), config.get_page(), 0, page_strips, page_max_strip_size, page_pixel_format);
			tif.write_body(handle.get_reader(), config.get_page(), 0, page_strips, page_max_strip_size, page_pixel_format, page_xdpi, page_ydpi);
			long raw_size = 0;
			if (page_compression == RASREAD_CCITTG4) {
				raw_size = pdfrasread_strip_raw_size(handle.get_reader(), config.get_page() - 1, 0);
			}
			tif.write_trailer(page_pixel_format, page_width, page_height, raw_size, page_compression, page_rotation);
		}
	}

	LOG(dbg, "<");
}

void application::run() {
	LOG(dbg, "> page=%d", config.get_page());
	LOG(dbg, "| test_pdfr=%s print_details=%s extract_image=%s", B2PC(config.op.get_test_pdfr()), B2PC(config.op.get_print_details()), B2PC(config.op.get_extract_image()));
	LOG(dbg, "| input_pdfr_filename = \"%s\"", handle.ifile.get_name().c_str());
	LOG(dbg, "| output_image_filename = \"%s\"", handle.ofile.get_name().c_str());

	pdfr_lib_info();

	handle.ifile.readable();
	handle.ifile.open("rb");

	pdfr_open();
	pdfr_parse_details();
	if (config.op.get_extract_image()) {
		pdfr_parse_image();
	}

	pdfr_close();

	LOG(dbg, "<");
	return;
}