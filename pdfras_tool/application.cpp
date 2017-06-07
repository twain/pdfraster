// pdfras_tool  application.cpp

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
#include "page.h"
#include "handles.h"
#include "configuration.h"
#include "application.h"

using std::cout;
using std::endl;

void application::usage() {
	cout << "usage: pdfras_tool arg1 [argN ...]" << endl;
	cout << " -d          : print details about PDFraster file" << endl;
	cout << " -i=<file>   : the PDFraster input file (required)" << endl;
	cout << " -o=<file>   : extract PDFraster image to output file" << endl;
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

static size_t file_reader(void *source, pduint32 offset, size_t length, char *buffer)
{
	if (!source)
		return 0;

	FILE* f = (FILE*)source;
	if (0 != fseek(f, offset, SEEK_SET)) {
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

// always test the input PDF/raster image, so even if no -d or -o options
// on the command line we still parse the details of the PDF/raster file
void application::pdfr_parse_details() {
	LOG(dbg, "<");

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
		LOG(err, "| -p=%d option greater than page count for filename=\"%s\"", config.get_page(), page_count, handle.ifile.get_name().c_str());
		ERR(PDFRAS_READER_PAGE_OPTION_TOO_BIG);
	}

	RasterReaderPixelFormat rrpf = pdfrasread_page_format(handle.get_reader(), config.get_page() - 1);
	page.set_pixel_format(rrpf);
	LOG(dbg, "| page_pixel_format = %d", page.get_pixel_format());
	LOG(msg, "| page_pixel_format = \"%s\"", page.get_pixel_format_string());
	if (config.op.get_print_details()) {
		cout << "page " << config.get_page() << " pixel format = " << page.get_pixel_format_string() << endl;
	}

	int bpc = pdfrasread_page_bits_per_component(handle.get_reader(), config.get_page() - 1);
	page.set_bits_per_component(bpc);
	LOG(msg, "| page_bits_per_component = %d", page.get_bits_per_component());
	if (config.op.get_print_details()) {
		cout << "page " << config.get_page() << " bits per component = " << page.get_bits_per_component() << endl;
	}

	int pw = pdfrasread_page_width(handle.get_reader(), config.get_page() - 1);
	page.set_width(pw);
	LOG(msg, "| page_width = %d", page.get_width());
	if (page.get_width() <= 0) {
		LOG(err, "| failed getting page width for filename=\"%s\" page=%d", handle.ifile.get_name().c_str(), config.get_page());
		ERR(PDFRAS_READER_PAGE_WIDTH_FAIL);
	}
	if (config.op.get_print_details()) {
		cout << "page " << config.get_page() << " width (pixels) = " << page.get_width() << endl;
	}

	int ph = pdfrasread_page_height(handle.get_reader(), config.get_page() - 1);
	page.set_height(ph);
	LOG(msg, "| page_width = %d", page.get_height());
	if (page.get_height() <= 0) {
		LOG(err, "| failed getting page height for filename=\"%s\" page=%d", handle.ifile.get_name().c_str(), config.get_page());
		ERR(PDFRAS_READER_PAGE_HEIGHT_FAIL);
	}
	if (config.op.get_print_details()) {
		cout << "page " << config.get_page() << " height (pixels) = " << page.get_height() << endl;
	}

	int pr = pdfrasread_page_rotation(handle.get_reader(), config.get_page() - 1);
	page.set_rotation(pr);
	LOG(msg, "| page_rotation = %d", page.get_rotation());
	if (config.op.get_print_details()) {
		cout << "page " << config.get_page() << " rotation (degrees clockwise when displayed) = " << page.get_rotation() << endl;
	}

	double xdpi = pdfrasread_page_horizontal_dpi(handle.get_reader(), config.get_page() - 1);
	page.set_x_dpi(xdpi);
	LOG(msg, "| page_x_dpi = %f", page.get_x_dpi());
	if (config.op.get_print_details()) {
		cout << "page " << config.get_page() << " horizontal resolution (DPI) = " << page.get_x_dpi() << endl;
	}

	double ydpi = pdfrasread_page_vertical_dpi(handle.get_reader(), config.get_page() - 1);
	page.set_y_dpi(ydpi);
	LOG(msg, "| page_y_dpi = %f", page.get_y_dpi());
	if (config.op.get_print_details()) {
		cout << "page " << config.get_page() << " vertical resolution (DPI) = " << page.get_y_dpi() << endl;
	}

	int ps = pdfrasread_strip_count(handle.get_reader(), config.get_page() - 1); // doc says call with page number but it's wrong
	page.set_strips(ps);
	LOG(msg, "| page_strips = %d", page.get_strips());
	if (page.get_strips() <= 0) {
		LOG(err, "| failed getting page strip count for filename=\"%s\" page=%d", handle.ifile.get_name().c_str(), config.get_page());
		ERR(PDFRAS_READER_PAGE_STRIP_COUNT_FAIL);
	}
	if (config.op.get_print_details()) {
		cout << "page " << config.get_page() << " strip count = " << page.get_strips() << endl;
	}

	size_t mss = pdfrasread_max_strip_size(handle.get_reader(), config.get_page() - 1); // doc says call with page number but it's wrong
	page.set_max_strip_size(mss);
	LOG(msg, "| page_max_strip_size = %zu", page.get_max_strip_size());
	if (page.get_max_strip_size() == 0) {
		LOG(err, "| failed getting maximum page strip size for filename=\"%s\" page=%d", handle.ifile.get_name().c_str(), config.get_page());
		ERR(PDFRAS_READER_PAGE_MAX_STRIP_SIZE_FAIL);
	}
	if (config.op.get_print_details()) {
		cout << "page " << config.get_page() << " maximum (raw) strip size = " << page.get_max_strip_size() << endl;
	}

	RasterReaderCompression pc = pdfrasread_strip_compression(handle.get_reader(), config.get_page() - 1, 0); // doc says call with page number but it's wrong
	page.set_compression(pc);
	LOG(dbg, "| page_compression = %d", page.get_compression());
	LOG(msg, "| page_compression = \"%s\"", page.get_compression_string());
	if (config.op.get_print_details()) {
		cout << "page " << config.get_page() << " compression = " << page.get_compression_string() << endl;
	}

	LOG(dbg, ">");
}

// always test the input PDF/raster image, so even if no -o option on the
// command line we still go through the process of extracting the PDF/raster
// file. We just don't actually write the image if no -o option specified.
void application::pdfr_extract_image()
{
	if (config.op.get_extract_image()) {
		handle.ofile.open("wb");
	}
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
	pdfr_extract_image();
	pdfr_close();

	LOG(dbg, "<");
	return;
}