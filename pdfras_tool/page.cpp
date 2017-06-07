// pdfras_tool  page.cpp

#include <iostream>

#include <pdfrasread.h>

#include "journal.h"
#include "error.h"
#include "page.h"

char *page_info::get_pixel_format_string() const {
	switch (pixel_format) {
	case RASREAD_BITONAL: return "bitonal";	// 1-bit per pixel, 0=black
	case RASREAD_GRAY8: return "gray8";	// 8-bit per pixel, 0=black
	case RASREAD_GRAY16: return "gray16"; // 16-bit per pixel, 0=black
	case RASREAD_RGB24: return "rgb24";	// 24-bit per pixel, sRGB
	case RASREAD_RGB48: return "rgb48";	// 48-bit per pixel, sRGB
	default:
		LOG(err, "X unrecognized pixel format");
		ERR(PDFRAS_READER_PAGE_PIXEL_FORMAT_FAIL);
	}
}

char *page_info::get_compression_string() const {
	switch (compression) {
	case RASREAD_COMPRESSION_NULL:
	case RASREAD_UNCOMPRESSED: return "uncompressed";
	case RASREAD_JPEG: return "JPEG";
	case RASREAD_CCITTG4: return "CCITT Group 4 Facsimile";
	default:
		LOG(err, "X unrecognized compression");
		ERR(PDFRAS_READER_PAGE_COMPRESSION_FAIL);
	}
}