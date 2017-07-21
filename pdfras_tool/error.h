// pdfras_tool  error.h

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

#pragma once

static const int err_base = 0x1000;

typedef enum {
	OK = 0,
	CLI_ARGS_INVALID = err_base + 1,
	FILE_NOT_READABLE = err_base + 2,
	FILE_OPEN_APPEND_FAIL = err_base + 3,
	PDFRAS_READER_CREATE_FAIL = err_base + 4,
	FILE_NOT_PDF_RASTER = err_base + 5,
	PDFRAS_READER_OPEN_FAIL = err_base + 6,
	PDFRAS_READER_CLOSE_FAIL = err_base + 7,
	PDFRAS_READER_PAGE_COUNT_FAIL = err_base + 8,
	PDFRAS_READER_PAGE_OPTION_TOO_BIG = err_base + 9,
	PDFRAS_READER_PAGE_PIXEL_FORMAT_FAIL = err_base + 10,
	FILE_CLOSE_FAIL = err_base + 11,
	PDFRAS_READER_PAGE_BITS_PER_COMPONENT_FAIL = err_base + 12,
	PDFRAS_READER_PAGE_WIDTH_FAIL = err_base + 13,
	PDFRAS_READER_PAGE_HEIGHT_FAIL = err_base + 14,
	PDFRAS_READER_PAGE_STRIP_COUNT_FAIL = err_base + 15,
	PDFRAS_READER_PAGE_MAX_STRIP_SIZE_FAIL = err_base + 16,
	PDFRAS_READER_PAGE_COMPRESSION_FAIL = err_base + 17,
	FILE_WRITE_FAIL = err_base + 18,
	FILE_OPEN_READ_FAIL = err_base + 19,
	FILE_OPEN_WRITE_FAIL = err_base + 20,
} pdfrt_error_code;

#define ERR(x) { \
	error err((x),__FUNCTION__,__FILE__,__LINE__); \
	throw err; \
}

using std::string;
class error {
private:
	int m_line;
	string m_file;
	string m_function;
	pdfrt_error_code m_pdfrt_error_code; //app error code
	ReadErrorCode m_ReadErrorCode; // pdfras_reader library error code
public:
	error();
	error(pdfrt_error_code err, const char *function, const char *file, int line);
	error(ReadErrorCode err, const char *function, const char *file, int line);
	bool operator () (void) const; // get
	const char *get_error_string() const;
};

using std::ostream;
ostream& operator << (ostream &os, const error &err);