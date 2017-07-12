// pdfras_tool  application.h

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

const string app_version("1.0");
const string app_name("pdfras_tool");

class application {
public:
	application() { page_count = -1; }
	void parse_args(int argc, char * argv[]);
	void application::usage();
	void run();
private:
	handles handle;
	configuration config;

	int page_count;
	RasterReaderPixelFormat page_pixel_format;
	int page_bit_per_component;
	int page_width;
	int page_height;
	int page_rotation; // clockwise rotation in degrees to be applied to page
	double page_xdpi;
	double page_ydpi;
	int page_strips;
	size_t page_max_strip_size;
	RasterReaderCompression page_compression;

	void pdfr_lib_info();
	void pdfr_open();
	void pdfr_parse_details();
	void pdfr_parse_image();
	void pdfr_close();
};