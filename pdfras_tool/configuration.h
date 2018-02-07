// pdfras_tool  configuration.h

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

class operation {
private:
	int op;
	const int nop = 0;					// do nothing
	const int test_pdfr = 1;			// test validity of PDFraster file
	const int print_details = 2;		// print PDFraster (width, length, resolution, etc.)
	const int extract_image = 4;		// extract image from PDFR file
    const int print_signature = 8;      // print info about digital signature
public:
	operation() { op = test_pdfr; }

	void set_nop() { op  = nop; }
	void add_nop() { op |= nop; }
	bool get_nop() { return op ? false : true;  }

	void set_test_pdfr() { op = test_pdfr; }
	void add_test_pdfr() { op |= test_pdfr; }
	bool get_test_pdfr() { return op & test_pdfr ? true : false; }

	void set_print_details() { op = print_details; }
	void add_print_details() { op |= print_details; }
	bool get_print_details() { return op & print_details ? true : false; }

	void set_extract_image() { op = extract_image; }
	void add_extract_image() { op |= extract_image; }
	bool get_extract_image() { return op & extract_image ? true : false; }

    void set_signature_info() { op = print_signature; }
    void add_signature_info() { op |= print_signature; }
    bool get_signature_info() { return op & print_signature ? true : false; }
};

class configuration {
public:
	operation op;
private:
	int page;
public:
	configuration();

	int get_page() const { return page; }
	void set_page(int p) { page = p; }

	bool is_valid();
};
