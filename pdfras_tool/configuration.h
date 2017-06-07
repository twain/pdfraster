// pdfras_tool  configuration.h

#pragma once

class operation {
private:
	int op;
	const int nop = 0;					// do nothing
	const int test_pdfr = 1;			// test validity of PDFraster file
	const int print_details = 2;		// print PDFraster (width, length, resolution, etc.)
	const int extract_image = 4;		// extract image from PDFR file
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
