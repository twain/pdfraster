// pdfras_tool  configuration.cpp

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

#include <iostream>

#include <pdfrasread.h>

#include "error.h"
#include "journal.h"
#include "configuration.h"

configuration::configuration() {
	page = 1;
}

bool configuration::is_valid() {
	LOG(dbg, "> page = %d", page);
	LOG(dbg, "| test_pdfr=%s print_details=%s extract_image=%s", B2PC(op.get_test_pdfr()), B2PC(op.get_print_details()), B2PC(op.get_extract_image()));

	bool rv = true;

	if (page < 1) {
		LOG(err, "| page number (%d) is less than 1", page);
		rv = false;
	}

	if (op.get_nop()) {
		LOG(err, "| configuration operatrion is NOP");
		rv = false;
	}

	LOG(dbg, "<");
	return rv;
}