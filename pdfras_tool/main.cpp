// pdfras_tools  main.cpp

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

#include "os_specific.h"
#ifdef COMPILING_FOR_WIN_MSVC
#	include "io.h"
#else
#	include "unistd.h"
#endif

#include <pdfrasread.h>

#include "os_specific.h"
#include "journal.h"
#include "error.h"
#include "handles.h"
#include "configuration.h"
#include "application.h"

using std::cerr;
using std::endl;

static void main_exit(error err)
{
	LOG(dbg, "> err()=%s" ,B2PC(err()));
	if (err())
		cerr << err << endl;
	LOG(dbg, "<");
	exit(err());
}

void main(int argc, char *argv[])
{
	LOG(dbg, "> argc=%d argv[0]=\"%s\"", argc, argv[0]);

	try {
		application app;
		app.parse_args(argc, argv);
		app.run();
		ERR(OK);
	}
	catch (error err) {
		main_exit(err);
	}

	LOG(dbg, "<");
}