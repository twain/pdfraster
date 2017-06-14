// pdfras_tools  main.cpp

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