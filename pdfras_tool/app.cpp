// app.cpp

#include <iostream>
#include <assert.h>
#include <string.h>
using namespace std;
#include "os_specific.h"
#include "journal.h"
#include "app.h"
#include "error.h"
#include "pdfras_tool.h"

static void usage(TW_UINT16 twrc, ostream &s = cerr)
{
	s << "usage: " << PROG_NAME << " [-h|--help] [-v|--verbose]" << endl;
	error e(twrc);
	throw e;
}

app::app(int arg_count, char *arg_values[])
{
	LOG(dbg, "X arg_count=%d", arg_count);
	argc = arg_count;
	argv = arg_values;

	for (int i = 1; i < argc; ++i) {
		if (!strcmp("-v0", argv[i]) || !strcmp("-vn", argv[i]) || !strcmp("--verbose-none", argv[i])) {
			journal.set_level(none);
		}
		else if (!strcmp("-v1", argv[i]) || !strcmp("-ve", argv[i]) || !strcmp("--verbose-error", argv[i])) {
			journal.set_level(err);
		}
		else if (!strcmp("-v2", argv[i]) || !strcmp("-vw", argv[i]) || !strcmp("--verbose-warning", argv[i])) {
			journal.set_level(warn);
		}
		else if (!strcmp("-v3", argv[i]) || !strcmp("-vm", argv[i]) || !strcmp("--verbose-message", argv[i]) || !strcmp("-v", argv[i]) || !strcmp("--verbose", argv[i])) {
			journal.set_level(msg);
		}
		else if (!strcmp("-v4", argv[i]) || !strcmp("-vi", argv[i]) || !strcmp("--verbose-information", argv[i])) {
			journal.set_level(info);
		}
		else if (!strcmp("-v5", argv[i]) || !strcmp("-vd", argv[i]) || !strcmp("--verbose-debug", argv[i])) {
			journal.set_level(dbg);
		}
		else if (!strcmp("-h", argv[i]) || !strcmp("--help", argv[i])) {
			usage(TWRC_SUCCESS);
		}
		else {
			usage(TWRC_FAILURE);
		}
	}
}

app::~app()
{
	LOG(dbg, "X");
}

TW_UINT16 app::run()
{
	TW_UINT16 twrc = TWRC_SUCCESS;

	LOG(dbg, "> argc=%d", argc);

	try {
		for (int i = 0; i<argc; ++i) {
			LOG(dbg, "- argv[%d]=\"%s\"", i, argv[i]);
		}
	}
	catch (error e) { LOG(err, "= exception=%hu", e.get_twrc()); }

	LOG(dbg, "<");
	return twrc;
};