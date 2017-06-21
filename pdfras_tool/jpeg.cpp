// pdfras_tool  jpeg.cpp

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
#include "handles.h"
#include "jpeg.h"

jpeg::jpeg(string filename)
{
	LOG(dbg, ">");

	string ext(".jpg");
	bool no_ext = filename.substr(filename.length() - ext.length(), ext.length()) != ext;
	ofile.set_name((filename+(no_ext?ext:"")).c_str());

	LOG(dbg, "> opening for writing JPEG filename=\"%s\"", ofile.get_name().c_str());
	ofile.open("wb");

	LOG(dbg, "<");
}

jpeg::~jpeg()
{
	ofile.close();
}

void jpeg::write_body(t_pdfrasreader *reader, int page, int strips, size_t max_strip_size)
{
	LOG(dbg, "> filename=\"%s\"", ofile.get_name().c_str());

	char *rawstrip = new char[max_strip_size];

	for (int s = 0; s < strips; s++) {
		size_t rcvd = pdfrasread_read_raw_strip(reader, page - 1, s, rawstrip, max_strip_size);

		LOG(dbg, "| writing strip=%d size=%zu page=%d max_strip_size=%zu", s, rcvd, page, max_strip_size);

		size_t wrtc = fwrite(rawstrip, rcvd, 1, ofile.get_fp());
		if (wrtc != 1) {
			LOG(err, "| failed writing strip=%d size=%zu page=%d max_strip_size=%zu filename=\"%s\"", s, rcvd, page, max_strip_size, ofile.get_name().c_str());
			ERR(FILE_WRITE_FAIL);
		}
	}

	delete[] rawstrip;
	LOG(dbg, "<");
}