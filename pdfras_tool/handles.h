// pdfras_tool  handles.h

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

class file {
private:
	FILE *fp;
	string name;
public:
	file() { fp = nullptr;  }
	~file() { if (fp) fclose(fp); }

	FILE* get_fp() const { return fp; }

	string get_name() const { return name; };
	void set_name(const char *a_name) { name = a_name; };

	void readable() {
		LOG(dbg, "> file=\"%s\"", name.c_str());
		bool is_readable = (ACCESS(name.c_str(), ACCESS_READ) == 0) ? true : false;
		if (!is_readable) {
			LOG(err, "| file not found or not readable \"%s\"", name.c_str());
			ERR(FILE_NOT_READABLE);
		}
		LOG(dbg, "<");
	}

	void open(const char *mode) {
		LOG(dbg, "> file=\"%s\" mode=\"%s\"", name.c_str(), mode);
		fp = fopen(name.c_str(), mode);
		if (nullptr == fp) {
			char *mode_desc = "";
			switch (mode[0]) {
			case 'a': mode_desc = "for appending"; break;
			case 'r': mode_desc = "for reading"; break;
			case 'w': mode_desc = "for writing"; break;
			}
			LOG(err, "| unable to fopen \"%s\" %s", name.c_str(), mode_desc);
			switch (mode[0]) {
			case 'a': ERR(FILE_OPEN_APPEND_FAIL); break;
			case 'r': ERR(FILE_OPEN_READ_FAIL); break;
			case 'w': ERR(FILE_OPEN_WRITE_FAIL); break;
			}
		}
		LOG(dbg, "<");
	}

	void close()
	{
		LOG(dbg, "> file=\"%s\"", name.c_str());
		if (fp != nullptr) {
			if (fclose(fp)) {
				LOG(err, "| error closing file \"%s\"", name.c_str());
				ERR(FILE_CLOSE_FAIL);
			}
			fp = nullptr;
		}
		LOG(dbg, "<");
	}
};

class handles {
private:
	t_pdfrasreader *reader;
public:
	file ifile, ofile;

	handles() { reader = nullptr; }
	~handles() {if (reader) pdfrasread_destroy(reader); }

	t_pdfrasreader* get_reader() const { return reader; }
	void set_reader(t_pdfrasreader* r) { reader = r; }
};