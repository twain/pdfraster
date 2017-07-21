// pdfras_tool   journal.h

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

enum log_level {none,err,warn,msg,info,dbg};

#define LOG(level,fmt,...) \
	(g_journal.println(__FILE__,__LINE__,__FUNCTION__,(level),(fmt),##__VA_ARGS__))

#define B2PC(b) ((b)?"True":"False")

using std::cerr;
using std::ostream;

class journal {
private:
	log_level lvl;
	ostream *os;
	unsigned line_count;
public:
	journal(ostream *s=&cerr);

	void set_ostream(ostream *s=&cerr)    { os = s; }
	void set_level(log_level level=none) { lvl = level; }

	log_level get_level()   const { return lvl; }
	ostream  *get_ostream() const { return  os; }

	// DO NOT call log_println() directly, ONLY use the macro LOG(level,fmt,...)
	void println(const char *path, const int line, const char *function, const log_level level, const char *fmt, ...);
};

extern journal g_journal;