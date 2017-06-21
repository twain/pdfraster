// pdfras_tool   journal.h

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
	void println(char *path, const int line, const char *function, const log_level level, const char *fmt, ...);
};

extern journal g_journal;