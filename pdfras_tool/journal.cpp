// journal.c

// DO NOT call any of the functions in journal.c directly
// ONLY use the macros in journal.h

#include <iomanip>
#include <iostream>

#include <time.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

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

journal g_journal(&cerr);

journal::journal(ostream *s)
{
  os = s;
  line_count = 0;

  char *level = getenv("PDFRAS_TOOL_DEBUG");
  if (level && (!STRICMP(level, "err") || !STRICMP(level, "err"))) {
	  lvl = err;
  }
  else if (level && (!STRICMP(level, "warn") || !STRICMP(level, "warning"))) {
	  lvl = warn;
  }
  else if (level && (!STRICMP(level, "msg") || !STRICMP(level, "message"))) {
	  lvl = msg;
  }
  else if (level && (!STRICMP(level, "info") || !STRICMP(level, "information"))) {
	  lvl = info;
  }
  else if (level && (!STRICMP(level, "dbg") || !STRICMP(level, "debug"))) {
	  lvl = dbg;
  }
  else {
	  lvl = none;
  }
}

#if defined(COMPILING_FOR_WIN)
#  define FILE_SEPARATOR '\\'
#else
#  define FILE_SEPARATOR '/'
#endif

static char *find_file_in_path(char *path)
{
  char *p = strrchr(path,FILE_SEPARATOR);
  return p ? p+1 : path;
}

using std::setw;
void journal::println(char *path, const int line, const char *function, const log_level level, const char *fmt, ...)
{
	if (level > lvl) return;

	time_t t = time(0);   // get time now
	struct tm * now = localtime(&t);

	if (!line_count++) {
		if (level >= dbg) {
			char tbuf[11];
			strftime(tbuf, sizeof(tbuf), "%Y/%m/%d", now);//if change format string, adjust sizeof tbuf decl on prior line
			println(__FILE__, __LINE__, __FUNCTION__, level, "%s %s %s log_level=%d (built %s at %s)", app_name.c_str(), app_version.c_str(), tbuf, lvl, __DATE__, __TIME__);
		}
	}

	char tbuf[6];
	strftime(tbuf, sizeof(tbuf), "%M:%S", now);//if change format string, adjust sizeof tbuf decl on prior line

	char level_ch;
	switch (level) {
	case  none: level_ch = 'N'; break;
	case  err: level_ch = 'E'; break;
	case  warn: level_ch = 'W'; break;
	case  msg: level_ch = 'M'; break;
	case  info: level_ch = 'I'; break;
	case  dbg:
	default: level_ch = 'D'; break;
	}

	*os << tbuf;
	*os << " " << find_file_in_path(path);
	*os << setw(5) << line;
	*os << " " << level_ch;
	*os << " " << function << "()";
	*os << " ";
  
	va_list args;
	va_start(args,fmt);

	const int buf_len_max = 1024;
 
	int buf_len = vsnprintf(0,0,fmt,args);
	assert((buf_len>0)&&(buf_len<=buf_len_max));

	int buf_size = buf_len + 1;
	char *buf = new char[buf_size + 1];

	int rv = vsnprintf(buf,buf_size,fmt,args);
	assert(rv==buf_len);

	va_end(args);

	*os << buf << endl;
	delete [] buf;
}