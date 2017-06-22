// pdfras_tool   os_specific.h

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

#if defined(WIN32) || defined(WIN64) || defined (_WINDOWS)
#  define COMPILING_FOR_WIN_MSVC
#else
#  undef  COMPILING_FOR_WIN_MSVC
#endif

#if defined(WIN32) || defined(WIN64) || defined (_WINDOWS)
#  define COMPILING_FOR_WIN
#else
#  undef  COMPILING_FOR_WIN
#endif

#ifdef COMPILING_FOR_WIN_MSVC
#	define STRICMP _stricmp
#	define ACCESS _access
#	define ACCESS_READ 04
#else
#	define STRICMP stricmp
#	define ACCESS access
#	define ACCESS_READ R_OK
#endif