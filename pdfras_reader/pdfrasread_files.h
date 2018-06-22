#ifndef _H_pdfras_files
#define _H_pdfras_files
#pragma once

#include "pdfrasread.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

// Return TRUE if the file is marked as a PDF/raster file.
// FALSE otherwise.
int PDFRASAPICALL pdfrasread_recognize_file(FILE* f);
typedef int (PDFRASAPICALL *pfn_pdfrasread_recognize_file)(FILE* f);

// Return TRUE if the file is marked as a PDF/raster file.
// FALSE otherwise.
int PDFRASAPICALL pdfrasread_recognize_filename(const char* fn);
typedef int (PDFRASAPICALL *pfn_pdfrasread_recognize_filename)(const char* fn);

int PDFRASAPICALL pdfrasread_page_count_file(FILE* f);
int PDFRASAPICALL pdfrasread_page_count_filename(const char* fn);
typedef int (PDFRASAPICALL *pfn_pdfrasread_page_count_file)(FILE* f);
typedef int (PDFRASAPICALL *pfn_pdfrasread_page_count_filename)(const char* fn);

// create a PDF/raster reader and use it to access a FILE
t_pdfrasreader* PDFRASAPICALL pdfrasread_open_file(int apiLevel, FILE* f);
typedef t_pdfrasreader* (PDFRASAPICALL *pfn_pdfrasread_open_file)(int apiLevel, FILE* f);

// create a PDF/raster reader and use it to access a FILE protected by password
t_pdfrasreader* PDFRASAPICALL pdfrasread_open_file_secured(int apiLevel, FILE* f, const char* password);
typedef t_pdfrasreader* (PDFRASAPICALL *pfn_pdfrasread_open_file_secured)(int apiLevel, FILE* f, const char* password);

// create a PDF/raster reader and use it to open a named file
t_pdfrasreader* PDFRASAPICALL pdfrasread_open_filename(int apiLevel, const char* fn);
typedef t_pdfrasreader* (PDFRASAPICALL *pfn_pdfrasread_open_filename)(int apiLevel, const char* fn);

// create a PDF/raster reader and use it to open a named file protected by password
t_pdfrasreader* PDFRASAPICALL pdfrasread_open_filename_secured(int apiLevel, const char* fn, const char* password);
typedef t_pdfrasreader* (PDFRASAPICALL *pfn_pdfrasread_open_filename_secured)(int apiLevel, const char* fn, const char* password);

// return security type used by document
RasterReaderSecurityType PDFRASAPICALL pdfrasread_get_security_type_filename(const char* filename);
typedef RasterReaderSecurityType(PDFRASAPICALL *pfn_pdfrasread_get_security_type_filename)(const char* filename);

#ifdef __cplusplus
}
#endif
#endif
