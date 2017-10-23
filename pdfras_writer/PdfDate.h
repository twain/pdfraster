#ifndef _H_PdfDate
#define _H_PdfDate
#pragma once

#include "PdfAlloc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct t_date t_date;

// Create date from current local time
t_date* pd_date_create_current_localtime(t_pdmempool* inpool);

// Destroy date object
void pd_date_destroy(t_date* date);

// Returns string representation of string in PDF format
char* pd_date_to_pdfstring(t_date* date);

#ifdef __cplusplus
}
#endif
#endif
