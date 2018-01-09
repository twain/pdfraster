#ifndef _H_PdfDigitalSignature
#define _H_PdfDigitalSignature

#ifdef __cplusplus
extern "C" {
#endif

#include "PdfRaster.h"
#include "PdfPlatform.h"

typedef struct t_pdfdigitalsignature t_pdfdigitalsignature;

// Initialize digital signature and return its object
// encoder - t_pdfrasencoder
// pfx_file - pfx file with certificate
// password - password for certificate
t_pdfdigitalsignature* digitalsignature_create(t_pdfrasencoder* encoder, const char* pfx_file, const char* password);

// finish process of signing
void digitalsignature_finish(t_pdfdigitalsignature* signature);

// Close digital signature (destroy). Call it at the end of digital signing process.
void digitalsignature_destroy(t_pdfdigitalsignature* signature);

// Create needed dictionaries
void digitalsignature_create_dictionaries(t_pdfdigitalsignature* signature);

// Set page containing signature
void digitalsignature_set_page(t_pdfdigitalsignature* signature, t_pdvalue page);

// was signature written into output
pdbool digitalsignature_written(t_pdfdigitalsignature* signature);

// internal handler for writer
int digitalsignature_writer(const pduint8* data, pduint32 offset, pduint32 len, void* cookie);

// get digital signature dictionary object number
extern pduint32 pd_digitalsignature_digsig_objnum(t_pdfdigitalsignature* signature);

#ifdef __cplusplus
}
#endif
#endif
