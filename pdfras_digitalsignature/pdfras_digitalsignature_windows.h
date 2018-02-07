// Windows specifi functions
#ifndef _H_PdfRaster_DigitalSignature_Windows
#define _H_PdfRaster_DigitalSignature_Windows

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32

#include "pdfras_digitalsignature.h"
#include "openssl/x509.h"

void digsig_load_certificates_from_store(X509_STORE* x509_store);

#endif // _WIN32

#ifdef __cplusplus
}
#endif
#endif
