#ifndef _H_PdfRaster_DigitalSignature
#define _H_PdfRaster_DigitalSignature

#ifdef __cplusplus
extern "C" {
#endif

#include "PdfPlatform.h"

#define DS_DOC_NOT_CHANGED      0x1 // Document has not been changed
#define DS_CERT_VERIFIED        0x2 // Certificate has been verified

#define PDFR_DOC_WAS_NOT_CHANGED(x) (((x) & DS_DOC_NOT_CHANGED) == DS_DOC_NOT_CHANGED)
#define PDFR_CERT_VERIFIED(x) (((x) & DS_CERT_VERIFIED) == DS_CERT_VERIFIED)

typedef struct t_signer t_signer;
typedef struct t_digitalsignature t_digitalsignature;

// Initiliaze digital signature module
// return: t_digitalsignature object
t_digitalsignature* PDFRASAPICALL pdfr_init_digitalsignature(); //const char* pfx_file, const char* password);
typedef t_digitalsignature* (PDFRASAPICALL *pfn_pdfr_init_digitalsignature) (); //const char* pfx_file, const char* password);

// Create digital signature signer object
// ds: t_digitalsignature object
// pfx_file: PFX file with certificate
// password: password for certificate
pdbool PDFRASAPICALL pdfr_digitalsignature_create_signer(t_digitalsignature* ds, const char* pfx_file, const char* password);
typedef pdbool (PDFRASAPICALL *pfn_pdfr_digitalsignature_create_signer) (t_digitalsignature* ds, const char* pfx_file, const char* password);

// Called at the end of working with digital signature module
void PDFRASAPICALL pdfr_exit_digitalsignature(t_digitalsignature* ds);
typedef void (PDFRASAPICALL *pfn_pdfr_exit_digitalsignature) (t_digitalsignature* ds);

// Computes digital signature lenght for Contents entry 
pdint32 PDFRASAPICALL pdfr_digsig_signature_length(t_digitalsignature* ds);
typedef pdint32(PDFRASAPICALL *pfn_pdfr_digsig_signature_length) (t_digitalsignature* ds);

// Validate PDF content
pdint32 PDFRASAPICALL pdfr_digitalsignature_validate(t_digitalsignature* ds, const pduint8* pkcs7, const pduint32 pkcs7_len, const pduint8* bytes, const pduint32 bytes_len);
typedef pdint32 (PDFRASAPICALL pfn_pdfr_digitalsignature_validate) (t_digitalsignature* ds, const pduint8* pkcs7, const pduint32 pkcs7_len, const pduint8* bytes, const pduint32 bytes_len);

// Sign data with certificate
// ds: t_digitalsignature object
// input: input buffer to be signed
// input_length: size of input buffer
// output: signed data value (must be allocated by caller)
// output_length: size of buffer for signed data. 
//                If it smaller than signed data computed in function than function will return -1.
pdint32 PDFRASAPICALL pdfr_digsig_sign_data(t_digitalsignature* ds, const pduint8* input, const pdint32 input_length, pduint8* output, const pduint32 output_length);
typedef pdint32(PDFRASAPICALL *pfn_pdfr_digisig_sign_data) (t_digitalsignature* ds, const pduint8* input, const pdint32 input_length, const pduint8* output, const pduint32 output_length);

#ifdef __cplusplus
}
#endif
#endif
