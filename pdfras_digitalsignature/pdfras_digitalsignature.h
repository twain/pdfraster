#ifndef _H_PdfRaster_DigitalSignature
#define _H_PdfRaster_DigitalSignature

#ifdef __cplusplus
extern "C" {
#endif

#include "PdfPlatform.h"

typedef struct t_signer t_signer;

// Initiliaze digital signature module
// pfx_file: PFX file with certificate
// password: password for certificate
t_signer* PDFRASAPICALL pdfr_init_digitalsignature(const char* pfx_file, const char* password);
typedef t_signer* (PDFRASAPICALL *pfn_pdfr_init_digitalsignature) (const char* pfx_file, const char* password);

// Called at the end of working with digital signature module
void PDFRASAPICALL pdfr_exit_digitalsignature(t_signer* signer);
typedef void (PDFRASAPICALL *pfn_pdfr_exit_digitalsignature) (t_signer* signer);

// Computes digital signature lenght for Contents entry 
pdint32 PDFRASAPICALL pdfr_digsig_signature_length(t_signer* signer);
typedef pdint32(PDFRASAPICALL *pfn_pdfr_digsig_signature_length) (t_signer* signer);

// Sign data with certificate
// signer: certificate data
// input: input buffer to be signed
// input_length: size of input buffer
// output: signed data value (must be allocated by caller)
// output_length: size of buffer for signed data. 
//                If it smaller than signed data computed in function than function will return -1.
pdint32 PDFRASAPICALL pdfr_digsig_sign_data(t_signer* signer, const pduint8* input, const pdint32 input_length, pduint8* output, const pduint32 output_length);
typedef pdint32(PDFRASAPICALL *pfn_pdfr_digisig_sign_data) (t_signer* signer, const pduint8* input, const pdint32 input_length, const pduint8* output, const pduint32 output_length);

#ifdef __cplusplus
}
#endif
#endif
