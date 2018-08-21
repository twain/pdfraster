#ifndef _H_PdfRaster_PubSec
#define _H_PdfRaster_PubSec

#ifdef __cplusplus
extern "C" {
#endif

#include "PdfPlatform.h"
#include "openssl/x509.h"

 extern char* encrypt_recipient_message(const char* pub_key_file, char* message, pduint8 message_size, pduint32* out_blob_size, pdbool aesV3);
 extern pdbool decrypt_recipient_message(const char* in_blob, pduint32 in_len, const char* password, char** message, pduint32* message_len);

#ifdef _WIN32
 extern void pubsec_load_certificates_from_store(X509_STORE* x509_store);
#endif
 
#ifdef __cplusplus
}
#endif

#endif // _H_PdfRaster_PubSec
