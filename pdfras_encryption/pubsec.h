#ifndef _H_PdfRaster_PubSec
#define _H_PdfRaster_PubSec

#ifdef __cplusplus
extern "C" {
#endif

#include "PdfPlatform.h"

 extern char* encrypt_recipient_message(const char* pub_key_file, char* message, pduint8 message_size, pduint32* out_blob_size, pdbool aesV3);
 
#ifdef __cplusplus
}
#endif

#endif // _H_PdfRaster_PubSec
