#ifndef _H_Rc4Crypter
#define _H_Rc4Crypter

#ifdef __cplusplus
extern "C" {
#endif

#include "PdfPlatform.h"

extern pduint32 pdfras_rc4_encrypt_data(const char* key, const pduint32 key_len, const char* data_in, const pdint32 in_len, char* data_out);

#ifdef __cplusplus
}
#endif

#endif // _H_Rc4Crypter
