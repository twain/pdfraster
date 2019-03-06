#ifndef _H_Rc4Crypter
#define _H_Rc4Crypter

#ifdef __cplusplus
extern "C" {
#endif

#include "PdfPlatform.h"

extern pduint32 pdfras_rc4_encrypt_data(const unsigned char* key, const pduint32 key_len, const unsigned char* data_in, const pdint32 in_len, unsigned char* data_out);
extern pduint32 pdfras_rc4_decrypt_data(const unsigned char* key, const pduint32 key_len, const unsigned char* data_in, const pdint32 in_len, unsigned char* data_out);

#ifdef __cplusplus
}
#endif

#endif // _H_Rc4Crypter
