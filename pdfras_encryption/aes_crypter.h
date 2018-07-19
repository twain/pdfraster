#ifndef _H_AESCrypter
#define _H_AESCrypter

#ifdef __cplusplus
extern "C" {
#endif

#include "PdfPlatform.h"

extern pduint32 pdfras_aes_encrypt_data(const char* key, const pduint32 key_len, const char* data_in, const pdint32 in_len, char* data_out);
extern void pdfras_generate_random_bytes(char* buf, pdint32 buf_len);
extern pduint32 pdfras_aes_decrypt_data(const char* key, const pduint32 key_len, const char* data_in, const pdint32 in_len, char* data_out);
extern pduint32 pdfras_aes_decrypt_encryption_key(const char* key, const pduint32 key_len, const char* data_in, const pdint32 in_len, char* data_out);

#ifdef __cplusplus
}
#endif

#endif // _H_AESCrypter
