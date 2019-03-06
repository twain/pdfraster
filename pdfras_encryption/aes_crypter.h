#ifndef _H_AESCrypter
#define _H_AESCrypter

#ifdef __cplusplus
extern "C" {
#endif

#include "PdfPlatform.h"

extern pduint32 pdfras_aes_encrypt_data(const unsigned char* key, const pduint32 key_len, const unsigned char* data_in, const pdint32 in_len, unsigned char* data_out);
extern void pdfras_generate_random_bytes(unsigned char* buf, pdint32 buf_len);
extern pduint32 pdfras_aes_decrypt_data(const unsigned char* key, const pduint32 key_len, const unsigned char* data_in, const pdint32 in_len, unsigned char* data_out);
extern pduint32 pdfras_aes_decrypt_encryption_key(const unsigned char* key, const pduint32 key_len, const unsigned char* data_in, const pdint32 in_len, unsigned char* data_out);

#ifdef __cplusplus
}
#endif

#endif // _H_AESCrypter
