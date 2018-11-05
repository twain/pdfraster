// rc4_crypter.c - encrypt/decrypt data using RC4 cipher

#include "rc4_crypter.h"

#include "openssl/rc4.h"

pduint32 pdfras_rc4_encrypt_data(const unsigned char* key, const pduint32 key_len, const unsigned char* data_in, const pdint32 in_len, unsigned char* data_out) {
    if (data_in == NULL || data_out == NULL)
        return -1;

    RC4_KEY rc4_key;
    RC4_set_key(&rc4_key, key_len, key);

    RC4(&rc4_key, in_len, data_in, data_out);

    return in_len;
}

pduint32 pdfras_rc4_decrypt_data(const unsigned char* key, const pduint32 key_len, const unsigned char* data_in, const pdint32 in_len, unsigned char* data_out) {
    return pdfras_rc4_encrypt_data(key, key_len, data_in, in_len, data_out);
}
