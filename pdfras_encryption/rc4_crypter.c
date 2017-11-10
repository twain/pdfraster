// rc4_crypter.c - encrypt/decrypt data using RC4 cipher

#include "rc4_crypter.h"

#include "openssl/rc4.h"

pduint32 pdfras_rc4_encrypt_data(const char* key, const pduint32 key_len, const char* data_in, const pdint32 in_len, char* data_out) {
    if (data_in == NULL || data_out == NULL)
        return -1;

    RC4_KEY rc4_key;
    RC4_set_key(&rc4_key, key_len, key);

    RC4(&rc4_key, in_len, data_in, data_out);

    return in_len;
}
