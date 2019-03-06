// aes_crypter.c - AES encryption/decryption

#include <stdlib.h>
#include <string.h>

#include "aes_crypter.h"
#include "openssl/rand.h"
#include "openssl/evp.h"
#include "openssl/aes.h"

#define IV_LEN 16

pduint32 pdfras_aes_encrypt_data(const unsigned char* key, const pduint32 key_len, const unsigned char* data_in, const pdint32 in_len, unsigned char* data_out) {
    if (data_in == NULL || data_out == NULL)
        return -1;

    unsigned char iv[IV_LEN];
    pdfras_generate_random_bytes(iv, IV_LEN);

    EVP_CIPHER_CTX* cipher = EVP_CIPHER_CTX_new();
    if (!cipher)
        return -1;

    if (key_len <= 16)
        EVP_EncryptInit(cipher, EVP_aes_128_cbc(), key, iv);
    else if (key_len == 32)
        EVP_EncryptInit(cipher, EVP_aes_256_cbc(), key, iv);
    else {
        EVP_CIPHER_CTX_free(cipher);
        return -1;
    }

    memcpy(data_out, iv, IV_LEN);

    int out_len, padded_len;;
    EVP_EncryptUpdate(cipher, data_out + IV_LEN, &out_len, data_in, in_len);
    EVP_EncryptFinal_ex(cipher, data_out + IV_LEN + out_len, &padded_len);

    EVP_CIPHER_CTX_free(cipher);

    return out_len + padded_len;
}

void pdfras_generate_random_bytes(unsigned char* buf, pdint32 buf_len) {
    if (RAND_bytes(buf, buf_len) == 0) {
        // try pseudo random generator
        if (RAND_bytes(buf, buf_len) == 0) {
			pdint32 i;
            // ok, openssl failed to generate random nums
            srand((unsigned int)time(NULL));
            for (i = 0; i < buf_len; ++i) {
                buf[i] = (char)rand();
            }
        }
    }
}

pduint32 pdfras_aes_decrypt_data(const unsigned char* key, const pduint32 key_len, const unsigned char* data_in, const pdint32 in_len, unsigned char* data_out) {
    if (data_in == NULL || data_out == NULL)
        return -1;

    EVP_CIPHER_CTX* cipher = EVP_CIPHER_CTX_new();
    if (!cipher)
        return -1;

    unsigned char iv[IV_LEN];
    memcpy(iv, data_in, IV_LEN);

    if (key_len <= 16)
        EVP_DecryptInit_ex(cipher, EVP_aes_128_cbc(), NULL, key, iv);
    else if (key_len == 32)
        EVP_DecryptInit_ex(cipher, EVP_aes_256_cbc(), NULL, key, iv);
    else {
        EVP_CIPHER_CTX_free(cipher);
        return -1;
    }

    int out_len = 0;
    int len = 0;
    EVP_DecryptUpdate(cipher, data_out, &len, data_in + IV_LEN, in_len - IV_LEN);
    out_len += len;

    EVP_DecryptFinal_ex(cipher, data_out + len, &len);
    out_len += len;

    EVP_CIPHER_CTX_free(cipher);

    return out_len;
}

pduint32 pdfras_aes_decrypt_encryption_key(const unsigned char* key, const pduint32 key_len, const unsigned char* data_in, const pdint32 in_len, unsigned char* data_out) {
    if (data_in == NULL || data_out == NULL)
        return -1;

    if (key_len != 32)
        return -1;

    EVP_CIPHER_CTX* cipher = EVP_CIPHER_CTX_new();

    unsigned char iv[IV_LEN];
    memset(iv, 0, IV_LEN);

    EVP_DecryptInit_ex(cipher, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_set_padding(cipher, 0);

    int out_len = 0;
    int len = 0;
    
    EVP_DecryptUpdate(cipher, data_out, &len, data_in, in_len);
    out_len += len;
    EVP_DecryptFinal_ex(cipher, data_out + len, &len);
    out_len += len;

    EVP_CIPHER_CTX_free(cipher);

    return out_len;
}
