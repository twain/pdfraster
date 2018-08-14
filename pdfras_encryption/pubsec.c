// pubsec_utils.c: function needed by public security
#include "pubsec.h"

#include "openssl/crypto.h"
#include "openssl/pem.h"
#include "openssl/err.h"
#include "openssl/bio.h"
#include "openssl/err.h"
#include "openssl/cms.h"

#include <string.h>

// returned X509 cert must be freed by X509_free()
static X509* load_public_key_cert(const char* pub_key_file) {
    BIO* fileBIO = NULL;
    X509* pubKeyCert = NULL;

    fileBIO = BIO_new_file(pub_key_file, "rb");
    if (!fileBIO)
        return NULL;

    pubKeyCert = PEM_read_bio_X509(fileBIO, NULL, NULL, NULL);
    if (!pubKeyCert)
        pubKeyCert = d2i_X509_bio(fileBIO, NULL);

    BIO_free_all(fileBIO);

    return pubKeyCert;
}

char* encrypt_recipient_message(const char* pub_key_file, char* message, pduint8 message_size, pduint32* out_blob_size, pdbool aesV3) {
    if (!pub_key_file)
        return NULL;

    pdbool error = PD_FALSE;
    X509* pub_key_cert = NULL;
    STACK_OF(X509)* stack_certs = NULL;

    BIO* messageBIO = BIO_new(BIO_s_mem());
    if (!messageBIO) {
        return NULL;
    }
    BIO_write(messageBIO, message, message_size);

    pub_key_cert = load_public_key_cert(pub_key_file);
    if (!pub_key_cert)
        error = PD_TRUE;

    if (!error) {
        stack_certs = sk_X509_new_null();
        if (!stack_certs) {
            error = PD_TRUE;
        }
    }

    if (!error) {
        if (!sk_X509_push(stack_certs, pub_key_cert)) {
            error = PD_TRUE;
        }
    }

    char* blob = NULL;
    if (!error) {
        CMS_ContentInfo* cms = NULL; 
        if (aesV3)
            cms = CMS_encrypt(stack_certs, messageBIO, EVP_aes_256_cbc(), CMS_BINARY);
        else
            cms = CMS_encrypt(stack_certs, messageBIO, EVP_aes_128_cbc(), CMS_BINARY);

        if (!cms)
            error = PD_TRUE;

        BIO* cmsBIO = BIO_new(BIO_s_mem());
        i2d_CMS_bio(cmsBIO, cms);
        BIO_flush(cmsBIO);

        BUF_MEM* mem = NULL;
        BIO_get_mem_ptr(cmsBIO, &mem);

        if (mem && mem->data) {
            blob = (char*)malloc(sizeof(char) * mem->length);
            if (out_blob_size)
                *out_blob_size = (pduint32)mem->length;

            memcpy(blob, mem->data, mem->length);
        }

        BIO_free(cmsBIO);
        CMS_ContentInfo_free(cms);
    }


    if (pub_key_cert)
        X509_free(pub_key_cert);
    if (stack_certs)
        sk_X509_free(stack_certs);
    if (messageBIO)
        BIO_free_all(messageBIO);

    return blob;
}
