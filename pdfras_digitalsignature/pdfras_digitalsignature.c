// pdfras_digitalsignature.c - function for digital signing of PDF

#include <assert.h>
#include <string.h>

#include "pdfras_digitalsignature.h"

#include "openssl/crypto.h"
#include "openssl/pem.h"
#include "openssl/pkcs12.h"
#include "openssl/err.h"
#include "openssl/md5.h"
#include "openssl/rand.h"
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

struct t_signer {
    EVP_PKEY* digsig_pkey;
    X509* digsig_cert;
};

pdbool static load_certificate(t_signer* signer, const char* file, const char* password) {
    PKCS12* pkcs12 = NULL;
    FILE* pfx_file = NULL;
    STACK_OF(X509)* ca = NULL;

#ifdef _WIN32
    BIO* bio_file = BIO_new_file(file, "rb");
    if (!bio_file)
        return PD_FALSE;

    pkcs12 = d2i_PKCS12_bio(bio_file, NULL);
    BIO_free(bio_file);
#else
    pfx_file = fopen(file, "rb");
    if (!pfx_file)
        return PD_FALSE;

    pkcs12 = d2i_PKCS12_fp(pfx_file, NULL);
    
    fclose(pfx_file);
#endif

    if (!pkcs12)
        return PD_FALSE;

    if (!PKCS12_parse(pkcs12, password, &signer->digsig_pkey, &signer->digsig_cert, &ca)) {
        PKCS12_free(pkcs12);
        return PD_FALSE;
    }

    PKCS12_free(pkcs12);

    return PD_TRUE;
}

t_signer* PDFRASAPICALL pdfr_init_digitalsignature(const char* pfx_file, const char* password) {
    // initialization of OpenSSL
    ERR_load_BIO_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    t_signer* signer = (t_signer*) malloc(sizeof(t_signer));
    signer->digsig_cert = NULL;
    signer->digsig_pkey = NULL;

    if (!load_certificate(signer, pfx_file, password)) {
        pdfr_exit_digitalsignature(signer);
        return NULL;
    }

    return signer;
}

void PDFRASAPICALL pdfr_exit_digitalsignature(t_signer* signer) {
    // OpenSSL clean up
    ERR_free_strings();
    EVP_cleanup();

    assert(signer);
    free(signer);
    signer = NULL;
}

/* returns signature length used by Contents.
   If error ocurred then returns -1.*/
pdint32 pdfr_digsig_signature_length(t_signer* signer) {
    pdint32 ret = -1;
    pduint8 random_buff[10];
    pdint8 random_buff_size = 1;

    BIO* inputbio = BIO_new(BIO_s_mem());
    BIO_write(inputbio, random_buff, random_buff_size);
    
    PKCS7* pkcs7;
    pduint32 flags = PKCS7_DETACHED | PKCS7_BINARY;
    pkcs7 = PKCS7_sign(signer->digsig_cert, signer->digsig_pkey, NULL, inputbio, flags);
    BIO_free(inputbio);

    if (pkcs7) {
        BIO* outputbio = BIO_new(BIO_s_mem());
        i2d_PKCS7_bio(outputbio, pkcs7);

        BUF_MEM* mem = NULL;
        BIO_get_mem_ptr(outputbio, &mem);

        if (mem && mem->data && mem->length)
            ret = (pdint32)mem->length + 20;

        BIO_free(outputbio);
        PKCS7_free(pkcs7);
    }

    return ret;
}

// sign data
pdint32 pdfr_digsig_sign_data(t_signer* signer, const pduint8* input, const pdint32 input_length, pduint8* output, const pduint32 output_length) {
    pdint32 ret = -1;

    BIO* inputbio = BIO_new(BIO_s_mem());
    BIO_write(inputbio, input, input_length);

    PKCS7* pkcs7;
    pduint32 flags = PKCS7_DETACHED | PKCS7_BINARY;
    pkcs7 = PKCS7_sign(signer->digsig_cert, signer->digsig_pkey, NULL, inputbio, flags);
    BIO_free(inputbio);

    if (pkcs7) {
        BIO* outputbio = BIO_new(BIO_s_mem());
        i2d_PKCS7_bio(outputbio, pkcs7);
        
        BUF_MEM* mem = NULL;
        BIO_get_mem_ptr(outputbio, &mem);

        if (mem && mem->data && output_length >= mem->length) {
            ret = mem->length;
            memcpy(output, mem->data, mem->length);
        }

        BIO_free(outputbio);
        PKCS7_free(pkcs7);
    }

    return ret;
}
