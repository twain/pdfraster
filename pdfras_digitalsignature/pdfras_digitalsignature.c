// pdfras_digitalsignature.c - function for digital signing of PDF

#include <assert.h>
#include <string.h>

#include "pdfras_digitalsignature.h"
#ifdef _WIN32
#include "pdfras_digitalsignature_windows.h"
#endif // _WIN32

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

struct t_digitalsignature {
    struct t_signer* signer;
    X509_STORE* cert_store;
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

t_digitalsignature* PDFRASAPICALL pdfr_init_digitalsignature() {
    // initialization of OpenSSL
    ERR_load_BIO_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    t_digitalsignature* ds = (t_digitalsignature*)malloc(sizeof(t_digitalsignature));
    ds->signer = NULL;
    ds->cert_store = X509_STORE_new();

    return ds;
}

pdbool PDFRASAPICALL pdfr_digitalsignature_create_signer(t_digitalsignature* ds, const char* pfx_file, const char* password) {
    assert(ds);

    if (ds->signer)
        free(ds->signer);

    ds->signer = (t_signer*) malloc(sizeof(t_signer));
    ds->signer->digsig_cert = NULL;
    ds->signer->digsig_pkey = NULL;

    if (!load_certificate(ds->signer, pfx_file, password)) {
        free(ds->signer);
        ds->signer = NULL;

        return PD_FALSE;
    }

    return PD_TRUE;
}

void PDFRASAPICALL pdfr_exit_digitalsignature(t_digitalsignature* ds) {
    // OpenSSL clean up
    ERR_free_strings();
    EVP_cleanup();

    assert(ds);
    
    if (ds->signer) {
        free(ds->signer);
        ds->signer = NULL;
    }

    if (ds->cert_store) {
        X509_STORE_free(ds->cert_store);
        ds->cert_store = NULL;
    }

    free(ds);
    ds = NULL;
}

/* returns signature length used by Contents.
   If error ocurred then returns -1.*/
pdint32 pdfr_digsig_signature_length(t_digitalsignature* ds) {
    assert(ds);
    assert(ds->signer);

    pdint32 ret = -1;
    pduint8 random_buff[10];
    pdint8 random_buff_size = 1;

    BIO* inputbio = BIO_new(BIO_s_mem());
    BIO_write(inputbio, random_buff, random_buff_size);
    
    PKCS7* pkcs7;
    pduint32 flags = PKCS7_DETACHED | PKCS7_BINARY;
    pkcs7 = PKCS7_sign(ds->signer->digsig_cert, ds->signer->digsig_pkey, NULL, inputbio, flags);
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
pdint32 pdfr_digsig_sign_data(t_digitalsignature* ds, const pduint8* input, const pdint32 input_length, pduint8* output, const pduint32 output_length) {
    assert(ds);
    assert(ds->signer);

    pdint32 ret = -1;

    BIO* inputbio = BIO_new(BIO_s_mem());
    if (inputbio == NULL)
        return ret;

    BIO_write(inputbio, input, input_length);

    PKCS7* pkcs7;
    pduint32 flags = PKCS7_DETACHED | PKCS7_BINARY;
    pkcs7 = PKCS7_sign(ds->signer->digsig_cert, ds->signer->digsig_pkey, NULL, inputbio, flags);
    BIO_free(inputbio);

    if (pkcs7) {
        BIO* outputbio = BIO_new(BIO_s_mem());
        i2d_PKCS7_bio(outputbio, pkcs7);
        
        BUF_MEM* mem = NULL;
        BIO_get_mem_ptr(outputbio, &mem);

        if (mem && mem->data && output_length >= mem->length) {
            ret = (pdint32)mem->length;
            memcpy(output, mem->data, mem->length);
        }

        BIO_free(outputbio);
        PKCS7_free(pkcs7);
    }

    return ret;
}

// validate data
pdint32 pdfr_digitalsignature_validate(t_digitalsignature* ds, const pduint8* pkcs7, const pduint32 pkcs7_len, const pduint8* bytes, const pduint32 bytes_len) {
    pduint32 ret = 0;

    BIO* pkcs7Bio = BIO_new(BIO_s_mem());
    if (pkcs7Bio == NULL)
        return ret;

    BIO_write(pkcs7Bio, pkcs7, pkcs7_len);    
    
    PKCS7* p7 = d2i_PKCS7_bio(pkcs7Bio, NULL);
    if (p7 == NULL) {
        BIO_free(pkcs7Bio);
        return ret;
    }

    BIO* inDataBio = BIO_new(BIO_s_mem());
    if (inDataBio == NULL) {
        BIO_free(pkcs7Bio);
        PKCS7_free(p7);
        return ret;
    }

    BIO_write(inDataBio, bytes, bytes_len);

#ifdef _WIN32
    digsig_load_certificates_from_store(ds->cert_store);
#endif // _WIN32

    if (PKCS7_verify(p7, NULL, ds->cert_store, inDataBio, NULL, 0) == 1) {
        ret |= DS_DOC_NOT_CHANGED;
        ret |= DS_CERT_VERIFIED;
    }
    else {
        if (PKCS7_verify(p7, NULL, ds->cert_store, inDataBio, NULL, PKCS7_NOVERIFY) == 1) {
            ret |= DS_DOC_NOT_CHANGED;
        }
    }

    BIO_free(pkcs7Bio);
    BIO_free(inDataBio);
    PKCS7_free(p7);
    
    return ret;
}
