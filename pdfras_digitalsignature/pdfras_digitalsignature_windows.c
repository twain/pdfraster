// Windows specific functions
#ifdef _WIN32
#pragma comment(lib, "crypt32.lib")
#endif // _WIN32

#include "pdfras_digitalsignature_windows.h"

#ifdef _WIN32
#include <Windows.h>
#include <wincrypt.h>
#include "openssl/x509.h"

static void load_certs_from_store(X509_STORE* x509_store, const char* name) {
    if (x509_store == NULL)
        return;

    HCERTSTORE store;
    PCCERT_CONTEXT context = NULL;

    // Load from ROOT
    store = CertOpenStore(CERT_STORE_PROV_SYSTEM_A, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, name);
    // system stores
    // including Trust, CA, or Root
    if (store == NULL)
        return;

    X509* x509;
    while (context = CertEnumCertificatesInStore(store, context)) {
        const unsigned char* cert = context->pbCertEncoded;
        x509 = d2i_X509(NULL, &cert, context->cbCertEncoded);

        if (x509) {
            X509_STORE_add_cert(x509_store, x509);
            X509_free(x509);
        }
    }

    CertFreeCertificateContext(context);
    CertCloseStore(store, 0);
}

void digsig_load_certificates_from_store(X509_STORE* x509_store) {
    load_certs_from_store(x509_store, "ROOT");
    load_certs_from_store(x509_store, "MY");
}

#endif // _WIN32
