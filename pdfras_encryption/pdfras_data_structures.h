#ifndef _H_PdfRaster_DataStructures
#define _H_PdfRaster_DataStructures

#ifdef __cplusplus
extern "C" {
#endif

#include "PdfPlatform.h"

    typedef enum {
        PDFRAS_RC4_40,   // RC4 with encryption key length of 40 bits
        PDFRAS_RC4_128,  // RC4 with ecnryption key length of 128 bits
        PDFRAS_AES_128,  // AES with encryption key length of 128 bits
        PDFRAS_AES_256,  // AES with encryption key lenght of 256 bits
        PDFRAS_UNDEFINED_ENCRYPT_ALGORITHM
    } PDFRAS_ENCRYPT_ALGORITHM;

    typedef enum {
        PDFRAS_PERM_UNKNOWN = 0x00000000,
        PDFRAS_PERM_PRINT_DOCUMENT = 0x00000004,
        PDFRAS_PERM_MODIFY_DOCUMENT = 0x00000008,
        PDFRAS_PERM_COPY_FROM_DOCUMENT = 0x00000010,
        PDFRAS_PERM_EDIT_ANNOTS = 0x00000020,
        PDFRAS_PERM_FILL_FORMS = 0x00000100,
        PDFRAS_PERM_ACCESSIBILITY = 0x00000200,
        PDFRAS_PERM_ASSEMBLE_DOCUMENT = 0x00000400,
        PDFRAS_PERM_HIGH_PRINT = 0x00000800,
        PDFRAS_PERM_ALL = (0x00000004 | 0x00000008 | 0x00000010 | 0x00000020 | 0x00000100 | 0x00000200 | 0x00000400 | 0x00000800),
    } PDFRAS_PERMS;

    typedef enum {
        PDFRAS_DOCUMENT_NONE_ACCESS,      // None access to the document
        PDFRAS_DOCUMENT_USER_ACCESS,      // User access to the document
        PDFRAS_DOCUMENT_OWNER_ACCESS      // Owner access to the document (full access)
    } PDFRAS_DOCUMENT_ACCESS;

    typedef struct t_encrypter t_encrypter;
    typedef struct t_encrypter t_decrypter;

    // Used by pubsec security.
    // Defines recipient (contains only encrypted blob for /Recipients in encrypt dictionary)
    struct t_recipient {
        char* pkcs7_blob;
        pduint32 pkcs7_blob_size;
        struct t_recipient* next;
    };

    typedef struct t_recipient t_recipient;

    typedef struct {
        PDFRAS_ENCRYPT_ALGORITHM algorithm;
        PDFRAS_PERMS perms;
        char* O;
        char* U;
        char* OE;
        char* UE;
        char* Perms;
        char* document_id;
        pduint32 OU_length;
        pduint32 OUE_length;
        pduint32 Perms_length;
        pduint32 document_id_length;
        pduint8 R;
        pduint8 V;
        pduint8 encryption_key_length;
        pdbool encrypt_metadata;
    } RasterReaderEncryptData;

#ifdef __cplusplus
}
#endif

#endif // _H_PdfRaster_DataStructures
