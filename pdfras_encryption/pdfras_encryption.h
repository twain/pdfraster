#ifndef _H_PdfRaster_Encryption
#define _H_PdfRaster_Encryption

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
    PDFRAS_PERM_PRINT_DOCUMENT = 0x00000004,
    PDFRAS_PERM_MODIFY_DOCUMENT = 0x00000008,
    PDFRAS_PERM_COPY_FROM_DOCUMENT = 0x00000010,
    PDFRAS_PERM_EDIT_ANNOTS = 0x00000020,
    PDFRAS_PERM_FILL_FORMS = 0x00000100,
    PDFRAS_PERM_ACCESSIBILITY = 0x00000200,
    PDFRAS_PERM_ASSEMBLE_DOCUMENT = 0x00000400,
    PDFRAS_PERM_HIGH_PRINT = 0x00000800
} PDFRAS_PERMS;

typedef struct t_encrypter t_encrypter;

// Creates encrypter
// user_passwd: open password with enabled restrictions on document
// owner_password: password for owner of document. Document withour any restrictions.
// perms: permissions
// algorithm: algorithm used to encrypt of document
// metadata: true for encrypting metadata, otherwise false.
t_encrypter* PDFRASAPICALL pdfr_create_encrypter(const char* user_passwd, const char* owner_passwd, PDFRAS_PERMS perms, PDFRAS_ENCRYPT_ALGORITHM algorithm, pdbool metadata);
typedef t_encrypter* (PDFRASAPICALL *pfn_pdfr_create_encrypter) (const char* owner_passwd, const char* user_passwd, PDFRAS_PERMS perms, PDFRAS_ENCRYPT_ALGORITHM algorithm, pdbool metadata);

// Destroy encrypter
void PDFRASAPICALL pdfr_destroy_encrypter(t_encrypter* encrypter);
typedef void (PDFRASAPICALL *pfn_pdfr_destroy_encrypter) (t_encrypter* encrypter);

// Update object number for actual object to be encrypted
void PDFRASAPICALL pdfr_encrypter_object_number(t_encrypter* encrypter, pduint32 objnum, pduint32 gennum);
typedef void (PDFRASAPICALL *pfn_pdfr_encrypter_object_number) (t_encrypter* encrypter, pduint32 objnum, pduint32 gennum);

// Prepares Encrypt dictionary values
// TODO: rename this function
pdbool PDFRASAPICALL pdfr_encrypter_dictionary_data(t_encrypter* encrypter, const char* document_id, pduint32 id_len);
typedef pdbool(PDFRASAPICALL *pfn_pdfr_encrypter_dictionary_data) (t_encrypter* encrypter, const char* document_id, pduint32 id_len);

// Encrypt data
pdint32 PDFRASAPICALL pdfr_encrypter_encrypt_data(t_encrypter* encrypter, const pduint8* data_in, const pdint32 in_len, pduint8* data_out);
typedef pdint32(PDFRASAPICALL *pfn_pdfr_encrypter_encrypt_data) (t_encrypter* encrypter, const pduint8* data_in, const pdint32 in_len, pduint8* data_out);

// Query functions
pduint8 PDFRASAPICALL pdfr_encrypter_get_V(t_encrypter* encrypter);
typedef pduint8(PDFRASAPICALL *pfn_pdfr_encrypter_get_V) (t_encrypter* encrypter);

pduint32 PDFRASAPICALL pdfr_encrypter_get_key_length(t_encrypter* encrypter);
typedef pduint32(PDFRASAPICALL *pfn_pdfr_encrypter_get_key_length) (t_encrypter* encrypter);

pduint8 PDFRASAPICALL pdfr_encrypter_get_R(t_encrypter* encrypter);
typedef pduint8(PDFRASAPICALL *pfn_pdfr_encrypter_get_R) (t_encrypter* encrypter);

pduint32 PDFRASAPICALL pdfr_encrypter_get_OU_length(t_encrypter* encrypter);
typedef pduint32(PDFRASAPICALL *pfn_pdfr_encrypter_get_OU_length) (t_encrypter* encrypter);

const char* PDFRASAPICALL pdfr_encrypter_get_O(t_encrypter* encrypter);
typedef const char* (PDFRASAPICALL *pfn_pdfr_encrypter_get_O) (t_encrypter* encrypter);

const char* PDFRASAPICALL pdfr_encrypter_get_U(t_encrypter* encrypter);
typedef const char* (PDFRASAPICALL *pfn_pdfr_encrypter_get_U) (t_encrypter* encrypter);

pduint32 PDFRASAPICALL pdfr_encrypter_get_permissions(t_encrypter* encrypter);
typedef pduint32(PDFRASAPICALL *pfn_pdfr_encrypter_get_permissions) (t_encrypter* encrypter);

pdbool PDFRASAPICALL pdfr_encrypter_get_metadata_encrypted(t_encrypter* encrypter);
typedef pdbool(PDFRASAPICALL *pfn_pdfr_encrypter_get_metadata_encrypted) (t_encrypter* encrypter);

PDFRAS_ENCRYPT_ALGORITHM PDFRASAPICALL pdfr_encrypter_get_algorithm(t_encrypter* encrypter);
typedef PDFRAS_ENCRYPT_ALGORITHM(PDFRASAPICALL *pfn_pdfr_encrypter_get_algorithm) (t_encrypter* encrypter);

const char* PDFRASAPICALL pdfr_encrypter_get_OE(t_encrypter* encrypter);
typedef const char* (PDFRASAPICALL pfn_pdfr_encrypter_get_OE) (t_encrypter* encrypter);

const char* PDFRASAPICALL pdfr_encrypter_get_UE(t_encrypter* encrypter);
typedef const char* (PDFRASAPICALL pfn_pdfr_encrypter_get_UE) (t_encrypter* encrypter);

pduint32 PDFRASAPICALL pdfr_encrypter_get_OUE_length(t_encrypter* encrypter);
typedef pduint32(PDFRASAPICALL pfn_pdfr_encrypter_get_OUE_length) (t_encrypter* encrypter);

const char* PDFRASAPICALL pdfr_encrypter_get_Perms(t_encrypter* encrypter);
typedef const char* (PDFRASAPICALL pfn_pdfr_encrypter_get_Perms) (t_encrypter* encrypter);

pduint32 PDFRASAPICALL pdfr_encrypter_get_Perms_length(t_encrypter* encrypter);
typedef pduint32(PDFRASAPICALL pfn_pdfr_encrypter_get_Perms_length) (t_encrypter* encrypter);

#ifdef __cplusplus
}
#endif

#endif // _H_PdfRaster_Encryption
