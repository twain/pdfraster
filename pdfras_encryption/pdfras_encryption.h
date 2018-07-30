#ifndef _H_PdfRaster_Encryption
#define _H_PdfRaster_Encryption

#ifdef __cplusplus
extern "C" {
#endif

#include "PdfPlatform.h"
#include "pdfras_data_structures.h"

 struct RasterPubSecRecipient {
     const char* pubkey;
     PDFRAS_PERMS perms;
 };

 typedef struct RasterPubSecRecipient RasterPubSecRecipient;

// Creates encrypter for password security
// user_passwd: open password with enabled restrictions on document
// owner_password: password for owner of document. Document withour any restrictions.
// perms: permissions
// algorithm: algorithm used to encrypt of document
// metadata: true for encrypting metadata, otherwise false.
t_encrypter* PDFRASAPICALL pdfr_create_encrypter(const char* user_passwd, const char* owner_passwd, PDFRAS_PERMS perms, PDFRAS_ENCRYPT_ALGORITHM algorithm, pdbool metadata);
typedef t_encrypter* (PDFRASAPICALL *pfn_pdfr_create_encrypter) (const char* owner_passwd, const char* user_passwd, PDFRAS_PERMS perms, PDFRAS_ENCRYPT_ALGORITHM algorithm, pdbool metadata);

// Creates encrypter for public key security
// recipients: array of recipients (each recipient has own public key and permissions)
// recipients_count: number of recipients in the first param.
// algorithm: algorithm used to encrypt of document
// metadata: true for encrypting metadata, otherwise false.
t_encrypter* PDFRASAPICALL pdfr_create_pubsec_encrypter(const RasterPubSecRecipient* recipients, size_t recipients_count, PDFRAS_ENCRYPT_ALGORITHM algorithm, pdbool metadata);
typedef t_encrypter* (PDFRASAPICALL *pfn_create_pubsec_encrypter)(const RasterPubSecRecipient* recipients, size_t recipients_count, PDFRAS_ENCRYPT_ALGORITHM algorithm, pdbool metdata);

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

pdbool PDFRASAPICALL pdfr_encrypter_is_password_security(t_encrypter* encrypter);
typedef pdbool(PDFRASAPICALL pfn_pdfr_encrypter_is_password_security) (t_encrypter* encrypter);

pduint32 PDFRASAPICALL pdfr_encrypter_pubsec_recipients_count(t_encrypter* encrypter);
typedef pduint32(PDFRASAPICALL pfn_pdfr_encrypter_pubsec_recipients_count) (t_encrypter* encrypter);

const char* PDFRASAPICALL pdfr_encrypter_pubsec_recipient_pkcs7(t_encrypter* encrypter, pduint32 idx, pduint32* pkcs7_size);
typedef const char* (PDFRASAPICALL pfn_pdfr_encrypter_pubsec_recipient_pkcs7) (t_encrypter* encrypter, pduint32 idx, pduint32* pkcs7_size);

// Decryption
// Creates decrypter used for authentification of user and decryption of encrypted file.
// encrypt_data: encryption data extracted from /Encrypt dictionary
t_decrypter* PDFRASAPICALL pdfr_create_decrypter(const RasterReaderEncryptData* encrypt_data);
typedef t_decrypter* (PDFRASAPICALL *pfn_pdfr_create_decrypter) (const RasterReaderEncryptData* encrypt_data);

// Destroy decrypter object.
void PDFRASAPICALL pdfr_destroy_decrypter(t_decrypter* decrypter);
typedef void (PDFRASAPICALL *pfn_pdfr_destroy_decrypter)(t_decrypter* decrypter);

// Authentificate and authorize user for opening document.
PDFRAS_DOCUMENT_ACCESS PDFRASAPICALL pdfr_decrypter_get_document_access(t_decrypter* decrypter, const char* password);
typedef PDFRAS_DOCUMENT_ACCESS(PDFRASAPICALL pfn_pdfr_decrypter_get_document_access)(t_decrypter* decrypter, const char* password);

// Decrypt data
pdint32 PDFRASAPICALL pdfr_decrypter_decrypt_data(t_decrypter* decrypter, const pduint8* data_in, const pdint32 in_len, pduint8* data_out);
typedef pduint32(PDFRASAPICALL pfn_pdfr_decrypter_decrypt_data) (t_decrypter* decrypter, const pduint8* data_in, const pdint32 in_len, pduint8* data_out);

// Algorithm used in encrypted document
PDFRAS_ENCRYPT_ALGORITHM PDFRASAPICALL pdfr_decrypter_get_algorithm(t_decrypter* decrypter);
typedef PDFRAS_ENCRYPT_ALGORITHM(PDFRASAPICALL *pfn_pdfr_decrypter_get_algorithm) (t_decrypter* decrypter);

// Update object number for actual object to be decrypted
void PDFRASAPICALL pdfr_decrypter_object_number(t_decrypter* decrypter, pduint32 objnum, pduint32 gennum);
typedef void (PDFRASAPICALL *pfn_pdfr_decrypter_object_number) (t_decrypter* decrypter, pduint32 objnum, pduint32 gennum);

// Check if metadata are encrypted
pdbool PDFRASAPICALL pdfr_decrypter_get_metadata_encrypted(t_decrypter* decrypter);
typedef pdbool(PDFRASAPICALL *pfn_pdfr_decrypter_get_metadata_encrypted) (t_decrypter* decrypter);

#ifdef __cplusplus
}
#endif

#endif // _H_PdfRaster_Encryption
