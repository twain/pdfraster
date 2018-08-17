#ifndef _H_PdfRaster_Recipient
#define _H_PdfRaster_Recipient

#ifdef __cplusplus
extern "C" {
#endif

#include "PdfPlatform.h"
#include "pdfras_data_structures.h"

pdbool PDFRASAPICALL pdfr_pubsec_add_recipient(t_recipient** root, const char* pub_key, PDFRAS_PERMS perms, const char* seed, PDFRAS_ENCRYPT_ALGORITHM algorithm);
typedef pdbool (PDFRASAPICALL *pfn_pdfr_pubsec_add_recipient) (t_recipient** root, const char* pub_key, PDFRAS_PERMS perms, const char* seed, PDFRAS_ENCRYPT_ALGORITHM algorithm);

// calling function becomes the owner of the buffer.
void PDFRASAPICALL pdfr_pubsec_add_existing_recipient(t_recipient** root, char* pkcs7_blob, pduint32 pkcs7_len);
typedef void (PDFRASAPICALL *pfn_pdfr_pubsec_add_existing_recipient) (t_recipient** root, char* pkcs7_blob, pduint32 pkcs7_len);

void PDFRASAPICALL pdfr_pubsec_delete_recipients(t_recipient* root);
typedef void (PDFRASAPICALL *pfn_pdfr_pubsec_delete_recipients) (t_recipient* root);

pduint32 PDFRASAPICALL pdfr_pubsec_recipients_count(t_recipient* root);
typedef pduint32(PDFRASAPICALL *pfn_pdfr_recipients_count) (t_recipient* root);

// Function will allocate buffer itself.
pdbool PDFRASAPICALL pdfr_pubsec_decrypt_recipient(t_recipient* recipients, const char* password, char** decrypted_blob, pduint32* decrypted_blob_len);
typedef pdbool(PDFRASAPICALL pfn_pdfr_pubsec_decrypt_recipient)(t_recipient* recipients, const char* password, char** decrypted_blob, pduint32* decrypted_blob_len);

#ifdef __cplusplus
}
#endif

#endif // _H_PdfRaster_Recipient
