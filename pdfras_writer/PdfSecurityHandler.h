#ifndef _H_PdfSecurityHandler
#define _H_PdfSecurityHandler

#ifdef __cplusplus
extern "C" {
#endif

//#include "PdfXrefTable.h"
#include "pdfras_encryption.h"
#include "PdfOS.h"
#include "PdfValues.h"

typedef struct t_pdencrypter t_pdencrypter;

// Create a new encrytper.
extern t_pdencrypter* pd_encrypt_new(t_pdmempool* pool, const char* user_passwd, const char* owner_passwd, PDFRAS_PERMS perms, PDFRAS_ENCRYPT_ALGORITHM algoritm, pdbool encrypt_metada, const char* document_id, pdint32 id_len);

// free encrypter
extern void pd_encrypt_free(t_pdencrypter* crypter);

extern void pd_encrypt_dictionary(t_pdencrypter* crypter, t_pdxref* xref, t_pdvalue* trailer);

// functions associated with an (encryption) security handler:
// * Creating an encryption state for a PDF from whatever it needs as input
// * Setting up to encrypt one object, using state+(onr,gen).
// * Predicting the buffer size needed to encrypt n bytes of data
// * Encrypting n bytes of data
// * Writing (or providing) all the encryption metadata

// initialize for encryption of an object.
// The object, or it's first indirect parent, is indirect object <onr, genr>.
extern void pd_encrypt_start_object(t_pdencrypter *crypter, pduint32 onr, pduint32 genr);

// calculate the encrypted size of n bytes of plain data
extern pdint32 pd_encrypted_size(t_pdencrypter *crypter, const pduint8* data, const pdint32 data_len);

// encrypt n bytes of data
extern pdint32 pd_encrypt_data(t_pdencrypter *crypter, const pduint8* data_in, const pdint32 in_len, pduint8* data_out);

extern void pd_encrypt_fill_dictionary(t_pdencrypter* encrypter, t_pdvalue* dict);

extern void pd_encrypt_activate(t_pdencrypter* encrypter);
extern void pd_encrypt_deactivate(t_pdencrypter* encrypter);
extern pdbool pd_encrypt_is_active(t_pdencrypter* encrypter);
extern pdbool pd_encrypt_metadata(t_pdencrypter* encrypter);

// Our callback for collecting stream data
extern int pd_encrypt_writer(const pduint8* data, pduint32 offset, pduint32 len, void* cookie);
extern pduint8* pd_encrypt_writer_data(t_pdencrypter* encrypter);
extern pduint32 pd_encrypt_writer_data_len(t_pdencrypter* encrypter);
extern void pd_encrypt_writer_reset(t_pdencrypter* encrypter);

// Current object number being encrypted
extern int pd_encrypt_get_current_objectnumber(t_pdencrypter* encrypter);

#ifdef __cplusplus
}
#endif

#endif
