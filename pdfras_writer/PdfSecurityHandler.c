#include <assert.h>
#include <string.h>

#include "PdfSecurityHandler.h"
#include "PdfAlloc.h"
#include "PdfDict.h"
#include "PdfString.h"
#include "PdfStandardAtoms.h"
#include "pdfras_encryption.h"
#include "PdfXrefTable.h"

#define BUFFER_SIZE 8192

typedef struct {
    pduint8* buffer;
    pduint32 bufferSize;
    pduint32 written;
} t_writer_data;

struct t_pdencrypter {
	t_pdmempool* pool;
    fOutputWriter userWriter;
    void* userCookie;
    t_writer_data* data;

    t_encrypter* encrypter;

    pduint32 encrypt_obj_number;
    pduint32 digsig_obj_number;

    pdbool active;
};

t_pdencrypter* pd_encrypt_new(t_pdmempool* pool, const char* user_passwd, const char* owner_passwd, PDFRAS_PERMS perms, PDFRAS_ENCRYPT_ALGORITHM algoritm, pdbool encrypt_metada, const char* document_id, pdint32 id_len)
{
	t_pdencrypter* crypter = (t_pdencrypter*)pd_alloc(pool, sizeof(t_pdencrypter));
    if (!crypter)
        return NULL;

    crypter->pool = pool;
    crypter->digsig_obj_number = 0;
    crypter->encrypt_obj_number = 0;
    crypter->active = PD_TRUE;

    crypter->data = (t_writer_data*)pd_alloc(crypter->pool, sizeof(t_writer_data));

    crypter->data->buffer = (pduint8*)pd_alloc(crypter->pool, sizeof(pduint8) * BUFFER_SIZE);
    if (!crypter->data->buffer)
        return NULL;

    crypter->data->bufferSize = BUFFER_SIZE;
    crypter->data->written = 0;


    crypter->encrypter = pdfr_create_encrypter(user_passwd, owner_passwd, perms, algoritm, encrypt_metada);
    pdfr_encrypter_dictionary_data(crypter->encrypter, document_id, id_len);
	return crypter;
}

void pd_encrypt_free(t_pdencrypter* crypter)
{
    if (crypter->encrypter)
        pdfr_destroy_encrypter(crypter->encrypter);

	pd_free(crypter);
}

void pd_encrypt_dictionary(t_pdencrypter* crypter, t_pdxref* xref, t_pdvalue* trailer) {
    t_pdvalue encrypt_dict = pd_dict_new(crypter->pool, 4);
    // fill encryption dictionary
    pd_encrypt_fill_dictionary(crypter, &encrypt_dict);
    t_pdvalue encrypt_dict_ref = pd_xref_makereference(xref, encrypt_dict);
    pd_dict_put(*trailer, ((t_pdatom) "Encrypt"), encrypt_dict_ref);

    crypter->encrypt_obj_number = pd_reference_object_number(encrypt_dict_ref);
}

void pd_encrypt_start_object(t_pdencrypter *crypter, pduint32 onr, pduint32 gen)
{
    if (crypter->encrypt_obj_number == onr)
        pd_encrypt_deactivate(crypter);
    else {
        if (pd_encrypt_is_active(crypter) == PD_FALSE)
            pd_encrypt_activate(crypter);

        pdfr_encrypter_object_number(crypter->encrypter, onr, gen);
    }
}

pdint32 pd_encrypted_size(t_pdencrypter *crypter, const pduint8* data, const pdint32 data_len)
{
    return pdfr_encrypter_encrypt_data(crypter->encrypter, data, data_len, NULL);
}

pdint32 pd_encrypt_data(t_pdencrypter *crypter, const pduint8* data_in, const pdint32 in_len, pduint8* data_out)
{
    return pdfr_encrypter_encrypt_data(crypter->encrypter, data_in, in_len, data_out);
}

void pd_encrypt_fill_dictionary(t_pdencrypter* encrypter, t_pdvalue* dict) {
    pd_dict_put(*dict, ((t_pdatom) "Filter"), pdatomvalue((t_pdatom)"Standard"));

    pduint8 V = pdfr_encrypter_get_V(encrypter->encrypter);
    pd_dict_put(*dict, ((t_pdatom)"V"), pdintvalue(V));
    
    pduint32 key_length = pdfr_encrypter_get_key_length(encrypter->encrypter);
    pd_dict_put(*dict, ((t_pdatom) "Length"), pdintvalue(key_length));

    pduint8 R = pdfr_encrypter_get_R(encrypter->encrypter);
    pd_dict_put(*dict, ((t_pdatom) "R"), pdintvalue(R));

    pduint32 ou_length = pdfr_encrypter_get_OU_length(encrypter->encrypter);
    const char* O = pdfr_encrypter_get_O(encrypter->encrypter);
    const char* U = pdfr_encrypter_get_U(encrypter->encrypter);
    pd_dict_put(*dict, ((t_pdatom) "O"), pdstringvalue(pd_string_new_binary(encrypter->pool, ou_length, O)));
    pd_dict_put(*dict, ((t_pdatom) "U"), pdstringvalue(pd_string_new_binary(encrypter->pool, ou_length, U)));
    
    pduint32 P = pdfr_encrypter_get_permissions(encrypter->encrypter);
    pd_dict_put(*dict, ((t_pdatom) "P"), pdintvalue(P));

    if (V == 4 || V == 5) {
        pdbool metadata_ecnrytped = pdfr_encrypter_get_metadata_encrypted(encrypter->encrypter);
        pd_dict_put(*dict, ((t_pdatom) "EncryptMetadata"), pdboolvalue(metadata_ecnrytped));

        t_pdvalue cf_dict = pd_dict_new(encrypter->pool, 1);
        t_pdvalue stdcf_dict = pd_dict_new(encrypter->pool, 4);

        pd_dict_put(stdcf_dict, ((t_pdatom) "Type"), pdatomvalue((t_pdatom) "CryptFilter"));
        PDFRAS_ENCRYPT_ALGORITHM algorithm = pdfr_encrypter_get_algorithm(encrypter->encrypter);

        if (algorithm == PDFRAS_AES_128)
            pd_dict_put(stdcf_dict, ((t_pdatom) "CFM"), pdatomvalue((t_pdatom) "AESV2"));
        if (algorithm == PDFRAS_RC4_128)
            pd_dict_put(stdcf_dict, ((t_pdatom) "CFM"), pdatomvalue((t_pdatom) "V2"));
        if (algorithm == PDFRAS_AES_256)
            pd_dict_put(stdcf_dict, ((t_pdatom) "CFM"), pdatomvalue((t_pdatom) "AESV3"));

        pd_dict_put(stdcf_dict, ((t_pdatom) "AuthEvent"), pdatomvalue((t_pdatom) "DocOpen"));
        pd_dict_put(stdcf_dict, ((t_pdatom) "Length"), pdintvalue(key_length / 8));

        pd_dict_put(cf_dict, ((t_pdatom) "StdCF"), stdcf_dict);
        pd_dict_put(*dict, ((t_pdatom) "CF"), cf_dict);
        pd_dict_put(*dict, ((t_pdatom) "StrF"), pdatomvalue((t_pdatom) "StdCF"));
        pd_dict_put(*dict, ((t_pdatom) "StmF"), pdatomvalue((t_pdatom) "StdCF"));
    }

    if (R == 6) {
        const char* OE = pdfr_encrypter_get_OE(encrypter->encrypter);
        const char* UE = pdfr_encrypter_get_UE(encrypter->encrypter);
        const char* Perms = pdfr_encrypter_get_Perms(encrypter->encrypter);
        pduint32 oue_length = pdfr_encrypter_get_OUE_length(encrypter->encrypter);
        pduint32 Perms_length = pdfr_encrypter_get_Perms_length(encrypter->encrypter);

        pd_dict_put(*dict, ((t_pdatom) "OE"), pdstringvalue(pd_string_new_binary(encrypter->pool, oue_length, OE)));
        pd_dict_put(*dict, ((t_pdatom) "UE"), pdstringvalue(pd_string_new_binary(encrypter->pool, oue_length, UE)));
        pd_dict_put(*dict, ((t_pdatom) "Perms"), pdstringvalue(pd_string_new_binary(encrypter->pool, Perms_length, Perms)));
    }
}

void pd_encrypt_activate(t_pdencrypter* encrypter) {
    if (encrypter)
        encrypter->active = PD_TRUE;
}

void pd_encrypt_deactivate(t_pdencrypter* encrypter) {
    if (encrypter)
        encrypter->active = PD_FALSE;
}

pdbool pd_encrypt_is_active(t_pdencrypter* encrypter) {
    if (encrypter)
        return encrypter->active;

    return PD_FALSE;
}

pdbool pd_encrypt_metadata(t_pdencrypter* encrypter) {
    if (!encrypter)
        return PD_FALSE;

    return pdfr_encrypter_get_metadata_encrypted(encrypter->encrypter);
}

// callback for writing data during encryption.
// Becuase pdfras writes stream byte by byte we have to collect whole stream and encrypt it.
int pd_encrypt_writer(const pduint8* data, pduint32 offset, pduint32 len, void* cookie) {
    assert(cookie);

    if (!data || !len)
        return 0;

    data += offset;

    t_pdencrypter* encrypter = (t_pdencrypter*)cookie;

    if ((encrypter->data->written + len) > encrypter->data->bufferSize) {
        pduint32 size = encrypter->data->written + len;
        pduint8* buf = (pduint8*)pd_alloc(encrypter->pool, sizeof(pduint8) * size);

        if (!buf)
            return 0;

        memcpy(buf, encrypter->data->buffer, encrypter->data->written);
        pd_free(encrypter->data->buffer);
        encrypter->data->buffer = buf;
        encrypter->data->bufferSize = size;
    }

    memcpy(encrypter->data->buffer + encrypter->data->written, data, len);
    encrypter->data->written += len;

    return len;
}

pduint8* pd_encrypt_writer_data(t_pdencrypter* encrypter) {
    assert(encrypter);

    return encrypter->data->buffer;
}
pduint32 pd_encrypt_writer_data_len(t_pdencrypter* encrypter) {
    assert(encrypter);

    return encrypter->data->written;
}

void pd_encrypt_writer_reset(t_pdencrypter* encrypter) {
    assert(encrypter);

    if (encrypter->data->buffer) {
        pd_free(encrypter->data->buffer);
        encrypter->data->buffer = (pduint8*)pd_alloc(encrypter->pool, sizeof(pduint8) * BUFFER_SIZE);
        encrypter->data->bufferSize = BUFFER_SIZE;
        encrypter->data->written = 0;
    }
}
