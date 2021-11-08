// PdfDigitalSignature.c - function for digital siging of PDF/R

#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "PdfDigitalSignature.h"
#include "PdfOS.h"
#include "PdfAlloc.h"
#include "PdfRaster.h"
#include "PdfStreaming.h"
#include "PdfDict.h"
#include "PdfArray.h"
#include "PdfString.h"
#include "PdfXrefTable.h"
#include "PdfDate.h"

#include "pdfras_digitalsignature.h"

// Need this to make C# happy...
typedef void X509_STORE;
struct t_digitalsignature {
	struct t_signer* signer;
	X509_STORE* cert_store;
};

// data structure for digital signature
struct t_pdfdigitalsignature {
    t_pdmempool* pool;

    t_pdfrasencoder* encoder;

    // data used by pdfras_digitalsignature module
    t_digitalsignature* ds;

    // page containing signature
    t_pdvalue page;
    
    // name, location, reason and contact info
    char* name;
    char* location;
    char* reason;
    char* contact_info;

    // written to output
    pdbool written;

    // output pdf file
    char* pdf_file;

    // mark digital signature
    pdbool digisig_finish;

    pduint32 digsig_objnum;
    pdint32 content_pos_begin, content_pos_end;
    pdint32 byterange_pos_begin, byterange_pos_end;
};

// Initialization
t_pdfdigitalsignature* digitalsignature_create(t_pdfrasencoder* encoder, const char *pdf_file, const char* pfx_file, const char* password) {
    assert(encoder);

    t_pdmempool* pool = pdfr_encoder_mempool(encoder);
    t_pdfdigitalsignature* digitalSignature = (t_pdfdigitalsignature*) pd_alloc(pool, sizeof(t_pdfdigitalsignature));
    if (!digitalSignature)
        return NULL;

    digitalSignature->ds = pdfr_init_digitalsignature();
    if (digitalSignature->ds == NULL) {
        pd_free(digitalSignature);
        return NULL;
    }

    pdbool result = pdfr_digitalsignature_create_signer(digitalSignature->ds, pfx_file, password);
    if (!result) {
        pdfr_exit_digitalsignature(digitalSignature->ds);
        pd_free(digitalSignature);
        return NULL;
    }

    digitalSignature->pool = pool;
    digitalSignature->encoder = encoder;

    digitalSignature->name = NULL;
    digitalSignature->location = NULL;
    digitalSignature->reason = NULL;
    digitalSignature->contact_info = NULL;

    digitalSignature->written = PD_FALSE;
    digitalSignature->digisig_finish = PD_FALSE;

    digitalSignature->digsig_objnum = 0;
    digitalSignature->content_pos_begin = 0;
    digitalSignature->content_pos_end = 0;
    digitalSignature->byterange_pos_begin = 0;
    digitalSignature->byterange_pos_end = 0;
    digitalSignature->pdf_file = (char *)pd_alloc(pool, strlen(pdf_file) + 1);
    if (!digitalSignature->pdf_file)
        return NULL;

    strcpy(digitalSignature->pdf_file, pdf_file);

    return digitalSignature;
}

void digitalsignature_ready(t_pdfdigitalsignature* signature) {
    signature->digisig_finish = PD_TRUE;
}

void digitalsignature_finish(t_pdfdigitalsignature* signature) {
    FILE* fd;
    char byterange_value[50];
    int byterange_len;
    pduint8* content_value;
    t_sign_range ranges[2];
    pdint32 signature_len;
    pdint32 content_len;

    if (signature->digisig_finish == PD_FALSE ||
        signature->content_pos_begin == 0 ||
        signature->content_pos_end == 0 ||
        signature->byterange_pos_begin == 0 ||
        signature->byterange_pos_end == 0) {
        return;
    }
    if (fopen_s(&fd, signature->pdf_file, "rb+")) {
        return;
    }
    ranges[0].offset = 0;
    ranges[0].len = signature->content_pos_begin;
    ranges[1].offset = signature->content_pos_end;

    fseek(fd, 0, SEEK_END);
    ranges[1].len = ftell(fd) - signature->content_pos_end;
    snprintf(byterange_value, sizeof(byterange_value), " %d %d %d %d",
                                                ranges[0].offset,
                                                ranges[0].len,
                                                ranges[1].offset,
                                                ranges[1].len);
    byterange_len = signature->byterange_pos_end - signature->byterange_pos_begin - strlen(byterange_value) - 2;
    fseek(fd, signature->byterange_pos_begin + 1, SEEK_SET);
    fputs(byterange_value, fd);
    while (byterange_len--) {
        fputc(' ', fd);
    }
    fflush(fd);
    content_len = (signature->content_pos_end - signature->content_pos_begin) / 2;
    content_value = (pduint8*)pd_alloc(signature->pool, content_len);
    if (content_value) {
        signature_len = pdfr_digsig_sign_range(signature->ds, fd, ranges, sizeof(ranges) / sizeof(t_sign_range), content_value, content_len);
        if (signature_len > 0) {
            fseek(fd, signature->content_pos_begin + 1, SEEK_SET);
            for (int i = 0; i < signature_len; i++) {
                fprintf(fd, "%02X", content_value[i]);
            }
        }
        pd_free(content_value);
    }
    fflush(fd);
    fclose(fd);   
}

// Destroy
void digitalsignature_destroy(t_pdfdigitalsignature* signature) {
    assert(signature);
    
    // sign document
    digitalsignature_finish(signature);
    pdfr_exit_digitalsignature(signature->ds);

    // free allocated memmory
    if (signature->name != NULL)
        pd_free(signature->name);
    if (signature->location != NULL)
        pd_free(signature->location);
    if (signature->reason != NULL)
        pd_free(signature->reason);
    if (signature->contact_info != NULL)
        pd_free(signature->contact_info);
    if (signature->pdf_file != NULL)
        pd_free(signature->pdf_file);
    pd_free(signature);

    signature = NULL;
}

// Set Name of signer. Owner of buffer with name becomes library
void pdfr_digitalsignature_set_name(t_pdfdigitalsignature* signature, const char* name) {
    assert(signature);

    pdint32 len = pdstrlen(name);
    if (signature->name != NULL)
        pd_free(signature->name);

    if (len == 0)
        signature->name = NULL;

    signature->name = (char*) pd_alloc(signature->pool, sizeof(char) * (len + 1));
    memcpy(signature->name, name, len);
    signature->name[len] = '\0';
}

// Set reason for the signing.
void pdfr_digitalsignature_set_reason(t_pdfdigitalsignature* signature, const char* reason) {
    assert(signature);

    pdint32 len = pdstrlen(reason);
    if (signature->reason != NULL)
        pd_free(signature->reason);

    if (len == 0)
        signature->reason = NULL;

    signature->reason = (char*)pd_alloc(signature->pool, sizeof(char) * (len + 1));
    memcpy(signature->reason, reason, len);
    signature->reason[len] = '\0';
}

// Set location of signing
void pdfr_digitalsignature_set_location(t_pdfdigitalsignature* signature, const char* location) {
    assert(signature);

    pdint32 len = pdstrlen(location);
    if (signature->location != NULL)
        pd_free(signature->location);

    if (len == 0)
        signature->location = NULL;

    signature->location = (char*)pd_alloc(signature->pool, sizeof(char) * (len + 1));
    memcpy(signature->location, location, len);
    signature->location[len] = '\0';
}

// Set contact info
void pdfr_digitalsignature_set_contactinfo(t_pdfdigitalsignature* signature, const char* contactinfo) {
    assert(signature);

    pdint32 len = pdstrlen(contactinfo);
    if (signature->contact_info != NULL)
        pd_free(signature->contact_info);

    if (len == 0)
        signature->contact_info = NULL;

    signature->contact_info = (char*)pd_alloc(signature->pool, sizeof(char) * (len + 1));
    memcpy(signature->contact_info, contactinfo, len);
    signature->contact_info[len] = '\0';
}

// set page containing signature
void digitalsignature_set_page(t_pdfdigitalsignature* signature, t_pdvalue page) {
    assert(signature);
    
    if (!IS_NULL(page))
        signature->page = page;
}

// Creates necessary dictionaries for signature
void digitalsignature_create_dictionaries(t_pdfdigitalsignature* signature) {
    pdbool succ;
    t_pdvalue* catalog = pdfr_encoder_catalog(signature->encoder);
    t_pdxref* xref = pdfr_encoder_xref(signature->encoder);
    pduint8* content;

    // Create AcroForm entry in the Catalog
    t_pdvalue acro_form = pd_dict_get(*catalog, (t_pdatom)"AcroForm", &succ);
    if (!succ) {
        acro_form = pd_dict_new(signature->pool, 2);
        t_pdvalue acro_form_ref = pd_xref_makereference(xref, acro_form);
        pd_dict_put(*catalog, ((t_pdatom)"AcroForm"), acro_form_ref);
    }

    // Filling AcroForm
    pd_dict_put(acro_form, ((t_pdatom)"SigFlags"), pdintvalue(3));

    //Creating /Fields array
    t_pdvalue fields = pd_dict_get(*catalog, (t_pdatom)"Fields", &succ);
    if (!succ) {
        fields = pdarrayvalue(pd_array_new(signature->pool, 2));
        t_pdvalue fields_ref = pd_xref_makereference(xref, fields);
        pd_dict_put(acro_form, ((t_pdatom)"Fields"), fields_ref);
    }

    // Preparing Field and appending to the Fields array
    t_pdvalue signature_field = pd_dict_new(signature->pool, 5);
    t_pdvalue signature_field_ref = pd_xref_makereference(xref, signature_field);
    pd_array_add(fields.value.arrvalue, signature_field_ref);

    //Enter paramaters to the /Field
    char t[] = "Sig_1";
    pd_dict_put(signature_field, ((t_pdatom)"T"), pdstringvalue(pd_string_new(signature->pool, (pduint32) strlen(t), t)));
    pd_dict_put(signature_field, ((t_pdatom)"FT"), pdatomvalue((t_pdatom)"Sig"));
    pd_dict_put(signature_field, ((t_pdatom)"Type"), pdatomvalue((t_pdatom)"Annot"));
    pd_dict_put(signature_field, ((t_pdatom)"SubType"), pdatomvalue((t_pdatom)"Widget"));
    pd_dict_put(signature_field, ((t_pdatom)"F"), pdintvalue(132));

    t_pdarray *field_rect_arr = pd_array_new(signature->pool, 4);
    pd_array_add(field_rect_arr, pdintvalue(0));
    pd_array_add(field_rect_arr, pdintvalue(0));
    pd_array_add(field_rect_arr, pdintvalue(0));
    pd_array_add(field_rect_arr, pdintvalue(0));
    pd_dict_put(signature_field, ((t_pdatom)"Rect"), pdarrayvalue(field_rect_arr));

    pd_dict_put(signature_field, ((t_pdatom)"P"), signature->page);
  
    if (IS_REFERENCE(signature->page)) {
        t_pdvalue page_dict = pd_reference_get_value(signature->page);
        
        t_pdarray* annots_array = pd_array_new(signature->pool, 1);
        pd_array_add(annots_array, signature_field_ref);

        pd_dict_put(page_dict, ((t_pdatom) "Annots"), pdarrayvalue(annots_array));
    }
    
    // Preparing /V dictionary 
    t_pdvalue v_dict = pd_dict_new(signature->pool, 3);
    // calculating lenght of the Content just to have accurate size 
    pdint32 signature_length = pdfr_digsig_signature_length(signature->ds);
    content = (pduint8 *)pd_alloc(signature->pool, signature_length);
    if (content != NULL) {
        memset(content, '\0', signature_length);
        pd_dict_put(v_dict, ((t_pdatom)"Contents"), pdstringvalue(pd_string_new_binary(signature->pool, signature_length, content)));
        pd_free(content);
    }
    pd_dict_put(v_dict, ((t_pdatom)"Type"), pdatomvalue((t_pdatom)"Sig"));
    pd_dict_put(v_dict, ((t_pdatom)"Filter"), pdatomvalue((t_pdatom)"Adobe.PPKLite"));
    pd_dict_put(v_dict, ((t_pdatom)"SubFilter"), pdatomvalue((t_pdatom)"adbe.pkcs7.detached"));

    if (signature->name)
        pd_dict_put(v_dict, ((t_pdatom) "Name"), pdstringvalue(pd_string_new(signature->pool, pdstrlen(signature->name), signature->name)));
    if (signature->reason)
        pd_dict_put(v_dict, ((t_pdatom) "Reason"), pdstringvalue(pd_string_new(signature->pool, pdstrlen(signature->reason), signature->reason)));
    if (signature->location)
        pd_dict_put(v_dict, ((t_pdatom) "Location"), pdstringvalue(pd_string_new(signature->pool, pdstrlen(signature->location), signature->location)));
    if (signature->contact_info)
        pd_dict_put(v_dict, ((t_pdatom) "ContactInfo"), pdstringvalue(pd_string_new(signature->pool, pdstrlen(signature->contact_info), signature->contact_info)));

    t_pdarray *byterange_arr = pd_array_new(signature->pool, 4);
    pd_array_add(byterange_arr, pdintvalue(2147483647));
    pd_array_add(byterange_arr, pdintvalue(2147483647));
    pd_array_add(byterange_arr, pdintvalue(2147483647));
    pd_array_add(byterange_arr, pdintvalue(2147483647));
    pd_dict_put(v_dict, ((t_pdatom)"ByteRange"), pdarrayvalue(byterange_arr));

    t_date* now = pd_date_create_current_localtime(signature->pool);
    char* m = pd_date_to_pdfstring(now);
    pd_dict_put(v_dict, ((t_pdatom)"M"), pdstringvalue(pd_string_new(signature->pool, pdstrlen(m), m)));
    pd_date_destroy(now);
    pd_free(m);

    // Insert V into the Filed dictionary
    t_pdvalue v_dict_ref = pd_xref_makereference(xref, v_dict);
    pd_dict_put(signature_field, ((t_pdatom)"V"), v_dict_ref);

    signature->digsig_objnum = pd_reference_object_number(v_dict_ref);

    signature->written = PD_TRUE;
}

pdbool digitalsignature_written(t_pdfdigitalsignature* signature) {
    return signature->written;
}

pduint32 pd_digitalsignature_digsig_objnum(t_pdfdigitalsignature* signature) {
    assert(signature);

    return signature->digsig_objnum;
}

void pd_digitalsignature_setcontent_pos(t_pdfdigitalsignature* signature, pduint32 content_pos_begin, pduint32 content_pos_end) {
    assert(signature);

    signature->content_pos_begin = content_pos_begin;
    signature->content_pos_end = content_pos_end;
}

void pd_digitalsignature_setbyterange_pos(t_pdfdigitalsignature* signature, pduint32 byterange_pos_begin, pduint32 byterange_pos_end) {
    assert(signature);

    signature->byterange_pos_begin = byterange_pos_begin;
    signature->byterange_pos_end = byterange_pos_end;
}
