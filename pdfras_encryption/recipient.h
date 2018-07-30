#ifndef _H_PdfRaster_Recipient
#define _H_PdfRaster_Recipient

#ifdef __cplusplus
extern "C" {
#endif

#include "PdfPlatform.h"
#include "pdfras_data_structures.h"

extern pdbool add_recipient(t_recipient** root, const char* pub_key, PDFRAS_PERMS perms, const char* seed, PDFRAS_ENCRYPT_ALGORITHM algorithm);
extern void delete_recipients(t_recipient* root);
extern pduint32 recipients_count(t_recipient* root);

#ifdef __cplusplus
}
#endif

#endif // _H_PdfRaster_Recipient
