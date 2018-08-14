// pdfras_recipient.c: handling recpient data structure

#include <stdlib.h>
#include <string.h>
#include "pdfras_data_structures.h"
#include "pubsec.h"

#define PUBSEC_SEED_LEN 20

pdbool add_recipient(t_recipient** root, const char* pub_key, PDFRAS_PERMS perms, const char* seed, PDFRAS_ENCRYPT_ALGORITHM algorithm) {
    t_recipient* recipient = NULL;

    if (!(*root)) {
        *root = (t_recipient*)malloc(sizeof(t_recipient));

        (*root)->pkcs7_blob = NULL;
        (*root)->pkcs7_blob_size = 0;
        (*root)->next = NULL;

        recipient = *root;
    }
    else {
        // find last recipient in the list
        if (!(*root)->next) {
            recipient = *root;
        }
        else {
            recipient = (*root)->next;
            while (recipient && recipient->next) {
                recipient = recipient->next;
            }
        }

        // create new recipient
        t_recipient* new_recipient = (t_recipient*)malloc(sizeof(t_recipient));
        if (!new_recipient)
            return PD_FALSE;

        new_recipient->pkcs7_blob = NULL;
        new_recipient->pkcs7_blob_size = 0;
        new_recipient->next = NULL;

        // link new recipient to last one found
        recipient->next = new_recipient;

        // last recipient created
        recipient = new_recipient;
    }

    // create PKCS7 Blob for /Recipients in Encrypt dictionary
    char message[PUBSEC_SEED_LEN + 4];
    pduint32 uPerms = (pduint32) perms;
    uPerms |= 0x01;  // Set bit for opening document
    memcpy(message, seed, PUBSEC_SEED_LEN);

    message[PUBSEC_SEED_LEN] = (pduint8)((uPerms >> 24) & 0xFF);
    message[PUBSEC_SEED_LEN + 1] = (pduint8)((uPerms >> 16) & 0xFF);
    message[PUBSEC_SEED_LEN + 2] = (pduint8)((uPerms >> 8) & 0xFF);
    message[PUBSEC_SEED_LEN + 3] = (pduint8)(uPerms & 0xFF);

    recipient->pkcs7_blob = encrypt_recipient_message(pub_key, message, (pduint8) PUBSEC_SEED_LEN + 4, &recipient->pkcs7_blob_size, algorithm == PDFRAS_AES_256 ? PD_TRUE : PD_FALSE);

    if (!recipient->pkcs7_blob)
        return PD_FALSE;

    return PD_TRUE;
}

static void delete_recipient(t_recipient* recipient) {
    if (recipient) {
        if (recipient->pkcs7_blob)
            free(recipient->pkcs7_blob);

        free(recipient);
        recipient = NULL;
    }
}

void delete_recipients(t_recipient* root) {
    if (!root)
        return;

    t_recipient* recipient = root;
    while (recipient) {
        t_recipient* next = recipient->next;
        delete_recipient(recipient);
        recipient = next;
    }
}

pduint32 recipients_count(t_recipient* root) {
    pduint32 count = 0;
    
    if (root) {
        t_recipient* recipient = root;
        while (recipient) {
            ++count;
            recipient = recipient->next;
        }
    }

    return count;
}
