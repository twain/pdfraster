// pdras_encryption.c - encryption support for pdfraster

#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "openssl/md5.h"
#include "openssl/rc4.h"
#include "openssl/sha.h"
#include "openssl/aes.h"
#include "openssl/evp.h"

#include "pdfras_encryption.h"
#include "rc4_crypter.h"
#include "aes_crypter.h"
#include "recipient.h"

#define MD5_HASH_BYTES  16
#define R_6_KEY_LENGTH  32
#define PUBSEC_SEED_LEN 20

struct t_encrypter {
    // user entered data
    char* user_password;  // Only for PDF 2.0
    char* owner_password; // Only for PDF 2.0

    char padded_up[32];
    char padded_op[32];

    char* O;
    char* U;
    char* OE;
    char* UE;
    char* Perms;
    PDFRAS_PERMS perms;
    PDFRAS_ENCRYPT_ALGORITHM algorithm;
    pdbool encrypt_metadata;

    pduint32 OU_length;
    pduint32 OUE_length;
    pduint32 Perms_length;

    pduint8 V;
    pduint8 R;

    char* document_id;
    pduint32 document_id_length;
    
    // encryption key
    char* encryption_key;
    pduint16 encryption_key_length;

    pdint32 current_obj_number;
    pdint32 current_gen_number;

    // Encrypt/decrypt mode
    pdbool encrypt_mode;

    // password or public key security
    pdbool password_security;

    // list of recipeints (terminated by NULL)
    t_recipient* recipients;

    // random seed data used by public key security
    char* seed;
};

static char password_padding[] = "\x28\xBF\x4E\x5E\x4E\x75\x8A\x41\x64\x00\x4E\x56\xFF\xFA\x01\x08\x2E\x2E\x00\xB6\xD0\x68\x3E\x80\x2F\x0C\xA9\xFE\x64\x53\x69\x7A";

static void padd_passwords(t_encrypter* enc, const char* user_password, const char* owner_password) {
    // a
    pdint32 len = 0;
    pdint32 idx = 0;
    if (owner_password) {
        len = (pdint32)strlen(owner_password);
        memcpy(enc->padded_op, owner_password, len > 32 ? 32 : len);

        // pad password
        while (len < 32)
            enc->padded_op[len++] = password_padding[idx++];
    }
    else
        memcpy(enc->padded_op, password_padding, 32);

    idx = 0;
    if (user_password) {
        len = (pdint32)strlen(user_password);
        memcpy(enc->padded_up, user_password, len > 32 ? 32 : len);

        // pad password
        while (len < 32)
            enc->padded_up[len++] = password_padding[idx++];
    }
    else
        memcpy(enc->padded_up, password_padding, 32);
}

// Alogrithm 3: Computing the encryption dictionary's O (owner password) value
static pdbool compute_O(t_encrypter* enc) {
    MD5_CTX md5;
    unsigned char hash[MD5_HASH_BYTES];

    if (MD5_Init(&md5) == 0)
        return PD_FALSE;

    // a, b
    MD5_Update(&md5, enc->padded_op, 32);
    MD5_Final(hash, &md5);

    // c
    if (enc->R >= 3) {
		pduint32 i;
        for (i = 0; i < 50; ++i) {
            MD5_Init(&md5);
            MD5_Update(&md5, hash, enc->encryption_key_length);
            MD5_Final(hash, &md5);
        }
    }

    // d
    RC4_KEY rc4_key;
    RC4_set_key(&rc4_key, enc->encryption_key_length, hash);

    // e done by previous function
    // f
    RC4(&rc4_key, 32, enc->padded_up, enc->O);

    // g
    if (enc->R >= 3) {
        unsigned char key[MD5_HASH_BYTES];
		pduint32 i;
		pduint32 k;

        for (i = 1; i <= 19; ++i) {
            for (k = 0; k < enc->encryption_key_length; ++k) {
                key[k] = (unsigned char)(hash[k] ^ i);
            }

            RC4_set_key(&rc4_key, enc->encryption_key_length, key);
            RC4(&rc4_key, 32, enc->O, enc->O);
        }
    }
    
    // h -> O already stored

    return PD_TRUE;
}

// Algorithm 4: Compute U value (revision 2)
static pdbool compute_U_r2(t_encrypter* enc) {
    if (enc->encryption_key == NULL)
        return PD_FALSE;

    RC4_KEY rc4_key;
    RC4_set_key(&rc4_key, enc->encryption_key_length, enc->encryption_key);
    RC4(&rc4_key, 32, password_padding, enc->U);

    return PD_TRUE;
}

// Algorithm 5: Compute U value (revision >= 3)
static pdbool compute_U_r3_4(t_encrypter* enc) {
    unsigned char hash[MD5_HASH_BYTES];
	pduint32 i;
	pduint32 k;

    if (enc->encryption_key == NULL)
        return PD_FALSE;

    MD5_CTX md5;
    if (MD5_Init(&md5) == 0)
        return PD_FALSE;

    // b
    MD5_Update(&md5, password_padding, 32);

    // c
    MD5_Update(&md5, enc->document_id, enc->document_id_length);
    MD5_Final(hash, &md5);

    // d
    RC4_KEY rc4_key;
    unsigned char rc4_hash[16];
    RC4_set_key(&rc4_key, enc->encryption_key_length, enc->encryption_key);
    RC4(&rc4_key, 16, hash, rc4_hash);

    // e
    unsigned char key[MD5_HASH_BYTES];
    for (i = 1; i <= 19; ++i) {
        for (k = 0; k < enc->encryption_key_length; ++k) {
            key[k] = (unsigned char)(enc->encryption_key[k] ^ i);
        }

        RC4_set_key(&rc4_key, enc->encryption_key_length, key);
        RC4(&rc4_key, MD5_HASH_BYTES, rc4_hash, rc4_hash);
    }

    // f
    memcpy(enc->U, rc4_hash, MD5_HASH_BYTES);
    memcpy(enc->U + MD5_HASH_BYTES, password_padding, MD5_HASH_BYTES);

    return PD_TRUE;
}

// Algorithm 2.B, PDF 2.0
static void compute_2B(const char* password, const pduint8* salt, const pduint8* additional, pduint8* hash) {
    // Algorithm 2.B from ISO 32000-2 to compute hash from password

    pdint32 length = 0;
    if (password != NULL)
        length = (pdint32)strlen(password);
    if (length > 127)
        length = 127;

    pduint8 K[64]; 
    pduint16 K_length = 32;
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, (const unsigned char *)password, length);
    SHA256_Update(&sha256, salt, 8);
    if (additional != NULL)
        SHA256_Update(&sha256, additional, 48);
    SHA256_Final(K, &sha256);

    unsigned int last = 0;
	unsigned int step;
    EVP_CIPHER_CTX* aes128 = EVP_CIPHER_CTX_new();
    for (step = 0; step < 64 || last > step - 32; step++) {
		int i;

        // step a
        pduint8 K1[15962] = "";
        pdint32 K1_length = 0;
        memcpy((unsigned char*)K1, password, length);
        K1_length += length;
        memcpy(&K1[K1_length], K, K_length);
        K1_length += K_length;
        if (additional != NULL) {
            memcpy(&K1[K1_length], additional, 48);
            K1_length += 48;
        }
        for (i = 0; i < 6; i++) {
            memcpy(&K1[K1_length], K1, K1_length);
            K1_length = K1_length << 1;
        }

        // step b
        pduint8 E[sizeof(K1)] = "";
        int E_length = 0, len = 0;
        
        EVP_EncryptInit(aes128, EVP_aes_128_cbc(), K, &K[16]);
        EVP_CIPHER_CTX_set_padding(aes128, 0);
        EVP_EncryptUpdate(aes128, E, &len, (const unsigned char*)&K1, K1_length);
        E_length = len;
        EVP_EncryptFinal_ex(aes128, E + len, &len);
        E_length += len;

        // step c
        unsigned int sum = 0;
        for (i = 0; i < 16; i++)
            sum += E[i];

        // step d
        switch (sum % 3) {
            case 1: {
                SHA512_CTX sha384;
                SHA384_Init(&sha384);
                SHA384_Update(&sha384, (const unsigned char *)E, E_length);
                SHA384_Final(K, &sha384);
                K_length = SHA384_DIGEST_LENGTH;
            }
                break;
            case 2: {
                SHA512_CTX sha512;
                SHA512_Init(&sha512);
                SHA512_Update(&sha512, (const unsigned char *)E, E_length);
                SHA512_Final(K, &sha512);
                K_length = SHA512_DIGEST_LENGTH;
            }
                break;
            case 0:
            default: {
                SHA256_CTX sha256;
                SHA256_Init(&sha256);
                SHA256_Update(&sha256, (const unsigned char *)E, E_length);
                SHA256_Final(K, &sha256);
                K_length = SHA256_DIGEST_LENGTH;
            }
                break;
        }

        // step e,f
        last = E[E_length - 1];
    }

    EVP_CIPHER_CTX_free(aes128);

    memcpy(hash, K, 32);
}

// Algorithm 8: Computing the encryption dictionary's U and UE values (R == 6)
static pdbool compute_U_UE_r_6(t_encrypter* enc) {
    pduint8 buffer[16];
    pdfras_generate_random_bytes(buffer, 16);

    pduint8* uValSalt = buffer;
    pduint8* uKeySalt = buffer + 8;

    // U
    compute_2B(enc->user_password, uValSalt, NULL, enc->U);
    memcpy(enc->U + 32, buffer, sizeof(buffer));

    // UE
    pduint8 ue_key[32];
    compute_2B(enc->user_password, uKeySalt, NULL, ue_key);
    pduint8 iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    int len;
    EVP_CIPHER_CTX* aes256 = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(aes256, EVP_aes_256_cbc(), ue_key, iv);
    EVP_CIPHER_CTX_set_padding(aes256, 0);
    EVP_EncryptUpdate(aes256, enc->UE, &len, (const unsigned char*)enc->encryption_key, 32);
    EVP_EncryptFinal_ex(aes256, enc->UE + len, &len);

    EVP_CIPHER_CTX_free(aes256);

    return PD_TRUE;
}

// Algorithm 9: Computing the encryption dictionary's O and OE values (R == 6)
static pdbool compute_O_OE_r_6(t_encrypter* enc) {
    if (!enc->U)
        return PD_FALSE;

    pduint8 buffer[16];
    pdfras_generate_random_bytes(buffer, 16);

    pduint8* oValSalt = buffer;
    pduint8* oKeySalt = buffer + 8;

    // O
    compute_2B(enc->owner_password, oValSalt, enc->U, enc->O);
    memcpy(enc->O + 32, buffer, sizeof(buffer));

    // OE
    pduint8 oe_key[32];
    compute_2B(enc->owner_password, oKeySalt, enc->U, oe_key);
    
    pduint8 iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    int len;
    EVP_CIPHER_CTX* aes256 = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(aes256, EVP_aes_256_cbc(), oe_key, iv);
    EVP_CIPHER_CTX_set_padding(aes256, 0);
    EVP_EncryptUpdate(aes256, enc->OE, &len, (const unsigned char*)enc->encryption_key, 32);
    EVP_EncryptFinal_ex(aes256, enc->OE + len, &len);
    
    EVP_CIPHER_CTX_free(aes256);

    return PD_TRUE;
}

// Algorithm 10: computing Perms entry for encryption dictionary (R == 6)
static pdbool compute_Perms(t_encrypter* enc) {
    // steps a,b
    pduint8 perms_buffer[16];
    perms_buffer[0] = (pduint8)(enc->perms & 0xFF);
    perms_buffer[1] = (pduint8)((enc->perms >> 8) & 0xFF);
    perms_buffer[2] = (pduint8)((enc->perms >> 16) & 0xFF);
    perms_buffer[3] = (pduint8)((enc->perms >> 24) & 0xFF);
    perms_buffer[4] = (pduint8)(0xFF);
    perms_buffer[5] = (pduint8)(0xFF);
    perms_buffer[6] = (pduint8)(0xFF);
    perms_buffer[7] = (pduint8)(0xFF);

    // step c
    perms_buffer[8] = enc->encrypt_metadata ? 'T' : 'F';

    // step d
    perms_buffer[9] = 'a';
    perms_buffer[10] = 'd';
    perms_buffer[11] = 'b';

    // step e - //random numbers. let's use: 'TwAi'
    perms_buffer[12] = 'T';
    perms_buffer[13] = 'w';
    perms_buffer[14] = 'A';
    perms_buffer[15] = 'i';

    // step f
    pduint8 iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    int len;
    EVP_CIPHER_CTX* aes256 = EVP_CIPHER_CTX_new();
    EVP_EncryptInit(aes256, EVP_aes_256_ecb(), enc->encryption_key, iv);
    EVP_CIPHER_CTX_set_padding(aes256, 0);
    EVP_EncryptUpdate(aes256, enc->Perms, &len, perms_buffer, sizeof perms_buffer);
    EVP_EncryptFinal_ex(aes256, enc->Perms + len, &len);

    EVP_CIPHER_CTX_free(aes256);
    
    return PD_TRUE;
}

// Algorithm 2: Computing encryption key
static pdbool generate_encryption_key(t_encrypter* enc) {
    if (enc->R == 6) {
        if (enc->encrypt_mode) {
            enc->encryption_key = (char*)malloc(sizeof(char) * R_6_KEY_LENGTH);
            enc->encryption_key_length = R_6_KEY_LENGTH;
            pdfras_generate_random_bytes(enc->encryption_key, R_6_KEY_LENGTH);
        }
    }
    else {
        pduint8 idx = 0;
        pduint32 len = 0;
		int i;

        // a -> passwords already padded

        // b
        MD5_CTX md5;
        if (MD5_Init(&md5) == 0)
            return PD_FALSE;

        //MD5_Update(&md5, padded_op, 32);
        MD5_Update(&md5, enc->padded_up, 32);

        // c
        MD5_Update(&md5, enc->O, enc->OU_length);

        // d
        pduint32 p = (pduint32)enc->perms;
        pduint8 p_a[4] = { (pduint8)(p), (pduint8)(p >> 8), (pduint8)(p >> 16), (pduint8)(p >> 24) };
        MD5_Update(&md5, p_a, 4);

        // e
        if (enc->document_id != NULL)
            MD5_Update(&md5, enc->document_id, enc->document_id_length);

        if (enc->R >= 4 && !enc->encrypt_metadata) {
            pduint8 m[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
            MD5_Update(&md5, m, 4);
        }

        // f
        unsigned char hash[MD5_HASH_BYTES];
        MD5_Final(hash, &md5);

        // g
        if (enc->R >= 3) {
            for (i = 0; i < 50; ++i) {
                if (MD5_Init(&md5) == 0)
                    return PD_FALSE;

                MD5_Update(&md5, hash, enc->encryption_key_length);
                MD5_Final(hash, &md5);
            }
        }

        // h
        enc->encryption_key = (char*)malloc(sizeof(char) * enc->encryption_key_length);
        memcpy(enc->encryption_key, (const unsigned char*)hash, enc->encryption_key_length);
    }

    return PD_TRUE;
}

static pdbool generate_encryption_key_pubsec(t_encrypter* encrypter) {
    pduint32 pkcs7_size = 0;
    pduint32 recipients_count = pdfr_encrypter_pubsec_recipients_count(encrypter);
    
    if (encrypter->encryption_key_length <= 16) {
        SHA_CTX ctx;
        char digest[SHA_DIGEST_LENGTH];

        if (!SHA1_Init(&ctx))
            return PD_FALSE;

        if (!SHA1_Update(&ctx, encrypter->seed, PUBSEC_SEED_LEN))
            return PD_FALSE;

        for (pduint32 i = 0; i < recipients_count; ++i) {
            const char* pkcs7_blob = pdfr_encrypter_pubsec_recipient_pkcs7(encrypter, i, &pkcs7_size);
            
            if (!SHA1_Update(&ctx, pkcs7_blob, pkcs7_size))
                return PD_FALSE;
        }

        if (encrypter->V >= 4 && !encrypter->encrypt_metadata) {
            pduint8 added[4] = { 0xFF, 0xFF, 0xFF, 0xFF };

            if (!SHA1_Update(&ctx, added, 4))
                return PD_FALSE;
        }

        if (!SHA1_Final(digest, &ctx)) {
            free(encrypter->encryption_key);
            encrypter->encryption_key = NULL;
            return PD_FALSE;
        }

        encrypter->encryption_key = (char*)malloc(sizeof(char) * encrypter->encryption_key_length);
        memcpy(encrypter->encryption_key, digest, encrypter->encryption_key_length);

        return PD_TRUE;
    }
    else {
        SHA256_CTX ctx;
        char digest[SHA256_DIGEST_LENGTH];

        if (!SHA256_Init(&ctx))
            return PD_FALSE;

        if (!SHA256_Update(&ctx, encrypter->seed, PUBSEC_SEED_LEN))
            return PD_FALSE;

        for (pduint32 i = 0; i < recipients_count; ++i) {
            const char* pkcs7_blob = pdfr_encrypter_pubsec_recipient_pkcs7(encrypter, i, &pkcs7_size);

            if (!SHA256_Update(&ctx, pkcs7_blob, pkcs7_size))
                return PD_FALSE;
        }

        if (encrypter->V >= 4 && !encrypter->encrypt_metadata) {
            pduint8 added[4] = { 0xFF, 0xFF, 0xFF, 0xFF };

            if (!SHA256_Update(&ctx, added, 4))
                return PD_FALSE;
        }

        if (!SHA256_Final(digest, &ctx)) {
            free(encrypter->encryption_key);
            encrypter->encryption_key = NULL;
            return PD_FALSE;
        }

        encrypter->encryption_key = (char*)malloc(sizeof(char) * encrypter->encryption_key_length);
        memcpy(encrypter->encryption_key, digest, encrypter->encryption_key_length);

        return PD_TRUE;
    }

    return PD_FALSE;
}

static t_encrypter* alloc_encrypter(PDFRAS_ENCRYPT_ALGORITHM algorithm, pdbool metadata) {
    t_encrypter* encrypter = (t_encrypter*)malloc(sizeof(t_encrypter));

    encrypter->algorithm = algorithm;
    encrypter->perms = PDFRAS_PERM_UNKNOWN;
    encrypter->encrypt_metadata = metadata;
    encrypter->document_id = NULL;
    encrypter->document_id_length = 0;
    encrypter->encryption_key = NULL;
    encrypter->current_obj_number = -1;
    encrypter->current_gen_number = -1;
    encrypter->user_password = NULL;
    encrypter->owner_password = NULL;
    encrypter->O = NULL;
    encrypter->U = NULL;
    encrypter->OU_length = 0;
    encrypter->OE = NULL;
    encrypter->UE = NULL;
    encrypter->Perms = NULL;
    encrypter->OUE_length = 0;
    encrypter->Perms_length = 0;
    encrypter->encrypt_mode = PD_TRUE;
    encrypter->password_security = PD_TRUE;
    encrypter->V = 0;
    encrypter->R = 0;
    encrypter->recipients = NULL;
    encrypter->seed = NULL;
    
    switch (encrypter->algorithm)
    {
    case PDFRAS_RC4_40:
        encrypter->V = 1;
        encrypter->R = 2;
        encrypter->encryption_key_length = 5;
        break;
    case PDFRAS_RC4_128:
    case PDFRAS_AES_128:
        encrypter->V = 4;
        encrypter->R = 4;
        encrypter->encryption_key_length = 16;
        break;
    case PDFRAS_AES_256:
        encrypter->V = 5; // PDF 2.0
        encrypter->R = 6; // PDF 2.0
        encrypter->encryption_key_length = 32;
        break;
    default:
        break;
    }

    return encrypter;
}

//TODO: If memory module will be separated, then use PDFRAS memory managment functions
t_encrypter* pdfr_create_encrypter(const char* user_password, const char* owner_password, PDFRAS_PERMS perms, PDFRAS_ENCRYPT_ALGORITHM algorithm, pdbool metadata) {
    if (algorithm >= PDFRAS_UNDEFINED_ENCRYPT_ALGORITHM || algorithm < PDFRAS_RC4_40)
        return NULL;

    t_encrypter* encrypter = alloc_encrypter(algorithm, metadata);

    encrypter->password_security = PD_TRUE; 
    encrypter->perms = perms;

    if (encrypter->R <= 4) {
        encrypter->OU_length = 32;
        encrypter->O = (char*)malloc(encrypter->OU_length * sizeof(char));
        encrypter->U = (char*)malloc(encrypter->OU_length * sizeof(char));        
    }
    else if (encrypter->R >= 6) {
        encrypter->OU_length = 48;
        encrypter->O = (char*)malloc(encrypter->OU_length * sizeof(char));
        encrypter->U = (char*)malloc(encrypter->OU_length * sizeof(char));

        encrypter->OUE_length = 32;
        encrypter->OE = (char*)malloc(encrypter->OUE_length * sizeof(char));
        encrypter->UE = (char*)malloc(encrypter->OUE_length * sizeof(char));

        encrypter->Perms_length = 16;
        encrypter->Perms = (char*)malloc(encrypter->Perms_length * sizeof(char));

        if (user_password) {
            pdint32 len = (pdint32)strlen(user_password);
            encrypter->user_password = (char*)malloc(sizeof(char) * (len + 1));
            strncpy(encrypter->user_password, user_password, len);
            encrypter->user_password[len] = '\0';
        }

        if (owner_password) {
            pdint32 len = (pdint32)strlen(owner_password);
            encrypter->owner_password = (char*)malloc(sizeof(char) * (len + 1));
            strncpy(encrypter->owner_password, owner_password, len);
            encrypter->owner_password[len] = '\0';
        }
    }
    else {
        encrypter->O = NULL;
        encrypter->U = NULL;
        encrypter->OU_length = 0;
    }

    padd_passwords(encrypter, user_password, owner_password);

    return encrypter;
}

t_encrypter* pdfr_create_pubsec_encrypter(const RasterPubSecRecipient* recipients, size_t recipients_count, PDFRAS_ENCRYPT_ALGORITHM algorithm, pdbool metadata) {
    // RC4 40 bit is not supported.
    if (algorithm >= PDFRAS_UNDEFINED_ENCRYPT_ALGORITHM || algorithm < PDFRAS_RC4_128)
        return NULL;

    t_encrypter* encrypter = alloc_encrypter(algorithm, metadata);
    encrypter->password_security = PD_FALSE;

    encrypter->seed = (char*)malloc(sizeof(char) * PUBSEC_SEED_LEN);
    pdfras_generate_random_bytes(encrypter->seed, PUBSEC_SEED_LEN);

    for (size_t i = 0; i < recipients_count; ++i) {
        if (!add_recipient(&encrypter->recipients, recipients[i].pubkey, recipients[i].perms, encrypter->seed, algorithm)) {
            pdfr_destroy_encrypter(encrypter);
            return NULL;
        }
    }

    if (!encrypter->recipients) {
        pdfr_destroy_encrypter(encrypter);
        return NULL;
    }

    return encrypter;
}

pduint32 pdfr_encrypter_pubsec_recipients_count(t_encrypter* encrypter) {
    if (!encrypter || !encrypter->recipients)
        return 0;

    return recipients_count(encrypter->recipients);
}

const char* pdfr_encrypter_pubsec_recipient_pkcs7(t_encrypter* encrypter, pduint32 idx, pduint32* pkcs7_size) {
    if (!encrypter || idx < 0)
        return NULL;

    pduint32 current_idx = 0;
    t_recipient* recipient = encrypter->recipients;
    
    while (idx != current_idx && recipient) {
        ++current_idx;
        recipient = recipient->next;
    }

    if (recipient) {
        if (pkcs7_size)
            *pkcs7_size = recipient->pkcs7_blob_size;

        return recipient->pkcs7_blob;
    }

    return NULL;
}

void pdfr_destroy_encrypter(t_encrypter* encrypter) {
    if (encrypter) {
        if (encrypter->O)
            free(encrypter->O);

        if (encrypter->U)
            free(encrypter->U);

        if (encrypter->document_id)
            free(encrypter->document_id);

        if (encrypter->encryption_key)
            free(encrypter->encryption_key);

        if (encrypter->user_password)
            free(encrypter->user_password);

        if (encrypter->owner_password)
            free(encrypter->owner_password);

        if (encrypter->UE)
            free(encrypter->UE);

        if (encrypter->OE)
            free(encrypter->OE);

        if (encrypter->Perms)
            free(encrypter->Perms);

        if (encrypter->seed)
            free(encrypter->seed);

        if (encrypter->recipients)
            delete_recipients(encrypter->recipients);

        free(encrypter);
    }
}

void pdfr_encrypter_object_number(t_encrypter* encrypter, pduint32 objnum, pduint32 gennum) {
    assert(encrypter);

    encrypter->current_obj_number = objnum;
    encrypter->current_gen_number = gennum;
}

pdbool pdfr_encrypter_dictionary_data(t_encrypter* encrypter, const char* document_id, pduint32 id_len) {
    assert(encrypter);

    if (document_id != NULL && id_len > 0) {
        if (encrypter->document_id != NULL)
            free(encrypter->document_id);

        encrypter->document_id = (char*)malloc(id_len * sizeof(char));
        strncpy(encrypter->document_id, document_id, id_len);
        encrypter->document_id_length = id_len;
    }

    if (encrypter->password_security) {
        if (encrypter->R < 6) {
            // compute O
            if (compute_O(encrypter) == PD_FALSE)
                return PD_FALSE;

            // compute encryption key
            if (generate_encryption_key(encrypter) == PD_FALSE) {
                return PD_FALSE;
            }

            if (encrypter->R == 2)
                compute_U_r2(encrypter);
            else if (encrypter->R >= 3)
                compute_U_r3_4(encrypter);
        }
        else if (encrypter->R == 6) {
            // encryption key
            if (generate_encryption_key(encrypter) == PD_FALSE)
                return PD_FALSE;

            // U and UE
            if (compute_U_UE_r_6(encrypter) == PD_FALSE)
                return PD_FALSE;

            // O and OE
            if (compute_O_OE_r_6(encrypter) == PD_FALSE)
                return PD_FALSE;

            // Perms
            if (compute_Perms(encrypter) == PD_FALSE)
                return PD_FALSE;
        }
    }
    else {
        if (!generate_encryption_key_pubsec(encrypter))
            return PD_FALSE;
    }

    return PD_TRUE;
}

pdint32 pdfr_encrypter_encrypt_data(t_encrypter* encrypter, const pduint8* data_in, const pdint32 in_len, pduint8* data_out) {
    assert(encrypter);

    if (data_in == NULL)
        return -1;

    if (encrypter->current_obj_number <= 0 || encrypter->current_gen_number < 0)
        return -1;

    pdbool aes = PD_FALSE;
    if (encrypter->algorithm == PDFRAS_RC4_40 || encrypter->algorithm == PDFRAS_RC4_128)
        aes = PD_FALSE;
    else if (encrypter->algorithm == PDFRAS_AES_128 || encrypter->algorithm == PDFRAS_AES_256)
        aes = PD_TRUE;
    else
        return -1;

    int out_len = -1;
    
    if (aes)
        out_len = (in_len + 16 - (in_len % 16)) + 16;
    else 
        out_len = in_len;
    
    if (data_out == NULL)
        return out_len;

    pduint32 encryption_key_len = 0;
    char* encryption_key = NULL;

    if (encrypter->R <= 5) {
        pduint32 obj_key_len = 0;

        obj_key_len = aes == PD_TRUE ? encrypter->encryption_key_length + 9 : encrypter->encryption_key_length + 5;

        char* obj_key = (char*)malloc(sizeof(char) * obj_key_len);
        if (!obj_key)
            return -1;

        memcpy(obj_key, encrypter->encryption_key, encrypter->encryption_key_length);
        obj_key[encrypter->encryption_key_length] = (char)encrypter->current_obj_number;
        obj_key[encrypter->encryption_key_length + 1] = (char)(encrypter->current_obj_number >> 8);
        obj_key[encrypter->encryption_key_length + 2] = (char)(encrypter->current_obj_number >> 16);
        obj_key[encrypter->encryption_key_length + 3] = (char)(encrypter->current_gen_number);
        obj_key[encrypter->encryption_key_length + 4] = (char)(encrypter->current_gen_number >> 8);

        if (aes) {
            obj_key[encrypter->encryption_key_length + 5] = (char)0x73;
            obj_key[encrypter->encryption_key_length + 6] = (char)0x41;
            obj_key[encrypter->encryption_key_length + 7] = (char)0x6c;
            obj_key[encrypter->encryption_key_length + 8] = (char)0x54;
        }

        MD5_CTX md5;
        char hash[MD5_HASH_BYTES];

        if (MD5_Init(&md5) == 0) {
            free(obj_key);
            return -1;
        }

        MD5_Update(&md5, obj_key, obj_key_len);
        MD5_Final(hash, &md5);

        encryption_key_len = encrypter->encryption_key_length + 5 > 16 ? 16 : encrypter->encryption_key_length + 5;
        encryption_key = (char*)malloc(sizeof(char) * encryption_key_len);
        memcpy(encryption_key, hash, encryption_key_len);

        free(obj_key);
    }
    else {
        encryption_key = encrypter->encryption_key;
        encryption_key_len = 32;
    }

    if (aes) {
        out_len = pdfras_aes_encrypt_data(encryption_key, encryption_key_len, data_in, in_len, data_out);
    }
    else {
        out_len = pdfras_rc4_encrypt_data(encryption_key, encryption_key_len, data_in, in_len, data_out);
    }

    if (encrypter->R < 5)
        free(encryption_key);
    
    return out_len;
}

pduint8 pdfr_encrypter_get_V(t_encrypter* encrypter) {
    assert(encrypter);
    
    return encrypter->V;
}

pduint32 pdfr_encrypter_get_key_length(t_encrypter* encrypter) {
    assert(encrypter);

    return encrypter->encryption_key_length * 8;
}

pduint8 pdfr_encrypter_get_R(t_encrypter* encrypter) {
    assert(encrypter);

    return encrypter->R;
}

pduint32 pdfr_encrypter_get_OU_length(t_encrypter* encrypter) {
    assert(encrypter);

    return encrypter->OU_length;
}

const char* pdfr_encrypter_get_O(t_encrypter* encrypter) {
    assert(encrypter);

    return encrypter->O;
}

const char* pdfr_encrypter_get_U(t_encrypter* encrypter) {
    assert(encrypter);

    return encrypter->U;
}

pduint32 pdfr_encrypter_get_permissions(t_encrypter* encrypter) {
    assert(encrypter);

    return encrypter->perms;
}

pdbool pdfr_encrypter_get_metadata_encrypted(t_encrypter* encrypter) {
    assert(encrypter);

    return encrypter->encrypt_metadata;
}

PDFRAS_ENCRYPT_ALGORITHM pdfr_encrypter_get_algorithm(t_encrypter* encrypter) {
    assert(encrypter);

    return encrypter->algorithm;
}

const char* pdfr_encrypter_get_OE(t_encrypter* encrypter) {
    assert(encrypter);

    return encrypter->OE;
}

const char* pdfr_encrypter_get_UE(t_encrypter* encrypter) {
    assert(encrypter);

    return encrypter->UE;
}

pduint32 pdfr_encrypter_get_OUE_length(t_encrypter* encrypter) {
    assert(encrypter);

    return encrypter->OUE_length;
}

const char* pdfr_encrypter_get_Perms(t_encrypter* encrypter) {
    assert(encrypter);

    return encrypter->Perms;
}

pduint32 pdfr_encrypter_get_Perms_length(t_encrypter* encrypter) {
    assert(encrypter);

    return encrypter->Perms_length;
}

pdbool pdfr_encrypter_is_password_security(t_encrypter* encrypter) {
    assert(encrypter);

    return encrypter->password_security;
}

// Decryption part
t_decrypter* pdfr_create_decrypter(const RasterReaderEncryptData* encrypt_data) {
    if (!encrypt_data)
        return NULL;

    if (encrypt_data->algorithm >= PDFRAS_UNDEFINED_ENCRYPT_ALGORITHM || encrypt_data->algorithm < PDFRAS_RC4_40) {
        return NULL;
    }

    t_decrypter* decrypter = (t_decrypter*)malloc(sizeof(t_decrypter));
    
    decrypter->algorithm = encrypt_data->algorithm;
    decrypter->perms = encrypt_data->perms;
    decrypter->encrypt_metadata = encrypt_data->encrypt_metadata;
    decrypter->R = encrypt_data->R;
    decrypter->V = encrypt_data->V;
    decrypter->OU_length = encrypt_data->OU_length;
    decrypter->OUE_length = encrypt_data->OUE_length;
    decrypter->Perms_length = encrypt_data->Perms_length;
    decrypter->encryption_key_length = encrypt_data->encryption_key_length;
    decrypter->encrypt_mode = PD_FALSE;

    decrypter->encryption_key = NULL;
    decrypter->current_obj_number = -1;
    decrypter->current_gen_number = -1;
    decrypter->user_password = NULL;
    decrypter->owner_password = NULL;
    decrypter->user_password = NULL;
    decrypter->Perms = NULL;   

    decrypter->O = NULL;
    decrypter->U = NULL;
    decrypter->OE = NULL;
    decrypter->UE = NULL;
    decrypter->Perms = NULL;

    if (encrypt_data->document_id && encrypt_data->document_id_length > 0) {
        decrypter->document_id = (char*)malloc(sizeof(char) * encrypt_data->document_id_length);
        decrypter->document_id_length = encrypt_data->document_id_length;
        memcpy(decrypter->document_id, encrypt_data->document_id, encrypt_data->document_id_length);
    }
    else {
        decrypter->document_id = NULL;
        decrypter->document_id_length = 0;
    }

    decrypter->OU_length = encrypt_data->OU_length;

    if (encrypt_data->O) {
        decrypter->O = (char*)malloc(sizeof(char) * decrypter->OU_length);
        memcpy(decrypter->O, encrypt_data->O, decrypter->OU_length);
    }

    if (encrypt_data->U) {
        decrypter->U = (char*)malloc(sizeof(char) * decrypter->OU_length);
        memcpy(decrypter->U, encrypt_data->U, decrypter->OU_length);
    }
        
    if (encrypt_data->OE) {
        decrypter->OE = (char*)malloc(sizeof(char) * decrypter->OUE_length);
        memcpy(decrypter->OE, encrypt_data->OE, decrypter->OUE_length);
    }

    if (encrypt_data->UE) {
        decrypter->UE = (char*)malloc(sizeof(char) * decrypter->OUE_length);
        memcpy(decrypter->UE, encrypt_data->UE, decrypter->OUE_length);
    }

    if (encrypt_data->Perms) {
        decrypter->Perms = (char*)malloc(sizeof(char) * decrypter->Perms_length);
        memcpy(decrypter->Perms, encrypt_data->Perms, decrypter->Perms_length);
    }
  
    return decrypter;
}

void pdfr_destroy_decrypter(t_decrypter* decrypter) {
    pdfr_destroy_encrypter(decrypter);
}

static pdbool is_user(t_decrypter* decrypter, const char* password, pdbool pad) {
    char tempU[48];

    if (pad)
        padd_passwords(decrypter, password, NULL);

    if (!generate_encryption_key(decrypter))
        return PD_FALSE;

    memcpy(tempU, decrypter->U, decrypter->OU_length);
    if (decrypter->R <= 2) {
        if (!compute_U_r2(decrypter)) {
            memcpy(decrypter->U, tempU, decrypter->OU_length);
            return PD_FALSE;
        }
    }
    else if (decrypter->R >= 3 && decrypter->R < 6) {
        if (!compute_U_r3_4(decrypter)) {
            memcpy(decrypter->U, tempU, decrypter->OU_length);
            return PD_FALSE;
        }
    }
    else if (decrypter->R == 6) {
        char userValidationSalt[8];
        memcpy(userValidationSalt, decrypter->U + 32, 8);
        compute_2B(password, userValidationSalt, NULL, tempU);
    }
    else {
        memcpy(decrypter->U, tempU, decrypter->OU_length);
        return PD_FALSE;
    }

    if (decrypter->R < 6) {
        if (memcmp(tempU, decrypter->U, decrypter->OU_length) == 0)
            return PD_TRUE;

        memcpy(decrypter->U, tempU, decrypter->OU_length);
    }
    else {
        if (memcmp(tempU, decrypter->U, 32) == 0) {
            if (decrypter->encryption_key)
                free(decrypter->encryption_key);
            decrypter->encryption_key = (char*)malloc(sizeof(char) * decrypter->encryption_key_length);
            
            char userKeySalt[8];
            memcpy(userKeySalt, decrypter->U + 40, 8);
            compute_2B(password, userKeySalt, NULL, tempU);

            if (pdfras_aes_decrypt_encryption_key(tempU, 32, decrypter->UE, decrypter->OUE_length, decrypter->encryption_key) == -1)
                return PD_FALSE;

            return PD_TRUE;
        }
    }

    return PD_FALSE;
}

static pdbool is_owner(t_decrypter* decrypter, const char* password) {
    if (decrypter->R < 6) {
        padd_passwords(decrypter, NULL, password);

        // Algorithm 7
        // a
        MD5_CTX md5;
        unsigned char hash[MD5_HASH_BYTES];

        if (MD5_Init(&md5) == 0)
            return PD_FALSE;

        // a, b
        MD5_Update(&md5, decrypter->padded_op, 32);
        MD5_Final(hash, &md5);

        // c
        if (decrypter->R >= 3) {
            pduint32 i;
            for (i = 0; i < 50; ++i) {
                MD5_Init(&md5);
                MD5_Update(&md5, hash, decrypter->encryption_key_length);
                MD5_Final(hash, &md5);
            }
        }

        // d
        RC4_KEY rc4_key;
        RC4_set_key(&rc4_key, decrypter->encryption_key_length, hash);

        RC4(&rc4_key, decrypter->OU_length, decrypter->O, decrypter->padded_up);

        if (decrypter->R >= 3) {
            unsigned char key[MD5_HASH_BYTES];
            pduint32 i;
            pduint32 k;

            for (i = 1; i <= 19; ++i) {
                for (k = 0; k < decrypter->encryption_key_length; ++k) {
                    key[k] = (unsigned char)(hash[k] ^ i);
                }

                RC4_set_key(&rc4_key, decrypter->encryption_key_length, key);
                RC4(&rc4_key, 32, decrypter->padded_up, decrypter->padded_up);
            }
        }

        if (is_user(decrypter, decrypter->padded_up, PD_FALSE))
            return PD_TRUE;
    }
    else {
        char tempO[48];
        char ownerValidationSalt[8];
        
        memcpy(ownerValidationSalt, decrypter->O + 32, 8);
        compute_2B(password, ownerValidationSalt, decrypter->U, tempO);

        if (memcmp(decrypter->O, tempO, 32) == 0) {
            if (decrypter->encryption_key)
                free(decrypter->encryption_key);
            decrypter->encryption_key = (char*)malloc(sizeof(char) * decrypter->encryption_key_length);

            char ownerKeySalt[8];
            memcpy(ownerKeySalt, decrypter->O + 40, 8);
            compute_2B(password, ownerKeySalt, decrypter->U, tempO);

            if (pdfras_aes_decrypt_encryption_key(tempO, 32, decrypter->OE, decrypter->OUE_length, decrypter->encryption_key) == -1)
                return PD_FALSE;

            return PD_TRUE;
        }
    }

    return PD_FALSE;
}

PDFRAS_DOCUMENT_ACCESS pdfr_decrypter_get_document_access(t_decrypter* decrypter, const char* password) {
    // let's try authentificate user for user access
    if (!decrypter)
        return PDFRAS_DOCUMENT_NONE_ACCESS;

    if (is_user(decrypter, password, PD_TRUE))
        return PDFRAS_DOCUMENT_USER_ACCESS;

    if (is_owner(decrypter, password))
        return PDFRAS_DOCUMENT_OWNER_ACCESS;

    return PDFRAS_DOCUMENT_NONE_ACCESS;
}

pdint32 pdfr_decrypter_decrypt_data(t_decrypter* decrypter, const pduint8* data_in, const pdint32 in_len, pduint8* data_out) {
    assert(decrypter);

    if (data_in == NULL || data_out == NULL)
        return -1;

    if (decrypter->current_obj_number <= 0 || decrypter->current_gen_number < 0)
        return -1;

    pdbool aes = PD_FALSE;
    if (decrypter->algorithm == PDFRAS_RC4_40 || decrypter->algorithm == PDFRAS_RC4_128)
        aes = PD_FALSE;
    else if (decrypter->algorithm == PDFRAS_AES_128 || decrypter->algorithm == PDFRAS_AES_256)
        aes = PD_TRUE;
    else
        return -1;

    int out_len = -1;

    pduint32 decryption_key_len = 0;
    char* decryption_key = NULL;

    if (decrypter->R <= 5) {
        pduint32 obj_key_len = aes == PD_TRUE ? decrypter->encryption_key_length + 9 : decrypter->encryption_key_length + 5;
        char* obj_key = (char*)malloc(sizeof(char) * obj_key_len);
        if (!obj_key)
            return -1;

        memcpy(obj_key, decrypter->encryption_key, decrypter->encryption_key_length);
        obj_key[decrypter->encryption_key_length] = (char)decrypter->current_obj_number;
        obj_key[decrypter->encryption_key_length + 1] = (char)(decrypter->current_obj_number >> 8);
        obj_key[decrypter->encryption_key_length + 2] = (char)(decrypter->current_obj_number >> 16);
        obj_key[decrypter->encryption_key_length + 3] = (char)(decrypter->current_gen_number);
        obj_key[decrypter->encryption_key_length + 4] = (char)(decrypter->current_gen_number >> 8);

        if (aes) {
            obj_key[decrypter->encryption_key_length + 5] = (char)0x73;
            obj_key[decrypter->encryption_key_length + 6] = (char)0x41;
            obj_key[decrypter->encryption_key_length + 7] = (char)0x6c;
            obj_key[decrypter->encryption_key_length + 8] = (char)0x54;
        }

        MD5_CTX md5;
        char hash[MD5_HASH_BYTES];

        if (MD5_Init(&md5) == 0) {
            free(obj_key);
            return -1;
        }

        MD5_Update(&md5, obj_key, obj_key_len);
        MD5_Final(hash, &md5);

        decryption_key_len = decrypter->encryption_key_length + 5 > 16 ? 16 : decrypter->encryption_key_length + 5;
        decryption_key = (char*)malloc(sizeof(char) * decryption_key_len);
        memcpy(decryption_key, hash, decryption_key_len);

        free(obj_key);
    }
    else {
        decryption_key = decrypter->encryption_key;
        decryption_key_len = decrypter->encryption_key_length;
    }

    if (aes) {
        out_len = pdfras_aes_decrypt_data(decryption_key, decryption_key_len, data_in, in_len, data_out);
    }
    else {
        out_len = pdfras_rc4_decrypt_data(decryption_key, decryption_key_len, data_in, in_len, data_out);
    }

    if (decrypter->R <= 5)
        free(decryption_key);

    return out_len;
}

PDFRAS_ENCRYPT_ALGORITHM pdfr_decrypter_get_algorithm(t_decrypter* decrypter) {
    assert(decrypter);
    return pdfr_encrypter_get_algorithm(decrypter);
}

void pdfr_decrypter_object_number(t_decrypter* decrypter, pduint32 objnum, pduint32 gennum) {
    assert(decrypter);
    pdfr_encrypter_object_number(decrypter, objnum, gennum);
}

pdbool pdfr_decrypter_get_metadata_encrypted(t_decrypter* decrypter) {
    assert(decrypter);
    return pdfr_encrypter_get_metadata_encrypted(decrypter);
}
