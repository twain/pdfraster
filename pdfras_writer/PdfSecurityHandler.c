#include "PdfSecurityHandler.h"
#include "PdfAlloc.h"

struct t_pdencrypter {
	void*		cookie;			// data specific to a particular class of encrypter
	pduint32	onr, gen;		// number & generation of current object
};

t_pdencrypter* pd_encrypt_new(t_pdmempool* pool, void *cookie)
{
	t_pdencrypter* crypter = (t_pdencrypter*)pd_alloc(pool, sizeof(t_pdencrypter));
	if (crypter) {
		crypter->cookie = cookie;
	}
	return crypter;
}

void pd_encrypt_free(t_pdencrypter* crypter)
{
	pd_free(crypter);
}

void pd_encrypt_start_object(t_pdencrypter *crypter, pduint32 onr, pduint32 gen)
{
	crypter->onr = onr;
	crypter->gen = gen;
}

pduint32 pd_encrypted_size(t_pdencrypter *crypter, pduint32 n)\
{
	(void)crypter;
	// for our supported encryptions, output size = input size.
	return n;
}

void pd_encrypt_data(t_pdencrypter *crypter, pduint8 *outbuf, const pduint8* data, pduint32 n)
{
	(void)crypter;
	(void)data;
	pduint32 i;
	for (i = 0; i < n; i++) {
		outbuf[i] = '$';		// TODO: real encryption...
	}
}

