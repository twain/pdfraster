#include <assert.h>

#include "PdfStandardObjects.h"
#include "PdfString.h"
#include "PdfStrings.h"
#include "PdfStandardAtoms.h"
#include "PdfDict.h"
#include "PdfArray.h"
#include "PdfContentsGenerator.h"

#include "md5.h"

// format unsigned integer n into w characters with leading 0's
// place at p with trailing NUL and return pointer to that NUL.
char* pdatoulz(char* p, pduint32 n, int w)
{
	char digits[12];
	pditoa(n, digits);
	// figure out how many digits to represent n
	int d = pdstrlen(digits);
	// lay down those leading 0's
	while (w > d) {
		*p++ = '0'; w--;
	}
	// append the digits
	pd_strcpy(p, w+1, digits);
	// step over them
	p += d;
	*p = (char)0;
	return p;
}

static long get_local_time_and_offset(time_t t, struct tm *ptm)
{
	long UTCoff;
#if defined(WIN32) && (_MSC_VER >= 1900)
	// get local time
	localtime_s(ptm, &t);
	// get the offset in seconds from local time to UTC:
	_get_timezone(&UTCoff);
	// We want the offset FROM UTC to local, in minutes:
	UTCoff = -UTCoff / 60;
#elif defined(__GNUC__)
    if (localtime_r(&t, ptm)) {
        // get offset from UTC to local time, including daylight saving
        // in minutes:
        UTCoff = ptm->tm_gmtoff / 60;
    }
#else
	// get local time
	*ptm = *localtime(&t);
	// localtime sets _timezone as a side-effect
	// _timezone is offset from localtime to UTC in seconds.
	// We want the offset FROM UTC to local, in minutes:
	UTCoff = -_timezone / 60;
#endif
	return UTCoff;
}

char* pd_format_time(time_t t, char* p, size_t dstlen)
{
	// local time structure
	struct tm tmp;
	// The offset FROM UTC to local in minutes.
	long UTCoff = get_local_time_and_offset(t, &tmp);
	char chSign = '+';
	// if output doesn't have enough room for output
	// including trailing NUL, fail.
	if (dstlen < 23)
	{
		// fail
		return NULL;
	}

	// "A PLUS SIGN as the value of the O field signifies that local time is at or later than UT,
	// a HYPHEN - MINUS signifies that local time is earlier than UT
	if (UTCoff < 0) {
		chSign = '-'; UTCoff = -UTCoff;
	}
	//else if (UTCoff == 0) chSign = 'Z';		// is this necessary or right?
	*p++ = 'D'; *p++ = ':';
	p = pdatoulz(p, tmp.tm_year + 1900, 4);
	p = pdatoulz(p, tmp.tm_mon + 1, 2);
	p = pdatoulz(p, tmp.tm_mday, 2);
	p = pdatoulz(p, tmp.tm_hour, 2);
	p = pdatoulz(p, tmp.tm_min, 2);
	p = pdatoulz(p, tmp.tm_sec, 2);
	// append offset FROM UTC TO local time in the form <sign>HH'mm
	*p++ = chSign;
	p = pdatoulz(p, UTCoff / 60, 2);
	*p++ = '\'';
	return pdatoulz(p, UTCoff % 60, 2);
}

char* pd_format_xmp_time(time_t t, char* p, size_t dstlen)
{
	struct tm tmp;
	// offset from UTC to local, in minutes:
	long UTCoff = get_local_time_and_offset(t, &tmp);
	char chSign = '+';

	// IF not enough output room, fail immediately
	if (dstlen < 26) {
		return NULL;
	}

	// Format the time per XMP basic metadata
	// YYYY-MM-DDThh:mm:ssOZZ:ZZ
	p = pdatoulz(p, tmp.tm_year + 1900, 4);
	*p++ = '-';
	p = pdatoulz(p, tmp.tm_mon + 1, 2);
	*p++ = '-';
	p = pdatoulz(p, tmp.tm_mday, 2);
	*p++ = 'T';
	p = pdatoulz(p, tmp.tm_hour, 2);
	*p++ = ':';
	p = pdatoulz(p, tmp.tm_min, 2);
	*p++ = ':';
	p = pdatoulz(p, tmp.tm_sec, 2);
	// append offset to local time from UTC, in the form <sign>hh:mm
	// "A PLUS SIGN as the value of the O field signifies that local time is at or later than UT,
	// a HYPHEN - MINUS signifies that local time is earlier than UT
	if (UTCoff < 0) {
		chSign = '-'; UTCoff = -UTCoff;
	}
	*p++ = chSign;
	p = pdatoulz(p, UTCoff / 60, 2);
	*p++ = ':';
	return pdatoulz(p, UTCoff % 60, 2);
}

t_pdvalue pd_make_time_string(t_pdmempool *alloc, time_t t)
{
	char szText[32];
	pd_format_time(t, szText, ELEMENTS(szText));
	return pdcstrvalue(alloc, szText);
}

t_pdvalue pd_make_now_string(t_pdmempool *alloc)
{
	time_t t;
	time(&t);
	return pd_make_time_string(alloc, t);
}

t_pdvalue pd_catalog_new(t_pdmempool *alloc, t_pdxref *xref)
{
	t_pdvalue catdict = pd_dict_new(alloc, 20);
	t_pdvalue pagesdict = pd_dict_new(alloc, 3);
	pd_dict_put(catdict, PDA_Type, pdatomvalue(PDA_Catalog));
	pd_dict_put(catdict, PDA_Pages, pd_xref_makereference(xref, pagesdict));

	pd_dict_put(pagesdict, PDA_Type, pdatomvalue(PDA_Pages));
	pd_dict_put(pagesdict, PDA_Kids, pdarrayvalue(pd_array_new(alloc, 10)));
	pd_dict_put(pagesdict, PDA_Count, pdintvalue(0));

	return pd_xref_makereference(xref, catdict);
}

t_pdvalue pd_info_new(t_pdmempool *alloc, t_pdxref *xref)
{
	t_pdvalue infodict = pd_dict_new(alloc, 8);
	return pd_xref_makereference(xref, infodict);
}

static pdbool hash_string_value(t_pdatom atom, t_pdvalue value, void *cookie)
{
	(void)atom;		// unused
	if (IS_STRING(value)) {
		MD5_CTX* md5 = (MD5_CTX*)cookie;
		t_pdstring *str = value.value.stringvalue;
		MD5_Update(md5, pd_string_data(str), pd_string_length(str));
	}
	return PD_TRUE;
}

t_pdvalue pd_generate_file_id(t_pdmempool *alloc, t_pdvalue info)
{
	// Construct the current document ID (an MD5 hash key)
	// We use only the string-valued entries in the DID.
	MD5_CTX md5;
	MD5_Init(&md5);
	// hash all the string values in the Info dictionary into the MD5 hash:
	pd_dict_foreach(info, hash_string_value, &md5);
	// get the 16-byte MD5 digest:
	unsigned char digest[16];
	MD5_Final(digest, &md5);
	// make a 2-element array
	t_pdarray *file_id = pd_array_new(alloc, 2);
	// containing the hash as a binary string, twice
	pd_array_add(file_id, pdstringvalue(pd_string_new_binary(alloc, sizeof digest, digest)));
	pd_array_add(file_id, pdstringvalue(pd_string_new_binary(alloc, sizeof digest, digest)));
	// TODO: don't encrypt the ID array!
	//pd_dont_encrypt(file_id);
	return pdarrayvalue(file_id);
}

t_pdvalue pd_trailer_new(t_pdmempool *alloc, t_pdxref *xref, t_pdvalue catalog, t_pdvalue info)
{
	t_pdvalue trailer = pd_dict_new(alloc, 4);
	pd_dict_put(trailer, PDA_Size, pdintvalue(pd_xref_size(xref)));
	pd_dict_put(trailer, PDA_Root, catalog);
	if (!IS_ERR(info))
		pd_dict_put(trailer, PDA_Info, info);
	return trailer;
}

t_pdvalue pd_page_new_simple(t_pdmempool *alloc, t_pdxref *xref, t_pdvalue catalog, double width, double height)
{
	pdbool succ;
	double box[4] = { 0.0, 0.0, width, height };

	t_pdvalue pagedict = pd_dict_new(alloc, 20);
	t_pdvalue pagesdict = pd_dict_get(catalog, PDA_Pages, &succ); /* this is a reference */
	t_pdvalue resources = pd_dict_new(alloc, 1);
	assert(IS_REFERENCE(pagesdict));

	pd_dict_put(pagedict, PDA_Type, pdatomvalue(PDA_Page));
	pd_dict_put(pagedict, PDA_Parent, pagesdict);
	pd_dict_put(pagedict, PDA_MediaBox, pdarrayvalue(pd_array_buildfloats(alloc, 4, box)));
	pd_dict_put(pagedict, PDA_Resources, resources);
	pd_dict_put(resources, PDA_XObject, pd_dict_new(alloc, 20));
	return pd_xref_makereference(xref, pagedict);
}

void pd_catalog_add_page(t_pdvalue catalog, t_pdvalue page)
{
	pdbool succ;
	t_pdvalue pagesdict = pd_dict_get(catalog, PDA_Pages, &succ); /* this is a reference */
	t_pdvalue kidsarr = pd_dict_get(pagesdict, PDA_Kids, &succ);
	t_pdvalue count = pd_dict_get(pagesdict, PDA_Count, &succ);
	assert(IS_REFERENCE(pagesdict));
	assert(IS_DICT(pd_reference_get_value(pagesdict)));
	assert(IS_ARRAY(kidsarr));
	assert(IS_INT(count));
	// append the new page to the /Kids array
	pd_array_add(kidsarr.value.arrvalue, page);
	// increment the total page count
	pd_dict_put(pagesdict, PDA_Count, pdintvalue(count.value.intvalue + 1));
}

t_pdvalue pd_contents_new(t_pdmempool *pool, t_pdxref *xref, t_pdcontents_gen *gen)
{
	t_pdvalue contents = stream_new(pool, xref, 0, pd_contents_generate, gen);
	pd_dict_put(contents, PDA_Length, pd_xref_create_forward_reference(xref));
	return contents;
}

void pd_page_add_image(t_pdvalue page, t_pdatom imageatom, t_pdvalue image)
{
	pdbool succ;
	pd_dict_put(pd_dict_get(pd_dict_get(page, PDA_Resources, &succ), PDA_XObject, &succ), imageatom, image);
}

t_pdvalue pd_metadata_new(t_pdmempool *alloc, t_pdxref *xref, f_on_datasink_ready ready, void *eventcookie)
{
	t_pdvalue metadata = stream_new(alloc, xref, 3, ready, eventcookie);
	if (IS_ERR(metadata)) return metadata;
	pd_dict_put(metadata, PDA_Type, pdatomvalue(PDA_Metadata));
	pd_dict_put(metadata, PDA_Subtype, pdatomvalue(PDA_XML));
	pd_dict_put(metadata, PDA_Length, pd_xref_create_forward_reference(xref));
	return metadata;
}
