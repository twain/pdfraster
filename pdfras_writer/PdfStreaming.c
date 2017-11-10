#include "PdfAlloc.h"
#include "PdfArray.h"
#include "PdfAtoms.h"
#include "PdfDatasink.h"
#include "PdfDict.h"
#include "PdfStandardAtoms.h"
#include "PdfStandardObjects.h"
#include "PdfStreaming.h"
#include "PdfString.h"
#include "PdfXrefTable.h"

#include <assert.h>

struct t_pdoutstream {
	fOutputWriter writer;
	t_pdencrypter *encrypter;
	void *writercookie;
	pduint32 pos;
    fOutStreamEventHandler eventHandler[PDF_OUTPUT_EVENT_COUNT];
    void* eventCookie[PDF_OUTPUT_EVENT_COUNT];
};

void pd_outstream_set_event_handler(t_pdoutstream *stm, PdfOutputEventCode eventid, fOutStreamEventHandler handler, void *cookie)
{
    if (stm && ((int)eventid >= 0) && (eventid < PDF_OUTPUT_EVENT_COUNT)) {
        stm->eventHandler[eventid] = handler;
        stm->eventCookie[eventid] = cookie;
    }
}


int pd_outstream_fire_event(t_pdoutstream *stm, PdfOutputEventCode eventid)
{
    int result = -1;
    if (stm && ((int)eventid >= 0) && (eventid < PDF_OUTPUT_EVENT_COUNT)) {
        fOutStreamEventHandler handler = stm->eventHandler[eventid];
        void* cookie = stm->eventCookie[eventid];
        if (handler) {
            result = handler(stm, cookie, eventid);
        }
    }
    return result;
}

t_pdoutstream *pd_outstream_new(t_pdmempool *pool, t_OS *os)
{
	t_pdoutstream *stm = (t_pdoutstream *)pd_alloc(pool, sizeof(t_pdoutstream));
	if (stm)
	{   // note allocated block is 0-filled
		stm->writer = os->writeout;
		stm->writercookie = os->writeoutcookie;
		// stm->pos = 0;    // redundant
	}
	return stm;
}

void pd_outstream_free(t_pdoutstream *stm)
{
	pd_free(stm);			// doesn't mind NULLs
}

///////////////////////////////////////////////////////////////////////
// Encryption

void pd_outstream_set_encrypter(t_pdoutstream *stm, t_pdencrypter *crypt)
{
	if (stm) {
		stm->encrypter = crypt;
	}
}

pdbool pd_stream_is_encrypted(t_pdoutstream *stm)
{
	return stm && stm->encrypter ? PD_TRUE : PD_FALSE;
}

t_pdencrypter* pd_outstream_get_encrypter(t_pdoutstream *stm)
{
	return stm ? stm->encrypter : NULL;
}

t_pdstring* pd_encrypt_string(t_pdoutstream *stm, t_pdstring *str)
{
	t_pdencrypter* encrypter = stm->encrypter;
	t_pdmempool* pool = pd_get_pool(str);
	// calculate encrypted size
	pduint32 strlen = pd_string_length(str);
    pdint32 enclen = pd_encrypted_size(encrypter, pd_string_data(str), strlen);
	// allocate the encrypted string
    pduint8* enc_data = (pduint8*)pd_alloc(pool, sizeof(pduint8) * enclen);
	// encrypt the data from plain string to encrypted string
    pd_encrypt_data(encrypter, pd_string_data(str), strlen, enc_data);

    t_pdstring* encstr = pd_string_new_binary(pool, enclen, enc_data);

	return encstr;
}

void pd_putc(t_pdoutstream *stm, char c)
{
	if (stm) {
		pduint8 buf[1];
		buf[0] = (pduint8)c;
		stm->pos += stm->writer(buf, 0, 1, stm->writercookie);	// data, offset, length, cookie
	}
}

void pd_putn(t_pdoutstream *stm, const void* s, pduint32 offset, pduint32 len)
{
	if (stm) {
		stm->pos += stm->writer((pduint8*)s, offset, len, stm->writercookie);
	}
}

void pd_puts(t_pdoutstream *stm, char *s)
{
	if (stm) {
		// Treat s==NULL same as empty string
		pdint32 len = s ? pdstrlen(s) : 0;
		pd_putn(stm, s, 0, len);
	}
}

void pd_puthex(t_pdoutstream *stm, pduint8 b)
{
	const char* hexdigit = "0123456789ABCDEF";
	pd_putc(stm, hexdigit[(b >> 4) & 0xF]);
	pd_putc(stm, hexdigit[b & 0xF]);
}

void pd_putint(t_pdoutstream *stm, pdint32 i)
{
	char num[12];
	pd_puts(stm, pditoa(i, num));
}

void pd_putfloat(t_pdoutstream *stm, pddouble n)
{
	// one weakness: with numbers > 10^16, you get noise digits
	// in the lower digits of the integer part.
	if (pdisnan(n)) {
		pd_puts(stm, "nan");
	}
	else if (n == 0.0) {
		pd_putc(stm, '0');
	}
	else if (pdisinf(n)) {
		if (n < 0) { pd_putc(stm, '-'); }
		pd_puts(stm, "inf");
	}
	else {
		if (n < 0) {
			pd_putc(stm, '-');
			n = -n;
		}
		// the least integer that has REAL_PRECISION digits:
		double nprec = pow(10, REAL_PRECISION-1);
		int decPt = 1, digits = 1;
		// compute w, the place-value of the leading digit
		double w = 1.0;
		while (w * 10 <= n) { w *= 10; decPt++; digits++; }
		// if n is fractional, shift it up until we find first non-zero digit:
		while (n < 1.0) { n *= 10; w *= 10; digits++; }
		// shift up more digits  from fractional part (if any) to bring
		// integer part of n to REAL_PRECISION digits:
		while (n < nprec && floor(n) != n) { n *= 10; w *= 10; digits++; }
		if (floor(n) != n && decPt == digits) {
			// would print as integer but isn't an integer,
			// make sure we print a fractional part to 'suggest' this:
			n *= 10; w *= 10; digits++;
		}
		// round that last digit to nearest.
		// Note, no effect if n is exact at this point
		n = floor(n + 0.5);
		if (w * 10 <= n) {
			// whoops, rare case where rounding adds a leading digit 1
			w *= 10; decPt++; digits++;
		}
		// now, finally, render n as a sequence of digits possibly
		// including a decimal point
		// (one weakness: with numbers > 10^16, you may get noise digits
		// in the lower digits of the integer part.)
		do {
			if (decPt-- == 0) pd_putc(stm, '.');
			int d = (int)floor(n / w);
			d = (d < 0) ? 0 : (d > 9) ? 9 : d;
			pd_putc(stm, (char)('0' + d));
			n -= d * w;
			if (n == 0 && decPt < 0) break;
			w /= 10;
		} while (--digits);
	}
}

pduint32 pd_outstream_pos(t_pdoutstream *stm)
{
	return stm ? stm->pos : 0;
}



static void writeatom(t_pdoutstream *os, t_pdatom atom)
{
	const char *str = pd_atom_name(atom);
	pd_putc(os, '/');
	while (*str)
	{
		char c = *str++;
		if (c <= (char)0x20 || c > '~' || c == '#' || c == '%' || c == '/')
		{
			pd_putc(os, '#');
			pd_puthex(os, (pduint8)c);
		}
		else
		{
			pd_putc(os, c);
		}
	}
}

// iterator for writing dictionary key-value pairs to a stream.
static pdbool itemwriter(t_pdatom key, t_pdvalue value, void *cookie)
{
	t_pdoutstream *os = (t_pdoutstream *)cookie;
	if (os) {
		pd_putc(os, ' ');
		writeatom(os, key);
		pd_putc(os, ' ');
		pd_write_value(os, value);
		return PD_TRUE;
	}
	else {
		return PD_FALSE;
	}
}

///////////////////////////////////////////////////////////////////////
// stream datasink

static pdbool stm_sink_put(const pduint8 *buffer, pduint32 offset, pduint32 len, void *cookie)
{
    t_pdoutstream *outstm = (t_pdoutstream *)cookie;
	pd_putn(outstm, buffer, offset, len);
	return PD_TRUE;
}

void stm_sink_free(void *cookie)
{
	(void)cookie;
}

static t_datasink *stream_datasink_new(t_pdoutstream *outstm)
{
	t_pdmempool* pool = pd_get_pool(outstm);
	return pd_datasink_new(pool, stm_sink_put, stm_sink_free, outstm);
}

static void stream_resolve_length(t_pdvalue stream, pduint32 len)
{
	pdbool succ;
	t_pdvalue lengthref = pd_dict_get(stream, PDA_Length, &succ);
	if (IS_REFERENCE(lengthref)) {
		pd_reference_resolve(lengthref, pdintvalue(len));
	}
}

static void writestreambody(t_pdoutstream *os, t_pdvalue dict)
{
	// create a datasink wrapper around the Stream and the outstream
	t_datasink *sink = stream_datasink_new(os);
	if (sink) {
		pd_puts(os, "\r\nstream\r\n");
        // record start of stream data
        pduint32 startpos = pd_outstream_pos(os);
        // Call the Stream's content generator to write its contents
		// to the sink (which writes it to the outstream):
        pduint32 finalpos = 0;
        if (os->encrypter != NULL && pd_encrypt_is_active(os->encrypter)) {
            fOutputWriter oldWriter = os->writer;
            void* oldWriterCookie = os->writercookie;
            os->writer = pd_encrypt_writer;
            os->writercookie = (void*)os->encrypter;

            stream_write_data(dict, sink);
            
            pduint8* data = pd_encrypt_writer_data(os->encrypter);
            pduint32 data_len = pd_encrypt_writer_data_len(os->encrypter);

            // encrypt data
            pdint32 encrypted_data_len = pd_encrypted_size(os->encrypter, data, data_len);
            pduint8* encrypted_data = NULL;
            if (encrypted_data_len > 0) {
                t_pdmempool *pool = pd_get_pool(os);
                encrypted_data = (pduint8*)pd_alloc(pool, sizeof(pduint8) * encrypted_data_len);
                pd_encrypt_data(os->encrypter, data, data_len, encrypted_data);
            }

            os->writer = oldWriter;
            os->writercookie = oldWriterCookie;

            os->writer(encrypted_data, 0, encrypted_data_len, os->writercookie);
            os->pos = startpos + encrypted_data_len;
            finalpos = pd_outstream_pos(os);

            if (encrypted_data)
                pd_free(encrypted_data);

            pd_encrypt_writer_reset(os->encrypter);
        }
        else {
            stream_write_data(dict, sink);
            finalpos = pd_outstream_pos(os);
        }
		// write the ending keyword after the stream data.
		pd_puts(os, "\r\nendstream\r\n");
		// If there's an indirect /Length entry in the Stream dictionary, resolve it
		stream_resolve_length(dict, finalpos - startpos);
		pd_datasink_free(sink);
	}
}

static void writedict(t_pdoutstream *os, t_pdvalue dict)
{
	// TODO: tricky: don't encrypt the /Encrypt dictionary.
	// How? Put an encryption-suppression flag on the dictionary?
	if (IS_DICT(dict)) {
		pd_puts(os, "<<");
		pd_dict_foreach(dict, itemwriter, os);
		// close the dictionary
		pd_puts(os, " >>");
		// If it's also a stream, append the stream<data>endstream
		if (pd_dict_is_stream(dict))
		{
			writestreambody(os, dict);
		}
	}
}

static pdbool arritemwriter(t_pdarray *arr, pduint32 currindex, t_pdvalue value, void *cookie)
{
	(void)arr; (void)currindex;
	t_pdoutstream *os = (t_pdoutstream *)cookie;
	if (!os) return PD_FALSE;
	pd_putc(os, ' ');
	pd_write_value(os, value);
	return PD_TRUE;
}

static void writearray(t_pdoutstream *os, t_pdvalue arr)
{
	if (!IS_ARRAY(arr)) return;
	pd_puts(os, "[");
	pd_array_foreach(arr.value.arrvalue, arritemwriter, os);
	pd_puts(os, " ]");
}

static void put_escaped(t_pdoutstream *stm, pduint8 c)
{
	pd_putc(stm, '\\');
	if (c < ' ')
	{	// old-school ASCII control character
		// write octal representation with leading 0.
		pd_putc(stm, '0');
		pd_putc(stm, '0' + ((c >> 3) & 7));
		pd_putc(stm, '0' + (c & 7));
	}
	else {
		pd_putc(stm, c);
	}
}

static pdbool asciter(pduint32 index, pduint8 c, void *cookie)
{
	(void)index;
	t_pdoutstream *stm = (t_pdoutstream *)cookie;
	if (c < ' ' || c == '(' || c == ')' || c == '\\')
		put_escaped(stm, c);
	else
		pd_putc(stm, c);
	return PD_TRUE;
}

static pdbool hexiter(pduint32 index, pduint8 c, void *cookie)
{
	(void)index;
	pd_puthex((t_pdoutstream *)cookie, c);
	return PD_TRUE;
}

// Write a string to stream as a hexadecimal-style string literal
static void put_hex_string(t_pdoutstream *stm, t_pdstring *str)
{
	pd_putc(stm, '<');
	pd_string_foreach(str, hexiter, stm);
	pd_putc(stm, '>');
}

static void writestring(t_pdoutstream *stm, t_pdstring *str)
{
	// If stream has encryption,
	// encrypt string contents before writing.
	// EXCEPT... the strings in the file /ID are never encrypted.
	if (pd_stream_is_encrypted(stm) && (pd_encrypt_is_active(stm->encrypter) == PD_TRUE)) {
		// encrypt the string and write it
		t_pdstring* encstr = pd_encrypt_string(stm, str);
		put_hex_string(stm, encstr);
		pd_string_free(encstr);
	}
	else if (pd_string_is_binary(str))
	{	// write using the hex string notation
		put_hex_string(stm, str);
	}
	else
	{
		// write using the ASCII notation, escaped as needed.
		pd_putc(stm, '(');
		pd_string_foreach(str, asciter, stm);
		pd_putc(stm, ')');
	}
}

void pd_write_value(t_pdoutstream *stm, t_pdvalue value)
{
	if (!stm) return;
	switch (value.pdtype)
	{
	case TPDARRAY: writearray(stm, value); break;
	case TPDNULL: pd_puts(stm, "null"); break;
	case TPDERRVALUE: pd_puts(stm, "*ERROR*"); break;
	case TPDBOOL: pd_puts(stm, value.value.boolvalue ? "true" : "false"); break;
	case TPDNUMBERINT: pd_putint(stm, value.value.intvalue); break;
	case TPDNUMBERFLOAT: pd_putfloat(stm, value.value.floatvalue); break;
	case TPDDICT: writedict(stm, value); break;		// note streams are a subcase
	case TPDNAME: writeatom(stm, value.value.namevalue); break;
	case TPDSTRING: writestring(stm, value.value.stringvalue); break;
	case TPDREFERENCE:
		pd_putint(stm, pd_reference_object_number(value));
		pd_puts(stm, " 0 R");
		break;
	}
}

void pd_write_reference_declaration(t_pdoutstream *stm, t_pdvalue ref)
{
	if (stm && IS_REFERENCE(ref)) {
		// if this indirect object has not already been written
		if (!pd_reference_is_written(ref)) {
			pduint32 onr = pd_reference_object_number(ref);
			// Tell the xref table where this object def starts
			pd_reference_set_position(ref, pd_outstream_pos(stm));
			// start definition with: <obj#> <gen#> obj<eol>
			pd_putint(stm, onr);
			pd_puts(stm, " 0 obj\n");
			if (pd_stream_is_encrypted(stm) && pd_encrypt_is_active(stm->encrypter)) {
				pd_encrypt_start_object(stm->encrypter, onr, 0);
			}
			pd_write_value(stm, pd_reference_get_value(ref));
			pd_puts(stm, "\nendobj\n");
			pd_reference_mark_written(ref);
		}
	}
}

void pd_write_pdf_header(t_pdoutstream *stm, char *version)
{
    // the conventional 2nd line comment that marks the
    // file as not being 7-bit ASCII:
	pd_puts(stm, "%PDF-");
	pd_puts(stm, version);
	pd_putc(stm, '\n');
	pd_puts(stm, "%\xE2\xE3\xCF\xD3\n");
}

void pd_write_endofdocument(t_pdoutstream *stm, t_pdxref *xref, t_pdvalue catalog, t_pdvalue info, t_pdvalue caller_trailer)
{
	if (stm) {
		// use the same storage pool as the stream:
		t_pdmempool *pool = pd_get_pool(stm);
		t_pdvalue trailer = caller_trailer;
		if (IS_NULL(trailer)) {
			// create the trailer now
			trailer = pd_trailer_new(pool, xref, catalog, info);
		}
		
		pd_xref_writeallpendingreferences(xref, stm);
        pd_outstream_fire_event(stm, PDF_EVENT_BEFORE_XREF);
		// note the position of the XREF table
		pduint32 pos = pd_outstream_pos(stm);
		// write the XREF table
		pd_xref_writetable(xref, stm);
		// write the trailer dictionary
        pd_outstream_fire_event(stm, PDF_EVENT_BEFORE_TRAILER);
        pd_puts(stm, "trailer\n");
        pd_encrypt_deactivate(stm->encrypter);
		pd_write_value(stm, trailer);
        pd_encrypt_activate(stm->encrypter);
		// write the EOF sequence, including pointer to XREF table
		pd_putc(stm, '\n');
        pd_outstream_fire_event(stm, PDF_EVENT_BEFORE_STARTXREF);
		pd_puts(stm, "startxref\n");
		pd_putint(stm, pos);
		pd_puts(stm, "\n%%EOF\n");
		// that's the last byte of output!

		// free the trailer dict, if we created it:
		if (!pd_value_eq(trailer, caller_trailer)) {
			pd_dict_free(trailer);
		}
	}
}

// Writer
extern fOutputWriter pd_outputstream_set_writer(t_pdoutstream* stm, fOutputWriter writer) {
    assert(stm);
    assert(writer);

    fOutputWriter ret = stm->writer;
    stm->writer = writer;

    return ret;
}

// Cookie
extern void* pd_outputstream_set_cookie(t_pdoutstream* stm, void* cookie) {
    assert(stm);

    void* ret = stm->writercookie;
    stm->writercookie = cookie;

    return ret;
}
