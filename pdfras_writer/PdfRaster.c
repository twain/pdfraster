// PdfRaster.c - functions to write PDF/raster
//
#include <assert.h>

#include "PdfRaster.h"
#include "PdfDict.h"
#include "PdfAtoms.h"
#include "PdfStandardAtoms.h"
#include "PdfString.h"
#include "PdfStrings.h"
#include "PdfXrefTable.h"
#include "PdfStandardObjects.h"
#include "PdfImage.h"
#include "PdfArray.h"
#include "PdfDigitalSignature.h"

struct t_pdfrasencoder {
	t_pdmempool*		pool;
	int					apiLevel;			// caller's specified API level.
	t_pdoutstream*		stm;				// output PDF stream
	void *				writercookie;
	time_t				creationDate;
	t_pdatomtable*		atoms;				// the atom table/dictionary
	// standard document objects
	t_pdxref*			xref;
	t_pdvalue			catalog;
	t_pdvalue			info;
	t_pdvalue			trailer;
	// optional document objects
	t_pdvalue			rgbColorspace;		// current colorspace for RGB images
	pdbool				bitonalUncal;		// use uncalibrated /DeviceGray for bitonal images
	// page parameters, apply to subsequently started pages
    int                 next_page_rotation;
    double              next_page_xdpi;
    double              next_page_ydpi;
	RasterPixelFormat	next_page_pixelFormat;		// how pixels are represented
	RasterCompression	next_page_compression;		// compression setting for next page

    // current page object
	t_pdvalue			currentPage;
    int					strips;				// number of strips on current page
    int					height;				// total pixel height of current page

    // page parameters, established at start of page or when first strip
    // is written
	int					rotation;			// page rotation (degrees clockwise)
	int					width;				// image width in pixels
    double				xdpi;				// horizontal resolution, pixels/inch
    double				ydpi;				// vertical resolution, pixels/inch
    RasterPixelFormat   pixelFormat;        // format of pixels
    RasterCompression   compression;        // compression algorithm
    t_pdvalue           colorspace;         // colorspace
    int					phys_pageno;		// physical page number
    int					page_front;			// front/back/unspecified

    // digital signature data
    t_pdfdigitalsignature* signer;
};

static t_pdfrasencoder* create_encoder(int apiLevel, t_OS* os) {
    struct t_pdmempool *pool;

    if (apiLevel < 1) {
        // TODO: report error
        // invalid apiLevel parameter value
        return NULL;
    }
    if (apiLevel > 1) {
        // TODO: report error
        // Caller was compiled for a later version of this API
        return NULL;
    }
    assert(os);
    // create a memory management pool for the internal use of this encoder.
    pool = pd_alloc_new_pool(os);
    assert(pool);

    t_pdfrasencoder *enc = (t_pdfrasencoder *)pd_alloc(pool, sizeof(t_pdfrasencoder));
    if (enc)
    {
        enc->pool = pool;						// associated allocation pool
        enc->apiLevel = apiLevel;				// level of this API assumed by caller
        enc->stm = pd_outstream_new(pool, os);	// our PDF-output stream abstraction

        enc->next_page_rotation = 0;						// default page rotation
        enc->next_page_xdpi = enc->next_page_ydpi = 300;    // default resolution
        enc->next_page_compression = PDFRAS_UNCOMPRESSED;	// default compression for next page
        enc->next_page_pixelFormat = PDFRAS_BITONAL;		// default pixel format
        enc->phys_pageno = -1;			    // unspecified
        enc->page_front = -1;			    // unspecified

        enc->signer = NULL;
        
        // initial atom table
        enc->atoms = pd_atom_table_new(pool, 128);
        // empty cross-reference table:
        enc->xref = pd_xref_new(pool);
        // initial document catalog:
        enc->catalog = pd_catalog_new(pool, enc->xref);

        // create 'info' dictionary
        enc->info = pd_info_new(pool, enc->xref);
        // and trailer dictionary
        enc->trailer = pd_trailer_new(pool, enc->xref, enc->catalog, enc->info);
        // default Producer
        pd_dict_put(enc->info, PDA_Producer, pdcstrvalue(pool, "PdfRaster encoder " PDFRAS_LIBRARY_VERSION));
        // record creation date & time:
        time(&enc->creationDate);
        pd_dict_put(enc->info, PDA_CreationDate, pd_make_time_string(pool, enc->creationDate));
        // we don't modify PDF so there is no ModDate

        assert(IS_NULL(enc->rgbColorspace));
        assert(IS_NULL(enc->currentPage));
    }

    return enc;
}

t_pdfrasencoder* pdfr_encoder_create(int apiLevel, t_OS *os)
{
    t_pdfrasencoder* enc = create_encoder(apiLevel, os);
	
    if (enc)
		pd_write_pdf_header(enc->stm, "1.7");
	
    return enc;
}

t_pdfrasencoder* pdfr_signed_encoder_create(int apiLevel, t_OS* os, const char* pfx_file, const char* password) {
    t_pdfrasencoder* enc = create_encoder(apiLevel, os);
    if (!enc)
        return NULL;

    enc->signer = digitalsignature_create(enc, pfx_file, password);
    if (!enc->signer) {
        pdfr_encoder_destroy(enc);
        return NULL;
    }
    
    pd_write_pdf_header(enc->stm, "1.7");

    return enc;
}

t_pdmempool* pdfr_encoder_mempool(t_pdfrasencoder* encoder) {
    return encoder->pool;
}

fOutputWriter pdfr_encoder_set_outputwriter(t_pdfrasencoder* encoder, fOutputWriter writer) {
    assert(writer);

    return pd_outputstream_set_writer(encoder->stm, writer);
    
}

void* pdfr_encoder_set_cookie(t_pdfrasencoder* encoder, void* cookie) {
    return pd_outputstream_set_cookie(encoder->stm, cookie);
}

t_pdvalue* pdfr_encoder_catalog(t_pdfrasencoder* encoder) {
    return &encoder->catalog;
}

t_pdxref* pdfr_encoder_xref(t_pdfrasencoder* encoder) {
    return encoder->xref;
}

t_pdvalue* pdfr_encoder_currentpage(t_pdfrasencoder* encoder) {
    return &encoder->currentPage;
}

void pdfr_encoder_set_creator(t_pdfrasencoder *enc, const char* creator)
{
	pd_dict_put(enc->info, PDA_Creator, pdcstrvalue(enc->pool, creator));
}

void pdfr_encoder_set_author(t_pdfrasencoder *enc, const char* author)
{
	pd_dict_put(enc->info, PDA_Author, pdcstrvalue(enc->pool, author));
}

void pdfr_encoder_set_title(t_pdfrasencoder *enc, const char* title)
{
	pd_dict_put(enc->info, PDA_Title, pdcstrvalue(enc->pool, title));
}

void pdfr_encoder_set_subject(t_pdfrasencoder *enc, const char* subject)
{
	pd_dict_put(enc->info, PDA_Subject, pdcstrvalue(enc->pool, subject));
}

void pdfr_encoder_set_keywords(t_pdfrasencoder *enc, const char* keywords)
{
	pd_dict_put(enc->info, PDA_Keywords, pdcstrvalue(enc->pool, keywords));
}

void f_write_string(t_datasink *sink, void *eventcookie)
{
	const char* xmpdata = (const char*)eventcookie;
	pd_datasink_put(sink, xmpdata, 0, pdstrlen(xmpdata));
}

void pdfr_encoder_get_creation_date(t_pdfrasencoder *enc, time_t *t)
{
	*t = enc->creationDate;
}

void pdfr_encoder_write_document_xmp(t_pdfrasencoder *enc, const char* xmpdata)
{
	t_pdvalue xmpstm = pd_metadata_new(enc->pool, enc->xref, f_write_string, (void*)xmpdata);
	// flush the metadata stream to output immediately
	pd_write_reference_declaration(enc->stm, xmpstm);
	pd_dict_put(enc->catalog, PDA_Metadata, xmpstm);
}

void pdfr_encoder_write_page_xmp(t_pdfrasencoder *enc, const char* xmpdata)
{
	t_pdvalue xmpstm = pd_metadata_new(enc->pool, enc->xref, f_write_string, (void*)xmpdata);
	// flush the metadata stream to output immediately
	pd_write_reference_declaration(enc->stm, xmpstm);
	pd_dict_put(enc->currentPage, PDA_Metadata, xmpstm);
}

void pdfr_encoder_set_resolution(t_pdfrasencoder *enc, double xdpi, double ydpi)
{
	enc->next_page_xdpi = xdpi;
	enc->next_page_ydpi = ydpi;
}

// Set the rotation for subsequent pages.
// Values that are not multiple of 90 are *ignored*.
// Valid values are mapped into the range 0, 90, 180, 270.
void pdfr_encoder_set_rotation(t_pdfrasencoder* enc, int degCW)
{
	while (degCW < 0) degCW += 360;
    degCW = degCW % 360;
	if (degCW % 90 == 0) {
		enc->next_page_rotation = degCW;
	}
}

void pdfr_encoder_set_pixelformat(t_pdfrasencoder* enc, RasterPixelFormat format)
{
	enc->next_page_pixelFormat = format;
}

// establishes compression to be used the next time a page is
// started (on first strip write).
void pdfr_encoder_set_compression(t_pdfrasencoder* enc, RasterCompression comp)
{
	enc->next_page_compression = comp;
}

int pdfr_encoder_set_bitonal_uncalibrated(t_pdfrasencoder* enc, int uncal)
{
    int previous = (enc->bitonalUncal != 0);
	enc->bitonalUncal = (uncal != 0);
    return previous;
}

void pdfr_encoder_define_calrgb_colorspace(t_pdfrasencoder* enc, double gamma[3], double black[3], double white[3], double matrix[9])
{
    enc->rgbColorspace =
        pd_make_calrgb_colorspace(enc->pool, gamma, black, white, matrix);
}

void pdfr_encoder_define_rgb_icc_colorspace(t_pdfrasencoder* enc, const pduint8 *profile, size_t len)
{
    if (!profile) {
        enc->rgbColorspace = pd_make_srgb_colorspace(enc->pool, enc->xref);
    }
    else {
        // define the calibrated (ICCBased) colorspace that should
        // be used on RGB images (if they aren't marked DeviceRGB)
        enc->rgbColorspace =
            pd_make_iccbased_rgb_colorspace(enc->pool, enc->xref, profile, len);
    }
}

int pdfr_encoder_start_page(t_pdfrasencoder* enc, int width)
{
	if (IS_DICT(enc->currentPage)) {
		pdfr_encoder_end_page(enc);
	}
    assert(IS_NULL(enc->currentPage));
	enc->width = width;
    // put the 'next page' settings into effect for this page
    enc->xdpi = enc->next_page_xdpi;
    enc->ydpi = enc->next_page_ydpi;
    enc->rotation = enc->next_page_rotation;
    // reset strip count and row count
	enc->strips = 0;				// number of strips written to current page
	enc->height = 0;				// height of current page so far

	double W = width / enc->xdpi * 72.0;
	// Start a new page (of unknown height)
	enc->currentPage = pd_page_new_simple(enc->pool, enc->xref, enc->catalog, W, 0);
	assert(IS_REFERENCE(enc->currentPage));
    assert(IS_DICT(pd_reference_get_value(enc->currentPage)));

    if (enc->signer) {
        if (digitalsignature_written(enc->signer) == PD_FALSE)
            digitalsignature_set_page(enc->signer, enc->currentPage);
    }

	return 0;
}

void pdfr_encoder_set_physical_page_number(t_pdfrasencoder* enc, int phpageno)
{
	enc->phys_pageno = phpageno;
}

void pdfr_encoder_set_page_front(t_pdfrasencoder* enc, int frontness)
{
	enc->page_front = frontness;
}


typedef struct {
	const pduint8* data;
	size_t count;
} t_stripinfo;

static void onimagedataready(t_datasink *sink, void *eventcookie)
{
	t_stripinfo* pinfo = (t_stripinfo*)eventcookie;
	pd_datasink_put(sink, pinfo->data, 0, pinfo->count);
}

t_pdvalue pdfr_encoder_get_rgb_colorspace(t_pdfrasencoder* enc)
{
    // if there's no current calibrated RGB ColorSpace
	if (IS_NULL(enc->rgbColorspace)) {
        // define the default calibrated RGB colorspace as an ICCBased
        // sRGB colorspace:
        pdfr_encoder_define_rgb_icc_colorspace(enc, NULL, 0);
	}
    // flush the colorspace profile to the output
    t_pdvalue profile = pd_array_get(enc->rgbColorspace.value.arrvalue, 1);
    pd_write_reference_declaration(enc->stm, profile);
    // return the current calibrated RGB colorspace
    return enc->rgbColorspace;
}

t_pdvalue pdfr_encoder_get_calgray_colorspace(t_pdfrasencoder* enc)
{
	double black[3] = { 0.0, 0.0, 0.0 };
	// Should this be D65? [0.9505, 1.0000, 1.0890]?  Does it matter?
	double white[3] = { 1.0, 1.0, 1.0 };
	// "The Gamma  entry shall be present in the CalGray colour space dictionary with a value of 2.2."
	double gamma = 2.2;
	return pd_make_calgray_colorspace(enc->pool, gamma, black, white);
}

t_pdvalue pdfr_encoder_get_colorspace(t_pdfrasencoder* enc)
{
	switch (enc->pixelFormat) {
	case PDFRAS_RGB24:
	case PDFRAS_RGB48:
        // retrieve the current calibrated colorspace, which may be either
        // a CalRGB space or an ICCBased space.
        return pdfr_encoder_get_rgb_colorspace(enc);
	case PDFRAS_BITONAL:
		// "Bitonal images shall be represented by an image XObject dictionary with DeviceGray
		// or CalGray as the value of its ColorSpace entry..."
		if (enc->bitonalUncal) {
			return pdatomvalue(PDA_DeviceGray);
		}
        // else use /CalGray
	case PDFRAS_GRAY8:
	case PDFRAS_GRAY16:
		// "Grayscale images shall be represented by an image XObject dictionary with CalGray
		// as the value of its ColorSpace entry..."
        // Note, DeviceGray and ICCBased are not options.
		return pdfr_encoder_get_calgray_colorspace(enc);
	default:
		break;
	} // switch
	return pderrvalue();
}

static void start_strip_zero(t_pdfrasencoder* enc)
{
    enc->compression = enc->next_page_compression;
    enc->pixelFormat = enc->next_page_pixelFormat;
    enc->colorspace = pdfr_encoder_get_colorspace(enc);
}

int pdfr_encoder_write_strip(t_pdfrasencoder* enc, int rows, const pduint8 *buf, size_t len)
{
    if (enc->strips == 0) {
        // first strip on this page, all strips on page
        // must have same format, compression and colorspace.
        start_strip_zero(enc);
    }
	char stripname[5+12] = "strip";

	e_ImageCompression comp = kCompNone;
	switch (enc->compression) {
	case PDFRAS_CCITTG4:
		comp = kCompCCITT;
		break;
	case PDFRAS_JPEG:
		comp = kCompDCT;
		break;
	default:
		break;
	}
	int bitsPerComponent = 8;
	switch (enc->pixelFormat) {
	case PDFRAS_BITONAL:
		bitsPerComponent = 1;
		break;
	case PDFRAS_GRAY16:
	case PDFRAS_RGB48:
		bitsPerComponent = 16;
		break;
	default:
		break;
	} // switch
	t_stripinfo stripinfo;
	stripinfo.data = buf;
	stripinfo.count = len;
	t_pdvalue image = pd_image_new_simple(enc->pool, enc->xref, onimagedataready, &stripinfo,
		enc->width, rows, bitsPerComponent,
		comp,
		kCCIITTG4, PD_FALSE,			// ignored unless compression is CCITT
		enc->colorspace);
	// get a reference to this (strip) image
	t_pdvalue imageref = pd_xref_makereference(enc->xref, image);
	pditoa(enc->strips, stripname + 5);
	// turn strip name into an atom
	t_pdatom strip = pd_atom_intern(enc->atoms, stripname);
	// add the image to the resources of the current page, with the given name
	pd_page_add_image(enc->currentPage, strip, imageref);
	// flush the image stream
	pd_write_reference_declaration(enc->stm, imageref);
	// adjust total page height:
	enc->height += rows;
	// increment strip count:
	enc->strips++;

	return 0;
}

int pdfr_encoder_get_page_height(t_pdfrasencoder* enc)
{
	return enc->height;
}

// callback to generate the content text for a page.
// it draws the strips of the page in order from top to bottom.
static void content_generator(t_pdcontents_gen *gen, void *cookie)
{
	int n;
	t_pdfrasencoder* enc = (t_pdfrasencoder*)cookie;
	// compute width & height of page in PDF points
	double W = enc->width / enc->xdpi * 72.0;
	double H = enc->height / enc->ydpi * 72.0;
	// horizontal (x) offset is always 0 - flush to left edge.
	double tx = 0;
	// vertical offset starts at top of page
	double ty = H;
	pdbool succ;
	t_pdvalue res = pd_dict_get(enc->currentPage, PDA_Resources, &succ);
	t_pdvalue xobj = pd_dict_get(res, PDA_XObject, &succ);
	for (n = 0; n < enc->strips; n++) {
		char stripNname[5+12] = "strip";
		pditoa(n, stripNname + 5);
		// turn strip name into an atom
		t_pdatom stripNatom = pd_atom_intern(enc->atoms, stripNname);
		// find the strip Image resource
		t_pdvalue img = pd_dict_get(xobj, stripNatom, &succ);
		// get its /Height
		t_pdvalue striph = pd_dict_get(img, PDA_Height, &succ);
		// calculate height in Points
		double SH = striph.value.intvalue * 72.0 / enc->ydpi;
		pd_gen_gsave(gen);
		pd_gen_concatmatrix(gen, W, 0, 0, SH, tx, ty-SH);
		pd_gen_xobject(gen, stripNatom);
		pd_gen_grestore(gen);
		ty -= SH;
	}
}

static void update_media_box(t_pdfrasencoder* enc, t_pdvalue page)
{
	pdbool success = PD_FALSE;
	t_pdvalue box = pd_dict_get(page, PDA_MediaBox, &success);
	assert(success);
	assert(IS_ARRAY(box));
	double W = enc->width / enc->xdpi * 72.0;
	double H = enc->height / enc->ydpi * 72.0;
	pd_array_set(box.value.arrvalue, 2, pdfloatvalue(W));
	pd_array_set(box.value.arrvalue, 3, pdfloatvalue(H));
}

static void write_page_metadata(t_pdfrasencoder* enc)
{
	if (enc->page_front >= 0 || enc->phys_pageno >= 0) {
		t_pdvalue modTime = pd_make_now_string(enc->pool);
		t_pdvalue privDict = pd_dict_new(enc->pool, 2);
		if (enc->phys_pageno >= 0) {
			pd_dict_put(privDict, PDA_PhysicalPageNumber, pdintvalue(enc->phys_pageno));
		}
		if (enc->page_front >= 0) {
			pd_dict_put(privDict, PDA_FrontSide, pdboolvalue(enc->page_front == 1));
		}
		t_pdvalue appDataDict = pd_dict_new(enc->pool, 2);
		pd_dict_put(appDataDict, PDA_LastModified, modTime);
		pd_dict_put(appDataDict, PDA_Private, privDict);
		t_pdvalue pieceInfo = pd_dict_new(enc->pool, 2);
		pd_dict_put(pieceInfo, PDA_PDFRaster, appDataDict);
		pd_dict_put(enc->currentPage, PDA_PieceInfo, pieceInfo);
		pd_dict_put(enc->currentPage, PDA_LastModified, modTime);
	}
}

int pdfr_encoder_end_page(t_pdfrasencoder* enc)
{
	if (!IS_NULL(enc->currentPage)) {
        // digital signature (if set then created needed dictionaries)
        if (enc->signer) {
            if (digitalsignature_written(enc->signer) == PD_FALSE)
                digitalsignature_create_dictionaries(enc->signer);
        }

		// create a content generator
		t_pdcontents_gen *gen = pd_contents_gen_new(enc->pool, content_generator, enc);
		// create contents object (stream)
		t_pdvalue contents = pd_xref_makereference(enc->xref, pd_contents_new(enc->pool, enc->xref, gen));
		// flush (write) the contents stream
		pd_write_reference_declaration(enc->stm, contents);
		// add the contents to the current page
		pd_dict_put(enc->currentPage, PDA_Contents, contents);
		// update the media box (we didn't really know the height until now)
		update_media_box(enc, enc->currentPage);
		if (enc->rotation != 0) {
			pd_dict_put(enc->currentPage, PDA_Rotate, pdintvalue(enc->rotation));
		}
		// metadata - add to page if any is specified
		write_page_metadata(enc);
		// flush (write) the current page
		pd_write_reference_declaration(enc->stm, enc->currentPage);
		// add the current page to the catalog (page tree)
		pd_catalog_add_page(enc->catalog, enc->currentPage);
		// done with current page:
		enc->currentPage = pdnullvalue();
	}
    // clear one-time page metadata
    enc->phys_pageno = -1;			// unspecified
    enc->page_front = -1;			// unspecified
    return 0;
}

int pdfr_encoder_page_count(t_pdfrasencoder* enc)
{
	int pageCount = -1;
	if (enc) {
		pdbool succ;
		t_pdvalue pagesdict = pd_dict_get(enc->catalog, PDA_Pages, &succ);
		assert(succ);
		if (succ) {
			t_pdvalue count = pd_dict_get(pagesdict, PDA_Count, &succ);
			assert(succ);
			assert(IS_INT(count));
			pageCount = count.value.intvalue;
			if (!IS_NULL(enc->currentPage)) {
				pageCount++;
			}
		}
	}
	return pageCount;
}

long pdfr_encoder_bytes_written(t_pdfrasencoder* enc)
{
	return pd_outstream_pos(enc->stm);
}

static int pdfr_sig_handler(t_pdoutstream *stm, void* cookie, PdfOutputEventCode eventid)
{
	(void)cookie;
	(void)eventid;
    pd_puts(stm, "%PDF-raster-" PDFRASTER_SPEC_VERSION "\n");
    return 0;
}

void pdfr_encoder_end_document(t_pdfrasencoder* enc)
{
    t_pdoutstream* stm = enc->stm;

    pdfr_encoder_end_page(enc);
	// remember to write our PDF/raster signature marker
    pd_outstream_set_event_handler(stm, PDF_EVENT_BEFORE_STARTXREF, pdfr_sig_handler, NULL);
	pd_write_endofdocument(stm, enc->xref, enc->catalog, enc->info, enc->trailer);

    // sign document if was set to sign
    if (enc->signer)
        digitalsignature_finish(enc->signer);

	// Note: we leave all the final data structures intact in case the client
	// has questions, like 'how many pages did we write?' or 'how big was the output file?'.
}

t_pdfdigitalsignature* pdfr_encoder_get_digitalsignature(t_pdfrasencoder* enc) {
    return enc->signer;
}

void pdfr_encoder_destroy(t_pdfrasencoder* enc)
{
    if (enc->signer)
        digitalsignature_destroy(enc->signer);

	if (enc) {
		// free everything in the pool associated
		// with this encoder. Including the pool
		// and the encoder struct.
		struct t_pdmempool *pool = enc->pool;
		pd_alloc_free_pool(pool);
	}
}

