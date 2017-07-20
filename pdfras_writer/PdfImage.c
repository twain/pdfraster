#include <assert.h>
#include <limits.h>

#include "PdfImage.h"
#include "PdfStandardObjects.h"
#include "PdfStandardAtoms.h"
#include "PdfDict.h"
#include "PdfArray.h"
#include "PdfContentsGenerator.h"
// creates a static byte array named srgb_icc_profile:
#include "../icc_profile/srgb_icc_profile.h"


static t_pdatom ToCompressionAtom(e_ImageCompression comp)
{
	switch (comp) {
	default:
	case kCompNone: return PDA_None;
	case kCompFlate: return PDA_FlateDecode;
	case kCompCCITT: return PDA_CCITTFaxDecode;
	case kCompDCT: return PDA_DCTDecode;
	case kCompJBIG2: return PDA_JBIG2Decode;
	case kCompJPX: return PDA_JPXDecode;
	}
}

t_pdvalue pd_image_new(t_pdmempool *alloc, t_pdxref *xref, f_on_datasink_ready ready, void *eventcookie,
	t_pdvalue width, t_pdvalue height, t_pdvalue bitspercomponent,
	e_ImageCompression comp, t_pdvalue compParms, t_pdvalue colorspace)
{
	t_pdvalue image = stream_new(alloc, xref, 10, ready, eventcookie);
	t_pdarray *filter, *filterparms;
	if (IS_ERR(image)) return image;
	pd_dict_put(image, PDA_Type, pdatomvalue(PDA_XObject));
	pd_dict_put(image, PDA_Subtype, pdatomvalue(PDA_Image));
	pd_dict_put(image, PDA_Width, width);
	pd_dict_put(image, PDA_Height, height);
	pd_dict_put(image, PDA_BitsPerComponent, bitspercomponent);
	filter = pd_array_new(alloc, 1);
	if (comp != kCompNone)
	{
		pd_array_add(filter, pdatomvalue(ToCompressionAtom(comp)));
		pd_dict_put(image, PDA_Filter, pdarrayvalue(filter));
		filterparms = pd_array_new(alloc, 1);
		if (!IS_NULL(compParms))
			pd_array_add(filterparms, compParms);
		pd_dict_put(image, PDA_DecodeParms, pdarrayvalue(filterparms));
	}
	pd_dict_put(image, PDA_ColorSpace, colorspace);
	pd_dict_put(image, PDA_Length, pd_xref_create_forward_reference(xref));

	return image;
}

static pdint32 ToK(e_CCITTKind kind)
{
	switch (kind)
	{
	default:
	case kCCIITTG4: return -1;
	case kCCITTG31D: return 0;
	case kCCITTG32D: return 1;
	}
}

static t_pdvalue MakeCCITTParms(t_pdmempool *alloc, pduint32 width, pduint32 height, e_CCITTKind kind, pdbool ccittBlackIs1)
{
	t_pdvalue parms = pd_dict_new(alloc, 4);
	pd_dict_put(parms, PDA_K, pdintvalue(ToK(kind)));
	pd_dict_put(parms, PDA_Columns, pdintvalue(width));
	pd_dict_put(parms, PDA_Rows, pdintvalue(height));
	pd_dict_put(parms, PDA_BlackIs1, pdboolvalue(ccittBlackIs1));
	return parms;
}

// Create & return a CalGray colorspace value
// with specified Gamma, BlackPoint and WhitePoint.
t_pdvalue pd_make_calgray_colorspace(t_pdmempool *alloc, double gamma, double black[3], double white[3])
{
	// A calibrated grayscale colorspace is an array [/CalGray <<dict>>]
	// Legal dictionary entries: WhitePoint, BlackPoint and Gamma.
	//
	// Create the color space dictionary
	t_pdvalue csdict = pd_dict_new(alloc, 3);
	// BlackPoint defaults to [0.0 0.0 0.0] so only include it if not all 0's
	if (black[0] || black[1] || black[2]) {
		// add blackpoint array
		t_pdarray* blackPt = pd_array_new(alloc, 3);
		pd_array_add(blackPt, pdfloatvalue(black[0]));
		pd_array_add(blackPt, pdfloatvalue(black[1]));
		pd_array_add(blackPt, pdfloatvalue(black[2]));
		pd_dict_put(csdict, PDA_BlackPoint, pdarrayvalue(blackPt));
	}
	{	// add whitepoint array
		t_pdarray* whitePt = pd_array_new(alloc, 3);
		pd_array_add(whitePt, pdfloatvalue(white[0]));
		pd_array_add(whitePt, pdfloatvalue(white[1]));
		pd_array_add(whitePt, pdfloatvalue(white[2]));
		pd_dict_put(csdict, PDA_WhitePoint, pdarrayvalue(whitePt));
	}
	// add Gamma:
	pd_dict_put(csdict, PDA_Gamma, pdfloatvalue(gamma));
	// create the color space (an array)
	t_pdarray* cs = pd_array_new(alloc, 2);
	// tag it as /CalGray
	pd_array_add(cs, pdatomvalue(PDA_CalGray));
	// plug in the color space dictionary
	pd_array_add(cs, csdict);
	// all done.
	return pdarrayvalue(cs);
}

// Create & return a calibrated RGBe (/CalRGB) colorspace,
// with given Gamma, BlackPoint, WhitePoint and transform matrix. See PDF spec.
t_pdvalue pd_make_calrgb_colorspace(t_pdmempool *alloc, double gamma[3], double black[3], double white[3], double matrix[9])
{
    // A calibrated RGB colorspace is an array [/CalRGB <<dict>>]
    // Legal dictionary entries: Gamma, WhitePoint, BlackPoint, and Matrix.
    //
    if (!white) {
        double default_white[3] = { 1, 1, 1 };
        white = default_white;
    }
    // Create the color space dictionary
    t_pdvalue csdict = pd_dict_new(alloc, 4);
    // Gamma defaults to [ 1 1 1 ] so only write it if not all 1's
    if (gamma && (gamma[0] != 1 || gamma[1] != 1 || gamma[2] != 1)) {
        // add gamma array
        t_pdarray* gams = pd_array_new(alloc, 3);
        pd_array_add(gams, pdfloatvalue(gamma[0]));
        pd_array_add(gams, pdfloatvalue(gamma[1]));
        pd_array_add(gams, pdfloatvalue(gamma[2]));
        pd_dict_put(csdict, PDA_Gamma, pdarrayvalue(gams));
    }
    // BlackPoint defaults to [0.0 0.0 0.0] so only include it if not all 0's
    if (black && (black[0] || black[1] || black[2])) {
        // add blackpoint array
        t_pdarray* blackPt = pd_array_new(alloc, 3);
        pd_array_add(blackPt, pdfloatvalue(black[0]));
        pd_array_add(blackPt, pdfloatvalue(black[1]));
        pd_array_add(blackPt, pdfloatvalue(black[2]));
        pd_dict_put(csdict, PDA_BlackPoint, pdarrayvalue(blackPt));
    }
    {	// add whitepoint array
        t_pdarray* whitePt = pd_array_new(alloc, 3);
        pd_array_add(whitePt, pdfloatvalue(white[0]));
        pd_array_add(whitePt, pdfloatvalue(white[1]));
        pd_array_add(whitePt, pdfloatvalue(white[2]));
        pd_dict_put(csdict, PDA_WhitePoint, pdarrayvalue(whitePt));
    }
    if (matrix) {
        // add transform matrix
        t_pdarray* m = pd_array_new(alloc, 9);
        for (int i = 0; i < 9; i++) {
            pd_array_add(m, pdfloatvalue(matrix[i]));
        }
        pd_dict_put(csdict, PDA_Matrix, pdarrayvalue(m));
    }
    // create the color space (an array)
    t_pdarray* cs = pd_array_new(alloc, 3);
    // tag it as /CalRGB
    pd_array_add(cs, pdatomvalue(PDA_CalRGB));
    // plug in the color space dictionary
    pd_array_add(cs, csdict);
    // all done.
    return pdarrayvalue(cs);
}


typedef struct {
	const pduint8*	pointer;
	size_t			size;
} DataBlock;

static void write_data_block(t_datasink *sink, void *eventcookie)
{
	DataBlock block = *(DataBlock*)eventcookie;
	pd_datasink_put(sink, block.pointer, 0, block.size);
}

t_pdvalue pd_make_srgb_colorspace(t_pdmempool *alloc, t_pdxref *xref)
{
	return pd_make_iccbased_rgb_colorspace(alloc, xref, srgb_icc_profile, sizeof srgb_icc_profile);
}

t_pdvalue pd_make_iccbased_rgb_colorspace(t_pdmempool *alloc, t_pdxref *xref, const pduint8* prof_data, size_t prof_size)
{
	// this has to be dynamically allocated because it needs to stick around after this function returns
	DataBlock* profile_data = (DataBlock *)pd_alloc(alloc, sizeof(DataBlock));
	profile_data->pointer = prof_data;
	profile_data->size = prof_size;
	t_pdvalue profile = stream_new(alloc, xref, 3, write_data_block, profile_data);
	// 3-channel colorspace:
	pd_dict_put(profile, PDA_N, pdintvalue(3));
	// Unlike many streams, we know the length of this one in advance:
	assert(prof_size < INT_MAX); // make sure cast below is OK
	pd_dict_put(profile, PDA_Length, pdintvalue((pdint32)prof_size));
	// Someday soon, this stream needs FlateDecode and ASCII85Decode filters
	//pd_dict_put(profile, PDA_FILTER, pdatomvalue(PDA_ASCIIHEXDECODE));
	// get a reference to the profile stream
	t_pdvalue profref = pd_xref_makereference(xref, profile);

	t_pdarray* cs = pd_array_new(alloc, 2);
	pd_array_add(cs, pdatomvalue(PDA_ICCBased));
	// add ICC stream-ref to array
	pd_array_add(cs, profref);
	return pdarrayvalue(cs);
}

t_pdvalue pd_image_new_simple(t_pdmempool *alloc, t_pdxref *xref, f_on_datasink_ready ready, void *eventcookie,
	pduint32 width, pduint32 height, pduint32 bitspercomponent, e_ImageCompression comp,
	e_CCITTKind kind, pdbool ccittBlackIs1, t_pdvalue colorspace)
{
	// map colorspace family to specific colorspace value:
	t_pdvalue comparms = (comp == kCompCCITT) ? MakeCCITTParms(alloc, width, height, kind, ccittBlackIs1) : pdnullvalue();
	return pd_image_new(alloc, xref, ready, eventcookie, pdintvalue(width), pdintvalue(height), pdintvalue(bitspercomponent),
		comp, comparms, colorspace);
}
