#ifndef _H_PdfRaster
#define _H_PdfRaster

#ifdef __cplusplus
extern "C" {
#endif

#include "PdfAlloc.h"
#include "PdfValues.h"
#include "PdfDatasink.h"
#include "pdfras_encryption.h"

#define PDFRAS_API_LEVEL	1

// Version of the file format we support (or at least, write)
#define PDFRASTER_SPEC_VERSION "1.0"

#define PDFRAS_LIBRARY_VERSION "0.19"
//      gus     2017.07.19  compiles 64-bit, added pdfpos_t type
// 0.18 spike   2016.10.23  clarified/enforced image params that must be same for all strips on page.
// 0.17 spike   2016.09.23  moved %PDF-raster marker to just before startxref
// 0.16 spike   2016.09.06  fix: align allowed colorspaces with spec, support /CalRGB.
// 0.15 spike   2016.08.18  fix: length of strip streams was wrong.
// 0.14	spike	2016.07.20	pdfras_writer_managed compiles & links /clr!
// 0.13	spike	2016.07.13	moved signature to end of trailer dict
//							introduced first high-level PdfRaster tests.
//							fixed several bugs, one breaking change to low-level API.
// 0.12 spike   2016.05.24  moved signature to before xref table
// 0.11 spike   2016.05.18  correctly output PDF/raster signature in trailer
// 0.10	spike	2016.03.11	new: pd_format_xmp_time, renamed pd_get_time_string => pd_format_time
// 0.9	spike	2015.12.01	multi-strip working
// 0.8	spike	2015.09.25	added file ID in trailer dict
// 0.7	spike	2015.09.17	introducing calibrated vs device colorspaces
// 0.6	spike	2015.02.13	bugfix! no EOL after the signature comment
// 0.5	spike	2015.01.13	prototype of 16-bit/channel image support
// 0.4	spike	2015.01.13	added physical page number & page-side
// 0.3	spike	2015.01.07	fixed bug in CCITTFaxDecode filter (mispelled!)
// 0.2	spike	2015.01.06	added pd_raster_set_rotation
// 0.1	spike	2014.12.14	1st version, using Steve Hawley's mini PDF writer

// Pixel Formats
typedef enum {
	PDFRAS_BITONAL,				// 1-bit per pixel, 0=black (DeviceGray or CalGray)
	PDFRAS_GRAY8,				// 8-bit per pixel, 0=black (CalGray)
	PDFRAS_GRAY16,				// 16-bit per pixel, 0=black (CalGray)
	PDFRAS_RGB24,				// 24-bit per pixel, (ICCBased or CalRGB)
	PDFRAS_RGB48,				// 48-bit per pixel, (ICCBased or CalRGB)
} RasterPixelFormat;

// Compression Modes
typedef enum {
	PDFRAS_UNCOMPRESSED,		// uncompressed (/Filter null)
	PDFRAS_JPEG,				// JPEG baseline (DCTDecode)
	PDFRAS_CCITTG4,				// CCITT Group 4 (CCITTFaxDecode)
} RasterCompression;

typedef struct t_pdfrasencoder t_pdfrasencoder;
typedef struct t_pdfdigitalsignature t_pdfdigitalsignature;

// create and return a raster PDF encoder, reading to begin
// encoding a PDF/raster output stream.
// apiLevel is the version of this API that the caller is expecting.
// (You can use PDFRAS_API_LEVEL)
// os points to a structure containing various functions and
// handles provided by the caller to the raster encoder.
// The 'os' object provides memory management and output functions.
// The encoder allocates a memory pool to hold all the memory it needs,
// which is released when the encoder is destroyed.
//
// The following encoder properties are set to their default values:
// pixelformat		PDFRAS_BITONAL
// compression		PDFRAS_UNCOMPRESSED
// xdpi, ydpi		300
// rotation			0
//
t_pdfrasencoder* PDFRASAPICALL pdfr_encoder_create(int apiLevel, t_OS *os);
typedef t_pdfrasencoder* (PDFRASAPICALL *pfn_pdfr_encoder_create)(int apiLevel, t_OS *os);

// Extended version of pdfr_encoder_create for creating digitaly signed document.
// Extended params:
// pfx_file: path to the certificate stored in PFX file
// password: password for certificate
t_pdfrasencoder* PDFRASAPICALL pdfr_signed_encoder_create(int apiLevel, t_OS* os, const char* pfx_file, const char* password);
typedef t_pdfrasencoder* (PDFRASAPICALL *pfn_signed_encoder_create) (int apiLevel, t_OS* os, const char* pfx_file, const char* password);

// Query function for t_pdfrasencoder
t_pdmempool* PDFRASAPICALL pdfr_encoder_mempool(t_pdfrasencoder* encoder);
typedef t_pdmempool* (PDFRASAPICALL *pfn_pdfr_encoder_mempool) (t_pdfrasencoder* encoder);
fOutputWriter PDFRASAPICALL pdfr_encoder_set_outputwriter(t_pdfrasencoder* encoder, fOutputWriter writer);
typedef fOutputWriter(PDFRASAPICALL *pfn_pdfr_encoder_set_outputwriter) (t_pdfrasencoder* encoder, fOutputWriter writer);
void* PDFRASAPICALL pdfr_encoder_set_cookie(t_pdfrasencoder* encoder, void* cookie);
typedef void* (PDFRASAPICALL *pfn_pdfr_encoder_set_cookie) (t_pdfrasencoder* encoder, void* cookie);
t_pdvalue* PDFRASAPICALL pdfr_encoder_catalog(t_pdfrasencoder* encoder);
typedef t_pdvalue* (PDFRASAPICALL *pfn_pdfr_encoder_catalog) (t_pdfrasencoder* encoder);
t_pdxref* PDFRASAPICALL pdfr_encoder_xref(t_pdfrasencoder* encoder);
typedef t_pdxref* (PDFRASAPICALL *pfn_pdfr_encoder_xref) (t_pdfrasencoder* encoder);
t_pdvalue* PDFRASAPICALL pdfr_encoder_currentpage(t_pdfrasencoder* encoder);
typedef t_pdvalue* (PDFRASAPICALL *pfn_pdfr_encoder_currentpage) (t_pdfrasencoder* encoder);

// Set various document metadata, traditionally stored in the DID (Document
// Information Dictionary) but from PDF 2.0 stored preferentially
// in XMP document metadata.
//
// 'Creator' is customarily set to the name and version of the creating application.
void PDFRASAPICALL pdfr_encoder_set_creator(t_pdfrasencoder *enc, const char* creator);
void PDFRASAPICALL pdfr_encoder_set_author(t_pdfrasencoder *enc, const char* author);
void PDFRASAPICALL pdfr_encoder_set_title(t_pdfrasencoder *enc, const char* title);
void PDFRASAPICALL pdfr_encoder_set_subject(t_pdfrasencoder *enc, const char* subject);
void PDFRASAPICALL pdfr_encoder_set_keywords(t_pdfrasencoder *enc, const char* keywords);
typedef void (PDFRASAPICALL *pfn_pdfr_encoder_set_creator)(t_pdfrasencoder *enc, const char* creator);
typedef void (PDFRASAPICALL *pfn_pdfr_encoder_set_author)(t_pdfrasencoder *enc, const char* author);
typedef void (PDFRASAPICALL *pfn_pdfr_encoder_set_title)(t_pdfrasencoder *enc, const char* title);
typedef void (PDFRASAPICALL *pfn_pdfr_encoder_set_subject)(t_pdfrasencoder *enc, const char* subject);
typedef void (PDFRASAPICALL *pfn_pdfr_encoder_set_keywords)(t_pdfrasencoder *enc, const char* keywords);

// get the creation time/date of this document.
// By default this is written to the DID as /CreationDate
// This can also be written to the XMP metadata as the xap:CreateDate
void PDFRASAPICALL pdfr_encoder_get_creation_date(t_pdfrasencoder *enc, time_t *t);
typedef void (PDFRASAPICALL *pfn_pdfr_encoder_get_creation_date)(t_pdfrasencoder *enc, time_t *t);

// Attach XMP metadata to the current page.
// The XMP data is a UTF-8 encoded, NUL-terminated string which is written verbatim.
void PDFRASAPICALL pdfr_encoder_write_page_xmp(t_pdfrasencoder *enc, const char* xmpdata);
typedef void (PDFRASAPICALL *pfn_pdfr_encoder_write_page_xmp)(t_pdfrasencoder *enc, const char* xmpdata);

// Attach XMP metadata to the document.
void PDFRASAPICALL pdfr_encoder_write_document_xmp(t_pdfrasencoder *enc, const char* xmpdata);
typedef void (PDFRASAPICALL *pfn_pdfr_encoder_write_document_xmp)(t_pdfrasencoder *enc, const char* xmpdata);

// Set the viewing angle for subsequent pages.
// The angle is a rotation clockwise in degrees and must be a multiple of 90.
// The viewing angle is initially 0.
void PDFRASAPICALL pdfr_encoder_set_rotation(t_pdfrasencoder* enc, int degCW);
typedef void (PDFRASAPICALL *pfn_pdfr_encoder_set_rotation)(t_pdfrasencoder* enc, int degCW);

// Set the resolution for subsequent pages
void PDFRASAPICALL pdfr_encoder_set_resolution(t_pdfrasencoder *enc, double xdpi, double ydpi);
typedef void (PDFRASAPICALL *pfn_pdfr_encoder_set_resolution)(t_pdfrasencoder *enc, double xdpi, double ydpi);

// Set the pixel format for subsequent pages
void PDFRASAPICALL pdfr_encoder_set_pixelformat(t_pdfrasencoder* enc, RasterPixelFormat format);
typedef void (PDFRASAPICALL *pfn_pdfr_encoder_set_pixelformat)(t_pdfrasencoder* enc, RasterPixelFormat format);

// Set the compression mode/algorithm to be used in writing subsequent pages.
// Takes effect when first strip is written to a page.
void PDFRASAPICALL pdfr_encoder_set_compression(t_pdfrasencoder* enc, RasterCompression comp);
typedef void (PDFRASAPICALL *pfn_pdfr_encoder_set_compression)(t_pdfrasencoder* enc, RasterCompression comp);

// Turn on or off 'uncalibrated' (raw, device) colorspace for subsequent
// bitonal images.  Only bitonal images are affected.
// By default, bitonal images are written with a /CalGray colorspace with
// Gamma 2.2, BlackPoint [ 0 0 0] and WhitePoint [ 1 1 1 ]
// uncal = 0 means use the calibrated /CalGray colorspace.
// uncal <> 0 means use uncalibrated /DeviceGray colorspace.
// Return value is the previous setting, either 1 or 0.
int PDFRASAPICALL pdfr_encoder_set_bitonal_uncalibrated(t_pdfrasencoder* enc, int uncal);
typedef int (PDFRASAPICALL *pfn_pdfr_encoder_set_bitonal_uncalibrated)(t_pdfrasencoder* enc, int uncal);

// Specify an ICC-profile based colorspace for subsequent RGB images.
// (By default, RGB images are assumed to be sRGB)
// profile must point to a valid ICC color profile of len bytes.
// (the profile is not validated but is used verbatim)
// If profile is NULL, the standard sRGB profile is selected and the len value is ignored.
void PDFRASAPICALL pdfr_encoder_define_rgb_icc_colorspace(t_pdfrasencoder* enc, const pduint8 *profile, size_t len);
typedef void (PDFRASAPICALL *pfn_pdfr_encoder_define_rgb_icc_colorspace)(t_pdfrasencoder* enc, const pduint8 *profile, size_t len);

// Define the colorspace for subsequent color images as a /CalRGB space, with
// the given parameters (see PDF for details). Color images written after this
// will be assigned the specified colorspace.  Gray and bitonal images are not affected.
// Any of the array parameters can be NULL in which case the PDF default is used.
// (For whitepoint, the default is taken to be [ 1 1 1 ].)
void PDFRASAPICALL pdfr_encoder_define_calrgb_colorspace(t_pdfrasencoder* enc, double gamma[3], double black[3], double white[3], double matrix[9]);
typedef void (PDFRASAPICALL *pfn_pdfr_encoder_define_calrgb_colorspace)(t_pdfrasencoder* enc, double gamma[3], double black[3], double white[3], double matrix[9]);

// Start encoding a page in the current document.
// If a page is currently open, that page is automatically ended before the new page is started.
int PDFRASAPICALL pdfr_encoder_start_page(t_pdfrasencoder* enc, int width);
typedef int (PDFRASAPICALL *pfn_pdfr_encoder_start_page)(t_pdfrasencoder* enc, int width);

// Set the physical page number for the next or current page.
// Applies to the current page if one is open, otherwise to the next page started.
// If not set, this property defaults to -1, 'unspecified'.
void PDFRASAPICALL pdfr_encoder_set_physical_page_number(t_pdfrasencoder* enc, int phpageno);
typedef void (PDFRASAPICALL *pfn_pdfr_encoder_set_physical_page_number)(t_pdfrasencoder* enc, int phpageno);

// Mark the next or current page as being a front or back side.
// Applies to the current page if one is open, otherwise to the next page started.
// frontness must be 1 (front side), 0 (back side), or -1 (unspecified)
// If not set, this property defaults to -1, 'unspecified'.
void PDFRASAPICALL pdfr_encoder_set_page_front(t_pdfrasencoder* enc, int frontness);
typedef void (PDFRASAPICALL *pfn_pdfr_encoder_set_page_front)(t_pdfrasencoder* enc, int frontness);

// Append a strip to the current page of the current document.
// rows is the height (number of rows) in the strip.
// The data is len bytes, starting at buf.
// The data is assumed to have the width, resolution, pixel format,
// compression, colorspace and rotation that you specified (or defaulted)
// for the currently open page.
//
// Can be called any number of times to deliver the data for the current page.
// Invalid if no page is open.
// The data is copied byte - for - byte into the output PDF.
// Each row must start on the next byte following the last byte of the preceding row.
// JPEG-compressed data must be encoded in the JPEG baseline format. This includes
// transformation to YUV space as part of compression. Grayscale images are not transformed.
// CCITT compressed data must be compressed in accordance with the following PDF Optional parameters
// for the CCITTFaxDecode filter:
// K = -1, EndOfLine=false, EncodedByteAlign=false, BlackIs1=false
int PDFRASAPICALL pdfr_encoder_write_strip(t_pdfrasencoder* enc, int rows, const pduint8 *buf, size_t len);
typedef int (PDFRASAPICALL *pfn_pdfr_encoder_write_strip)(t_pdfrasencoder* enc, int rows, const pduint8 *buf, size_t len);

// get the height (so far) in rows(pixels) of the current page.
// equals the sum of the row-counts of strips written to the current page.
int PDFRASAPICALL pdfr_encoder_get_page_height(t_pdfrasencoder* enc);
typedef int (PDFRASAPICALL *pfn_pdfr_encoder_get_page_height)(t_pdfrasencoder* enc);

// Finish writing the current page to the current document.
// Invalid if no page is open.
// After this call succeeds, no page is open.
int PDFRASAPICALL pdfr_encoder_end_page(t_pdfrasencoder* enc);
typedef int (PDFRASAPICALL *pfn_pdfr_encoder_end_page)(t_pdfrasencoder* enc);

// Returns the number of pages written to this document,
// including the current page if one is open.
int PDFRASAPICALL pdfr_encoder_page_count(t_pdfrasencoder* enc);
typedef int (PDFRASAPICALL *pfn_pdfr_encoder_page_count)(t_pdfrasencoder* enc);

// End the current PDF, finish writing all data to the output.
void PDFRASAPICALL pdfr_encoder_end_document(t_pdfrasencoder* enc);
typedef void (PDFRASAPICALL *pfn_pdfr_encoder_end_document)(t_pdfrasencoder* enc);

// Returns the number of bytes written to the document
long PDFRASAPICALL pdfr_encoder_bytes_written(t_pdfrasencoder* enc);
typedef long (PDFRASAPICALL *pfn_pdfr_encoder_bytes_written)(t_pdfrasencoder* enc);

// Destroy a raster PDF encoder, releasing all associated resources.
// Do not use the enc pointer after this, it is invalid.
void PDFRASAPICALL pdfr_encoder_destroy(t_pdfrasencoder* enc);
typedef void (PDFRASAPICALL *pfn_pdfr_encoder_destroy)(t_pdfrasencoder* enc);

/* Digital signature prototypes */
// Get signature object.
t_pdfdigitalsignature* PDFRASAPICALL pdfr_encoder_get_digitalsignature(t_pdfrasencoder* enc);
typedef t_pdfdigitalsignature* (PDFRASAPICALL *pfn_pdfr_encoder_get_digitalsignature) (t_pdfrasencoder* enc);

// Set explictly Name of signer
void PDFRASAPICALL pdfr_digitalsignature_set_name(t_pdfdigitalsignature* signature, const char* name);
typedef void (PDFRASAPICALL *pfn_digitalsignature_set_name) (t_pdfdigitalsignature* signature, const char* name);

// Set reason for the signing
void PDFRASAPICALL pdfr_digitalsignature_set_reason(t_pdfdigitalsignature* signature, const char* reason);
typedef void (PDFRASAPICALL *pfn_digitalsignature_set_reason) (t_pdfdigitalsignature* signature, const char* reason);

// Set location of the signing
void PDFRASAPICALL pdfr_digitalsignature_set_location(t_pdfdigitalsignature* signature, const char* location);
typedef void (PDFRASAPICALL *pfn_digitalsignature_set_location) (t_pdfdigitalsignature* signature, const char* location);

// Set contact info for signer
void PDFRASAPICALL pdfr_digitalsignature_set_contactinfo(t_pdfdigitalsignature* signature, const char* contactinfo);
typedef void (PDFRASAPICALL *pfn_digitalsignature_set_contactinfo) (t_pdfdigitalsignature* signature, const char* contactinfo);

/* Encryption prototypes */
// RC4 40 bits
void PDFRASAPICALL pdfr_encoder_set_RC4_40_encrypter(t_pdfrasencoder* enc, const char* user_password, const char* owner_password, PDFRAS_PERMS perms, pdbool metadata);
typedef void (PDFRASAPICALL *pfn_pdfr_encoder_set_RC4_40_encrypter) (t_pdfrasencoder* enc, const char* user_password, const char* owner_password, pdint32 perms, pdbool metadata);

// RC4 128 bits
void PDFRASAPICALL pdfr_encoder_set_RC4_128_encrypter(t_pdfrasencoder* enc, const char* user_password, const char* owner_password, PDFRAS_PERMS perms, pdbool metadata);
typedef void (PDFRASAPICALL *pfn_pdfr_encoder_set_RC4_128_encrypter) (t_pdfrasencoder* enc, const char* user_password, const char* owner_password, pdint32 perms, pdbool metadata);

// AES 128 bits
void PDFRASAPICALL pdfr_encoder_set_AES128_encrypter(t_pdfrasencoder* enc, const char* user_password, const char* owner_password, PDFRAS_PERMS perms, pdbool metadata);
typedef void (PDFRASAPICALL *pfn_pdfr_encoder_set_AES128_encrypter) (t_pdfrasencoder* enc, const char* user_password, const char* owner_password, pdint32 perms, pdbool metadata);

// AES 256 bits
void PDFRASAPICALL pdfr_encoder_set_AES256_encrypter(t_pdfrasencoder* enc, const char* user_password, const char* owner_password, PDFRAS_PERMS perms, pdbool metadata);
typedef void (PDFRASAPICALL *pfn_pdfr_encoder_set_AES256_encrypter) (t_pdfrasencoder* enc, const char* user_password, const char* owner_password, pdint32 perms, pdbool metadata);

#ifdef __cplusplus
}
#endif
#endif
