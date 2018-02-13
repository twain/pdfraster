// raster_encoder_demo.cpp : Defines the entry point for the console application.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "PdfRaster.h"
#include "PdfStandardObjects.h"

#include "bw_ccitt_data.h"
#include "color_page.h"
#include "gray8_page.h"
#include "color_strip0.h"
#include "color_strip1.h"
#include "color_strip2.h"
#include "color_strip3.h"
#include "gray8_page_strip.h"
#include "bw1_ccitt_strip_data.h"

#define OUTPUT_FILENAME "raster.pdf"

static void myMemSet(void *ptr, pduint8 value, size_t count)
{
	memset(ptr, value, count);
}

static int myOutputWriter(const pduint8 *data, pduint32 offset, pduint32 len, void *cookie)
{
	FILE *fp = (FILE *)cookie;
	if (!data || !len)
		return 0;
	data += offset;
	fwrite(data, 1, len, fp);
	return len;
}

static void *mymalloc(size_t bytes)
{
	return malloc(bytes);
}

// tiny gray8 image, 8x8:
static pduint8 _imdata[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
	0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
	0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60, 0x60,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
	0xa0, 0xa0, 0xa0, 0xa0, 0xa0, 0xa0, 0xa0, 0xa0,
	0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0,
	0xe0, 0xe0, 0xe0, 0xe0, 0xe0, 0xe0, 0xe0, 0xe0,
	0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0,
	0xa0, 0xa0, 0xa0, 0xa0, 0xa0, 0xa0, 0xa0, 0xa0,
	0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
};

// slightly larger gray16 image:
static pduint16 deepGrayData[64 * 512];

// 48-bit RGB image data
static struct { pduint16 R, G, B; } deepColorData[85 * 110];

static pduint8 bitonalData[((850 + 7) / 8) * 1100];

// 24-bit RGB image data
struct { unsigned char R, G, B; } colorData[175 * 100];

static char XMP_metadata[4096] = "\
<?xpacket begin=\"\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?>\n\
<x:xmpmeta xmlns:x=\"adobe:ns:meta/\">\n\
  <rdf:RDF xmlns:rdf=\"http://www.w3.org/1999/02/22-rdf-syntax-ns#\">\
	<rdf:Description rdf:about=\"\" xmlns:dc=\"http://purl.org/dc/elements/1.1/\">\
	    <dc:format>application/pdf</dc:format>\
	</rdf:Description>\
	<rdf:Description rdf:about=\"\" xmlns:xap=\"http://ns.adobe.com/xap/1.0/\">\
	    <xap:CreateDate>2013-08-27T10:28:38+07:00</xap:CreateDate>\
		<xap:ModifyDate>2013-08-27T10:28:38+07:00</xap:ModifyDate>\
		<xap:CreatorTool>raster_encoder_demo 1.0</xap:CreatorTool>\
	</rdf:Description>\
	<rdf:Description rdf:about=\"\" xmlns:pdf=\"http://ns.adobe.com/pdf/1.3/\">\
		<pdf:Producer>PdfRaster encoder 0.8</pdf:Producer>\
	</rdf:Description>\
	<rdf:Description rdf:about=\"\" xmlns:xapMM=\"http://ns.adobe.com/xap/1.0/mm/\"><xapMM:DocumentID>uuid:42646CE2-2A6C-482A-BC04-030FDD35E676</xapMM:DocumentID>\
	</rdf:Description>\
"
//// Tag file as PDF/A-1b
//"\
//	<rdf:Description rdf:about=\"\" xmlns:pdfaid=\"http://www.aiim.org/pdfa/ns/id/\" pdfaid:part=\"1\" pdfaid:conformance=\"B\">\
//	</rdf:Description>\
//"
"\
  </rdf:RDF>\
</x:xmpmeta>\n\
\n\
<?xpacket end=\"w\"?>\
";

void set_xmp_create_date(char* xmp, time_t t)
{
	const char* CREATEDATE = "<xap:CreateDate>";
	const char* MODIFYDATE = "<xap:ModifyDate>";
	char* p = strstr(xmp, CREATEDATE);
	if (p) {
		p += pdstrlen(CREATEDATE);
		// format the time t into XMP timestamp format:
		char xmpDate[32];
		pd_format_xmp_time(t, xmpDate, ELEMENTS(xmpDate));
		// plug it into the XML template
		memcpy(p, xmpDate, pdstrlen(xmpDate));
		// likewise for the modify date
		p = strstr(xmp, MODIFYDATE);
		if (p) {
			p += pdstrlen(MODIFYDATE);
			memcpy(p, xmpDate, pdstrlen(xmpDate));
		}
	}
}


void generate_image_data()
{
	// generate bitonal page data
	for (int i = 0; i < sizeof bitonalData; i++) {
		int y = (i / 107);
		int b = (i % 107);
		if ((y % 100) == 0) {
			bitonalData[i] = 0xAA;
		}
		else if ((b % 12) == 0 && (y & 1)) {
			bitonalData[i] = 0x7F;
		}
		else {
			bitonalData[i] = 0xff;
		}
	}
	// generate 16-bit grayscale data
	// 64 columns, 512 rows
	for (int i = 0; i < 64 * 512; i++) {
		int y = (i / 64);
		unsigned value = 65535 - (y * 65535 / 511);
		pduint8* pb = (pduint8*)(deepGrayData + i);
		pb[0] = value / 256;
		pb[1] = value % 256;
	}
	// generate 48-bit RGB data
	// 85 columns, 110 rows
	memset(deepColorData, 0, sizeof(deepColorData));
	for (int y = 0; y < 110; y++) {
		int sv = (65535 / 110) * y;
		pduint16 v = (pduint16)(((sv << 8)&0xFF00) | ((sv >> 8) & 0xFF));
		for (int x = 0; x < 85; x++) {
			int i = y * 85 + x;
			if (x < (85 / 4)) {
				deepColorData[i].R = v;
			}
			else if (x < (85 / 4) * 2) {
				deepColorData[i].G = v;
			}
			else if (x < (85 / 4) * 3) {
				deepColorData[i].B = v;
			}
			else {
				deepColorData[i].R = v;
				deepColorData[i].G = v;
				deepColorData[i].B = v;
			}
		}
	}

	// generate RGB data
	for (int i = 0; i < (175 * 100); i++) {
		int y = (i / 175);
		int x = (i % 175);
		colorData[i].R = x * 255 / 175;
		colorData[i].G = y * 255 / 100;
		colorData[i].B = (x + y) * 255 / (100 + 175);
	}
} // generate_image_data

int write_0page_file(t_OS os, const char *filename)

{
	FILE *fp = fopen(filename, "wb");
	if (fp == 0) {
		fprintf(stderr, "unable to open %s for writing\n", filename);
		return 1;
	}
	os.writeoutcookie = fp;
	os.allocsys = pd_alloc_new_pool(&os);

	// Construct a raster PDF encoder
	t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
	pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
	pdfr_encoder_set_subject(enc, "0-page sample output");

	// the document is complete
	pdfr_encoder_end_document(enc);
	// clean up
	fclose(fp);
	pdfr_encoder_destroy(enc);
    printf("  %s\n", filename);
	return 0;
}

// write 8.5 x 11 bitonal page 100 DPI with a light dotted grid
void write_bitonal_uncomp_page(t_pdfrasencoder* enc)
{
	pdfr_encoder_set_resolution(enc, 100.0, 100.0);
	pdfr_encoder_start_page(enc, 850);
	pdfr_encoder_set_pixelformat(enc, PDFRAS_BITONAL);
	pdfr_encoder_set_compression(enc, PDFRAS_UNCOMPRESSED);
	pdfr_encoder_write_strip(enc, 1100, bitonalData, sizeof bitonalData);
	pdfr_encoder_end_page(enc);
}

// write 8.5 x 11 bitonal page 100 DPI with a light dotted grid
// multi-strip, rotate 90 degrees for viewing
void write_bitonal_uncomp_multistrip_page(t_pdfrasencoder* enc)
{
	int stripheight = 100;
	pduint8* data = (pduint8*)bitonalData;
	size_t stripsize = (850+7)/8 * stripheight;

	pdfr_encoder_set_resolution(enc, 100.0, 100.0);
	pdfr_encoder_set_rotation(enc, 90);
	pdfr_encoder_start_page(enc, 850);
	pdfr_encoder_set_pixelformat(enc, PDFRAS_BITONAL);
	pdfr_encoder_set_compression(enc, PDFRAS_UNCOMPRESSED);
	for (int r = 0; r < 1100; r += stripheight) {
		pdfr_encoder_write_strip(enc, stripheight, data, stripsize);
		data += stripsize;
	}
	if (pdfr_encoder_get_page_height(enc) != 1100) {
		fprintf(stderr, "wrong page height at end of write_bitonal_uncomp_multistrip_page");
		exit(1);
	}
	pdfr_encoder_end_page(enc);
}

int write_bitonal_uncompressed_file(t_OS os, const char *filename)
{
	FILE *fp = fopen(filename, "wb");
	if (fp == 0) {
		fprintf(stderr, "unable to open %s for writing\n", filename);
		return 1;
	}
	os.writeoutcookie = fp;
	os.allocsys = pd_alloc_new_pool(&os);

	// Construct a raster PDF encoder
	t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
	pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
	pdfr_encoder_set_subject(enc, "BW 1-bit Uncompressed sample output");

	write_bitonal_uncomp_page(enc);

	// the document is complete
	pdfr_encoder_end_document(enc);
	// clean up
	fclose(fp);
	pdfr_encoder_destroy(enc);
    printf("  %s\n", filename);
    return 0;
}

int write_bitonal_uncompressed_signed_file(t_OS os, const char* filename, const char* image_path) {
    FILE *fp = fopen(filename, "wb");
    if (fp == 0) {
        fprintf(stderr, "unable to open %s for writing\n", filename);
        return 1;
    }
    os.writeoutcookie = fp;
    os.allocsys = pd_alloc_new_pool(&os);

    // Construct a raster PDF encoder
    char cert_path[256];
    memset(cert_path, 0, 256);
    char* demo = strstr(image_path, "demo_raster_encoder");
    strncpy(cert_path, image_path, demo - image_path);
    sprintf(cert_path + (demo - image_path), "%s", "certificate.p12");
    t_pdfrasencoder* enc = pdfr_signed_encoder_create(PDFRAS_API_LEVEL, &os, cert_path, "");
    pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
    pdfr_encoder_set_subject(enc, "BW 1-bit Uncompressed sample output");

    t_pdfdigitalsignature* signature = pdfr_encoder_get_digitalsignature(enc);
    pdfr_digitalsignature_set_location(signature, "Nove Zamky");
    pdfr_digitalsignature_set_name(signature, "Mato");
    pdfr_digitalsignature_set_reason(signature, "Test of signing");

    write_bitonal_uncomp_page(enc);

    // the document is complete
    pdfr_encoder_end_document(enc);
    // clean up
    fclose(fp);
    pdfr_encoder_destroy(enc);
    printf("  %s\n", filename);
    return 0;
}

int write_bitonal_uncompressed_signed_and_encrypted_file(t_OS os, const char* filename, const char* image_path) {
    FILE *fp = fopen(filename, "wb");
    if (fp == 0) {
        fprintf(stderr, "unable to open %s for writing\n", filename);
        return 1;
    }
    os.writeoutcookie = fp;
    os.allocsys = pd_alloc_new_pool(&os);

    // Construct a raster PDF encoder
    char cert_path[256];
    memset(cert_path, 0, 256);
    char* demo = strstr(image_path, "demo_raster_encoder");
    strncpy(cert_path, image_path, demo - image_path);
    sprintf(cert_path + (demo - image_path), "%s", "certificate.p12");
    t_pdfrasencoder* enc = pdfr_signed_encoder_create(PDFRAS_API_LEVEL, &os, cert_path, "");
    pdfr_encoder_set_AES128_encrypter(enc, "open", "master", PDFRAS_PERM_COPY_FROM_DOCUMENT, PD_TRUE);

    pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
    pdfr_encoder_set_subject(enc, "BW 1-bit Uncompressed sample output");

    t_pdfdigitalsignature* signature = pdfr_encoder_get_digitalsignature(enc);
    pdfr_digitalsignature_set_location(signature, "Nove Zamky");
    pdfr_digitalsignature_set_name(signature, "Mato");
    pdfr_digitalsignature_set_reason(signature, "Test of signing and encryption.");

    write_bitonal_uncomp_page(enc);

    // the document is complete
    pdfr_encoder_end_document(enc);
    // clean up
    fclose(fp);
    pdfr_encoder_destroy(enc);
    printf("  %s\n", filename);
    return 0;
}

int write_bitonal_uncompressed_multistrip_file(t_OS os, const char *filename)
{
	FILE *fp = fopen(filename, "wb");
	if (fp == 0) {
		fprintf(stderr, "unable to open %s for writing\n", filename);
		return 1;
	}
	os.writeoutcookie = fp;
	os.allocsys = pd_alloc_new_pool(&os);

	// Construct a raster PDF encoder
	t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
	pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
	pdfr_encoder_set_subject(enc, "BW 1-bit Uncompressed multi-strip sample output");

    write_bitonal_uncomp_multistrip_page(enc);

	// the document is complete
	pdfr_encoder_end_document(enc);
	// clean up
	fclose(fp);
	pdfr_encoder_destroy(enc);
	printf("  %s\n", filename);
	return 0;
}

void write_bitonal_ccitt_page(t_pdfrasencoder* enc)
{
	// Next page: CCITT-compressed B&W 300 DPI US Letter (scanned)
	pdfr_encoder_set_resolution(enc, 300.0, 300.0);
	pdfr_encoder_start_page(enc, 2521);
	pdfr_encoder_set_pixelformat(enc, PDFRAS_BITONAL);
	pdfr_encoder_set_compression(enc, PDFRAS_CCITTG4);
	pdfr_encoder_write_strip(enc, 3279, bw_ccitt_page_bin, sizeof bw_ccitt_page_bin);
	pdfr_encoder_end_page(enc);
}

int write_bitonal_ccitt_file(t_OS os, const char *filename, int uncal)
{
	// Write a file: CCITT-compressed B&W 300 DPI US Letter (scanned)
	FILE *fp = fopen(filename, "wb");
	if (fp == 0) {
		fprintf(stderr, "unable to open %s for writing\n", filename);
		return 1;
	}
	os.writeoutcookie = fp;
	os.allocsys = pd_alloc_new_pool(&os);

	t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
	pdfr_encoder_set_author(enc, "Willy Codewell");
	pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
	pdfr_encoder_set_keywords(enc, "raster bitonal CCITT");
	pdfr_encoder_set_subject(enc, "BW 1-bit CCITT-G4 compressed sample output");
    pdfr_encoder_set_bitonal_uncalibrated(enc, uncal);

	write_bitonal_ccitt_page(enc);

	// the document is complete
	pdfr_encoder_end_document(enc);
	// clean up
	fclose(fp);
	pdfr_encoder_destroy(enc);
    printf("  %s\n", filename);
    return 0;
}

void write_bitonal_ccitt_multistrip_page(t_pdfrasencoder* enc)
{
	// Next page: CCITT-compressed B&W 300 DPI US Letter (scanned)
	pdfr_encoder_set_resolution(enc, 300.0, 300.0);
	pdfr_encoder_set_rotation(enc, 270);
	pdfr_encoder_start_page(enc, 2521);
	pdfr_encoder_set_pixelformat(enc, PDFRAS_BITONAL);
	pdfr_encoder_set_compression(enc, PDFRAS_CCITTG4);
	pdfr_encoder_write_strip(enc, 1000, bw1_ccitt_2521x1000_0_bin, sizeof bw1_ccitt_2521x1000_0_bin);
	pdfr_encoder_write_strip(enc, 1000, bw1_ccitt_2521x1000_1_bin, sizeof bw1_ccitt_2521x1000_1_bin);
	pdfr_encoder_write_strip(enc, 1000, bw1_ccitt_2521x1000_2_bin, sizeof bw1_ccitt_2521x1000_2_bin);
	pdfr_encoder_write_strip(enc,  279, bw1_ccitt_2521x0279_3_bin, sizeof bw1_ccitt_2521x0279_3_bin);
	pdfr_encoder_end_page(enc);
}

int write_bitonal_ccitt_multistrip_file(t_OS os, const char *filename, int uncal)
{
	// Write a file: CCITT-compressed B&W 300 DPI US Letter (scanned) multistrip
	FILE *fp = fopen(filename, "wb");
	if (fp == 0) {
		fprintf(stderr, "unable to open %s for writing\n", filename);
		return 1;
	}
	os.writeoutcookie = fp;
	os.allocsys = pd_alloc_new_pool(&os);

	t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
	pdfr_encoder_set_author(enc, "Willy Codewell");
	pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
	pdfr_encoder_set_keywords(enc, "raster bitonal CCITT");
	pdfr_encoder_set_subject(enc, "BW 1-bit CCITT-G4 compressed multistrip sample output");
	pdfr_encoder_set_bitonal_uncalibrated(enc, uncal);

	write_bitonal_ccitt_multistrip_page(enc);

	// the document is complete
	pdfr_encoder_end_document(enc);
	// clean up
	fclose(fp);
	pdfr_encoder_destroy(enc);
	printf("  %s\n", filename);
	return 0;
}

void write_gray8_uncomp_page(t_pdfrasencoder* enc)
{
	// 8-bit grayscale, uncompressed, 4" x 5.5" at 2.0 DPI
	pdfr_encoder_set_resolution(enc, 2.0, 2.0);
	// start a new page:
	pdfr_encoder_start_page(enc, 8);
	pdfr_encoder_set_pixelformat(enc, PDFRAS_GRAY8);
	pdfr_encoder_set_compression(enc, PDFRAS_UNCOMPRESSED);
	// write a strip of raster data to the current page
	// 11 rows high
	pdfr_encoder_write_strip(enc, 11, _imdata, sizeof _imdata);
	// the page is done
	pdfr_encoder_end_page(enc);
}

void write_gray8_uncomp_multistrip_page(t_pdfrasencoder* enc)
{
	int stripheight = 4;
	pduint8* data = (pduint8*)_imdata;
	size_t stripsize = 8 * stripheight;

	// 8-bit grayscale, uncompressed, 4" x 5.5" at 2.0 DPI
	pdfr_encoder_set_resolution(enc, 2.0, 2.0);
	pdfr_encoder_set_rotation(enc, 90);
	// start a new page:
	pdfr_encoder_start_page(enc, 8);
	pdfr_encoder_set_pixelformat(enc, PDFRAS_GRAY8);
	pdfr_encoder_set_compression(enc, PDFRAS_UNCOMPRESSED);
	// write 2 strips of 4 rows high raster data to the current page
	for (int r = 0; r < 2; ++r) {
		pdfr_encoder_write_strip(enc, stripheight, data, stripsize);
		data += stripsize;
	}
	// write 1 strip of 3 rows high raster data to the current page
	stripheight = 3;
	stripsize = 8 * stripheight;
	pdfr_encoder_write_strip(enc, stripheight, data, stripsize);
	data += stripsize;

	if (pdfr_encoder_get_page_height(enc) != 11) {
		fprintf(stderr, "wrong page height at end of write_gray8_uncomp_multistrip_page");
		exit(1);
	}
	// the page is done
	pdfr_encoder_end_page(enc);
}

int write_gray8_uncompressed_file(t_OS os, const char *filename)
{
	FILE *fp = fopen(filename, "wb");
	if (fp == 0) {
		fprintf(stderr, "unable to open %s for writing\n", filename);
		return 1;
	}
	os.writeoutcookie = fp;
	os.allocsys = pd_alloc_new_pool(&os);

	t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
	pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
	pdfr_encoder_set_subject(enc, "GRAY8 Uncompressed sample output");

	pdfr_encoder_write_page_xmp(enc, XMP_metadata);

	write_gray8_uncomp_page(enc);

	// the document is complete
	pdfr_encoder_end_document(enc);
	// clean up
	fclose(fp);
	pdfr_encoder_destroy(enc);
	printf("  %s\n", filename);
	return 0;
}

int write_gray8_uncompressed_multistrip_file(t_OS os, const char *filename)
{
	FILE *fp = fopen(filename, "wb");
	if (fp == 0) {
		fprintf(stderr, "unable to open %s for writing\n", filename);
		return 1;
	}
	os.writeoutcookie = fp;
	os.allocsys = pd_alloc_new_pool(&os);

	t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
	pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
	pdfr_encoder_set_subject(enc, "GRAY8 Uncompressed multi-strip sample output");

	pdfr_encoder_write_page_xmp(enc, XMP_metadata);

	write_gray8_uncomp_multistrip_page(enc);

	// the document is complete
	pdfr_encoder_end_document(enc);
	// clean up
	fclose(fp);
	pdfr_encoder_destroy(enc);
	printf("  %s\n", filename);
	return 0;
}

void write_gray8_jpeg_page(t_pdfrasencoder* enc)
{
	// 4" x 5.5" at 2.0 DPI
	pdfr_encoder_set_resolution(enc, 100.0, 100.0);
	// start a new page:
	pdfr_encoder_start_page(enc, 850);
	pdfr_encoder_set_pixelformat(enc, PDFRAS_GRAY8);
	pdfr_encoder_set_compression(enc, PDFRAS_JPEG);
	// write a strip of raster data to the current page
	pdfr_encoder_write_strip(enc, 1100, gray8_page_jpg, sizeof gray8_page_jpg);
    // page metadata
    pdfr_encoder_write_page_xmp(enc, XMP_metadata);
	// the page is done
	pdfr_encoder_end_page(enc);
}

int write_gray8_jpeg_file(t_OS os, const char *filename)
{
	// Write a file: 4" x 5.5" at 2.0 DPI, uncompressed 8-bit grayscale
	FILE *fp = fopen(filename, "wb");
	if (fp == 0) {
		fprintf(stderr, "unable to open %s for writing\n", filename);
		return 1;
	}
	os.writeoutcookie = fp;
	os.allocsys = pd_alloc_new_pool(&os);

	t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
	pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
	//pdfr_encoder_set_subject(enc, "GRAY8 JPEG sample output");

	time_t tcd;
	pdfr_encoder_get_creation_date(enc, &tcd);
	set_xmp_create_date(XMP_metadata, tcd);
	pdfr_encoder_write_document_xmp(enc, XMP_metadata);

	write_gray8_jpeg_page(enc);

	// the document is complete
	pdfr_encoder_end_document(enc);
	// clean up
	fclose(fp);
	pdfr_encoder_destroy(enc);
    printf("  %s\n", filename);
    return 0;
}

void write_gray16_uncomp_page(t_pdfrasencoder* enc)
{
	// 16-bit grayscale!
	pdfr_encoder_set_resolution(enc, 16.0, 128.0);
	pdfr_encoder_start_page(enc, 64);
	pdfr_encoder_set_pixelformat(enc, PDFRAS_GRAY16);
	pdfr_encoder_set_compression(enc, PDFRAS_UNCOMPRESSED);
	pdfr_encoder_set_physical_page_number(enc, 2);			// physical page 2
															// write a strip of raster data to the current page
	pdfr_encoder_write_strip(enc, 512, (const pduint8*)deepGrayData, sizeof deepGrayData);
	pdfr_encoder_end_page(enc);
}

void write_gray16_uncomp_multistrip_page(t_pdfrasencoder* enc)
{
	int stripheight = 32;
	pduint8* data = (pduint8*)deepGrayData;
	size_t stripsize = 64 * 2 * stripheight;

	// 16-bit grayscale!
	pdfr_encoder_set_resolution(enc, 16.0, 128.0);
	pdfr_encoder_set_rotation(enc, 90);
	pdfr_encoder_start_page(enc, 64);
	pdfr_encoder_set_pixelformat(enc, PDFRAS_GRAY16);
	pdfr_encoder_set_compression(enc, PDFRAS_UNCOMPRESSED);
	pdfr_encoder_set_physical_page_number(enc, 2);			// physical page 2
	// write 16 strips of 32 rows high raster data to the current page
	for (int r = 0; r < 512; r+=stripheight) {
		pdfr_encoder_write_strip(enc, stripheight, data, stripsize);
		data += stripsize;
	}
	if (pdfr_encoder_get_page_height(enc) != 512) {
		fprintf(stderr, "wrong page height at end of write_gray16_uncomp_multistrip_page");
		exit(1);
	}
	pdfr_encoder_end_page(enc);
}

void write_rgb48_uncomp_page(t_pdfrasencoder* enc)
{
	// 48-bit RGB!
	pdfr_encoder_set_resolution(enc, 10.0, 10.0);
	pdfr_encoder_set_rotation(enc, 270);
	pdfr_encoder_start_page(enc, 85);
	pdfr_encoder_set_pixelformat(enc, PDFRAS_RGB48);
	pdfr_encoder_set_compression(enc, PDFRAS_UNCOMPRESSED);
	pdfr_encoder_set_physical_page_number(enc, 1);			// physical page 1
															// write a strip of raster data to the current page
	pdfr_encoder_write_strip(enc, 110, (const pduint8*)deepColorData, sizeof deepColorData);
	pdfr_encoder_end_page(enc);
}

void write_rgb48_uncomp_multistrip_page(t_pdfrasencoder* enc)
{
	int stripheight = 10;
	pduint8* data = (pduint8*)deepColorData;
	size_t stripsize = 85 * 2 * 3 * stripheight;

	// 48-bit RGB!
	pdfr_encoder_set_resolution(enc, 10.0, 10.0);
	pdfr_encoder_set_rotation(enc, 90);
	pdfr_encoder_start_page(enc, 85);
	pdfr_encoder_set_pixelformat(enc, PDFRAS_RGB48);
	pdfr_encoder_set_compression(enc, PDFRAS_UNCOMPRESSED);
	pdfr_encoder_set_physical_page_number(enc, 1);			// physical page 1
	// write 11 strips of 10 rows high raster data to the current page
	for (int r = 0; r < 110; r += stripheight) {
		pdfr_encoder_write_strip(enc, stripheight, data, stripsize);
		data += stripsize;
	}
	if (pdfr_encoder_get_page_height(enc) != 110) {
		fprintf(stderr, "wrong page height at end of write_rgb48_uncomp_multistrip_page");
		exit(1);
	}
	pdfr_encoder_end_page(enc);
}

int write_gray16_uncompressed_file(t_OS os, const char *filename)
{
	// Write a file: 4" x 5.5" at 2.0 DPI, uncompressed 16-bit grayscale
	FILE *fp = fopen(filename, "wb");
	if (fp == 0) {
		fprintf(stderr, "unable to open %s for writing\n", filename);
		return 1;
	}
	os.writeoutcookie = fp;
	os.allocsys = pd_alloc_new_pool(&os);

	t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
	pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
	pdfr_encoder_set_subject(enc, "GRAY16 Uncompressed sample output");

	write_gray16_uncomp_page(enc);

	// the document is complete
	pdfr_encoder_end_document(enc);
	// clean up
	fclose(fp);
	pdfr_encoder_destroy(enc);
	printf("  %s\n", filename);
	return 0;
}

int write_gray16_uncompressed_multistrip_file(t_OS os, const char *filename)
{
	// Write a file: 4" x 5.5" at 2.0 DPI, uncompressed 16-bit multi-strip grayscale
	FILE *fp = fopen(filename, "wb");
	if (fp == 0) {
		fprintf(stderr, "unable to open %s for writing\n", filename);
		return 1;
	}
	os.writeoutcookie = fp;
	os.allocsys = pd_alloc_new_pool(&os);

	t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
	pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
	pdfr_encoder_set_subject(enc, "GRAY16 Uncompressed multi-strip output");

	write_gray16_uncomp_multistrip_page(enc);

	// the document is complete
	pdfr_encoder_end_document(enc);
	// clean up
	fclose(fp);
	pdfr_encoder_destroy(enc);
	printf("  %s\n", filename);
	return 0;
}

int write_rgb48_uncompressed_file(t_OS os, const char *filename)
{
	// Write a file: 8.5" x 11" at 10.0 DPI, uncompressed 48-bit color
	// single strip, rotate for display by 270 degrees
	FILE *fp = fopen(filename, "wb");
	if (fp == 0) {
		fprintf(stderr, "unable to open %s for writing\n", filename);
		return 1;
	}
	os.writeoutcookie = fp;
	os.allocsys = pd_alloc_new_pool(&os);

	t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
	pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
	pdfr_encoder_set_subject(enc, "RGB48 Uncompressed sample output");

	write_rgb48_uncomp_page(enc);

	// the document is complete
	pdfr_encoder_end_document(enc);
	// clean up
	fclose(fp);
	pdfr_encoder_destroy(enc);
	printf("  %s\n", filename);
	return 0;
}

int write_rgb48_uncompressed_multistrip_file(t_OS os, const char *filename)
{
	// Write a file: 8.5" x 11" at 10.0 DPI, uncompressed 48-bit color
	// multi-strip, rotate for display by 90 degrees
	FILE *fp = fopen(filename, "wb");
	if (fp == 0) {
		fprintf(stderr, "unable to open %s for writing\n", filename);
		return 1;
	}
	os.writeoutcookie = fp;
	os.allocsys = pd_alloc_new_pool(&os);

	t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
	pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
	pdfr_encoder_set_subject(enc, "RGB48 Uncompressed multi-strip sample output");

	write_rgb48_uncomp_multistrip_page(enc);

	// the document is complete
	pdfr_encoder_end_document(enc);
	// clean up
	fclose(fp);
	pdfr_encoder_destroy(enc);
	printf("  %s\n", filename);
	return 0;
}

void write_rgb24_uncomp_page(t_pdfrasencoder* enc)
{
	pdfr_encoder_set_resolution(enc, 50.0, 50.0);
	pdfr_encoder_set_rotation(enc, 90);
	pdfr_encoder_start_page(enc, 175);
	pdfr_encoder_set_pixelformat(enc, PDFRAS_RGB24);
	pdfr_encoder_set_compression(enc, PDFRAS_UNCOMPRESSED);
	pdfr_encoder_write_strip(enc, 100, (pduint8*)colorData, sizeof colorData);
	if (pdfr_encoder_get_page_height(enc) != 100) {
		fprintf(stderr, "wrong page height at end of write_rgb24_uncomp_page");
		exit(1);
	}
	pdfr_encoder_end_page(enc);
}

int write_rgb24_uncompressed_file(t_OS os, const char* filename)
{
	// Write a file: 24-bit RGB color 3.5" x 2" 50 DPI
	FILE *fp = fopen(filename, "wb");
	if (fp == 0) {
		fprintf(stderr, "unable to open %s for writing\n", filename);
		return 1;
	}
	os.writeoutcookie = fp;
	os.allocsys = pd_alloc_new_pool(&os);

	t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
	pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
	pdfr_encoder_set_subject(enc, "RGB24 Uncompressed sample output");

	write_rgb24_uncomp_page(enc);

	// the document is complete
	pdfr_encoder_end_document(enc);
	// clean up
	fclose(fp);
	pdfr_encoder_destroy(enc);
    printf("  %s\n", filename);
    return 0;
}

void write_rgb24_uncomp_multistrip_page(t_pdfrasencoder* enc)
{
	int stripheight = 20, r;
	pduint8* data = (pduint8*)colorData;
	size_t stripsize = 175 * 3 * stripheight;

	pdfr_encoder_set_resolution(enc, 50.0, 50.0);
	pdfr_encoder_set_rotation(enc, 90);
	pdfr_encoder_start_page(enc, 175);
	pdfr_encoder_set_pixelformat(enc, PDFRAS_RGB24);
	pdfr_encoder_set_compression(enc, PDFRAS_UNCOMPRESSED);
	for (r = 0; r < 100; r += stripheight) {
		pdfr_encoder_write_strip(enc, stripheight, data, stripsize);
		data += stripsize;
	}
	if (pdfr_encoder_get_page_height(enc) != 100) {
		fprintf(stderr, "wrong page height at end of write_rgb24_uncomp_multistrip_page");
		exit(1);
	}
	pdfr_encoder_end_page(enc);
}

int write_rgb24_uncompressed_multistrip_file(t_OS os, const char* filename)
{
	// Write a file: 24-bit RGB color 3.5" x 2" 50 DPI, multiple strips.
	FILE *fp = fopen(filename, "wb");
	if (fp == 0) {
		fprintf(stderr, "unable to open %s for writing\n", filename);
		return 1;
	}
	os.writeoutcookie = fp;
	os.allocsys = pd_alloc_new_pool(&os);

	t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
	pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
	pdfr_encoder_set_subject(enc, "RGB24 Uncompressed multi-strip sample output");

	write_rgb24_uncomp_multistrip_page(enc);

	// the document is complete
	pdfr_encoder_end_document(enc);
	// clean up
	fclose(fp);
	pdfr_encoder_destroy(enc);
    printf("  %s\n", filename);
    return 0;
}

// write an sRGB 8-bit/channel color image with JPEG compression
// 100 dpi, -180 rotation, 850 x 1100
void write_rgb24_jpeg_page(t_pdfrasencoder* enc)
{
	pdfr_encoder_set_resolution(enc, 100.0, 100.0);
	pdfr_encoder_set_rotation(enc, -180);
	pdfr_encoder_start_page(enc, 850);
	pdfr_encoder_set_pixelformat(enc, PDFRAS_RGB24);
	pdfr_encoder_set_compression(enc, PDFRAS_JPEG);
	pdfr_encoder_write_strip(enc, 1100, color_page_jpg, sizeof color_page_jpg);
	pdfr_encoder_end_page(enc);
}


int write_rgb24_jpeg_file(t_OS os, const char *filename)
{
	// Write a file: JPEG-compressed color US letter page (stored upside-down)
	FILE *fp = fopen(filename, "wb");
	if (fp == 0) {
		fprintf(stderr, "unable to open %s for writing\n", filename);
		return 1;
	}
	os.writeoutcookie = fp;
	os.allocsys = pd_alloc_new_pool(&os);

	t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
	pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
	pdfr_encoder_set_title(enc, filename);
	pdfr_encoder_set_subject(enc, "24-bit JPEG-compressed sample output");

	pdfr_encoder_write_document_xmp(enc, XMP_metadata);

	write_rgb24_jpeg_page(enc);

	// the document is complete
	pdfr_encoder_end_document(enc);
	// clean up
	fclose(fp);
	pdfr_encoder_destroy(enc);
    printf("  %s\n", filename);
    return 0;
}

int write_rgb24_jpeg_file_encrypted_rc4_40(t_OS os, const char* filename) {
    // Write a file: JPEG-compressed color US letter page (stored upside-down)
    FILE *fp = fopen(filename, "wb");
    if (fp == 0) {
        fprintf(stderr, "unable to open %s for writing\n", filename);
        return 1;
    }
    os.writeoutcookie = fp;
    os.allocsys = pd_alloc_new_pool(&os);

    t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
    pdfr_encoder_set_RC4_40_encrypter(enc, "open", "master", PDFRAS_PERM_COPY_FROM_DOCUMENT, PD_FALSE);
    pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
    pdfr_encoder_set_title(enc, filename);
    pdfr_encoder_set_subject(enc, "24-bit JPEG-compressed sample output");

    pdfr_encoder_write_document_xmp(enc, XMP_metadata);

    write_rgb24_jpeg_page(enc);

    // the document is complete
    pdfr_encoder_end_document(enc);
    // clean up
    fclose(fp);
    pdfr_encoder_destroy(enc);
    printf("  %s\n", filename);
    return 0;
}

int write_rgb24_jpeg_file_encrypted_rc4_128(t_OS os, const char* filename) {
    // Write a file: JPEG-compressed color US letter page (stored upside-down)
    FILE *fp = fopen(filename, "wb");
    if (fp == 0) {
        fprintf(stderr, "unable to open %s for writing\n", filename);
        return 1;
    }
    os.writeoutcookie = fp;
    os.allocsys = pd_alloc_new_pool(&os);

    t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
    pdfr_encoder_set_RC4_128_encrypter(enc, "open", "master", PDFRAS_PERM_COPY_FROM_DOCUMENT, PD_FALSE);
    pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
    pdfr_encoder_set_title(enc, filename);
    pdfr_encoder_set_subject(enc, "24-bit JPEG-compressed sample output");

    pdfr_encoder_write_document_xmp(enc, XMP_metadata);

    write_rgb24_jpeg_page(enc);

    // the document is complete
    pdfr_encoder_end_document(enc);
    // clean up
    fclose(fp);
    pdfr_encoder_destroy(enc);
    printf("  %s\n", filename);
    return 0;
}

int write_rgb24_jpeg_file_encrypted_aes128(t_OS os, const char* filename) {
    // Write a file: JPEG-compressed color US letter page (stored upside-down)
    FILE *fp = fopen(filename, "wb");
    if (fp == 0) {
        fprintf(stderr, "unable to open %s for writing\n", filename);
        return 1;
    }
    os.writeoutcookie = fp;
    os.allocsys = pd_alloc_new_pool(&os);

    t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
    pdfr_encoder_set_AES128_encrypter(enc, "open", "master", PDFRAS_PERM_COPY_FROM_DOCUMENT, PD_FALSE);
    pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
    pdfr_encoder_set_title(enc, filename);
    pdfr_encoder_set_subject(enc, "24-bit JPEG-compressed sample output");

    pdfr_encoder_write_document_xmp(enc, XMP_metadata);

    write_rgb24_jpeg_page(enc);

    // the document is complete
    pdfr_encoder_end_document(enc);
    // clean up
    fclose(fp);
    pdfr_encoder_destroy(enc);
    printf("  %s\n", filename);
    return 0;
}

int write_rgb24_jpeg_file_encrypted_aes256(t_OS os, const char* filename) {
    // Write a file: JPEG-compressed color US letter page (stored upside-down)
    FILE *fp = fopen(filename, "wb");
    if (fp == 0) {
        fprintf(stderr, "unable to open %s for writing\n", filename);
        return 1;
    }
    os.writeoutcookie = fp;
    os.allocsys = pd_alloc_new_pool(&os);

    t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
    pdfr_encoder_set_AES256_encrypter(enc, "open", "master", PDFRAS_PERM_COPY_FROM_DOCUMENT, PD_FALSE);
    pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
    pdfr_encoder_set_title(enc, filename);
    pdfr_encoder_set_subject(enc, "24-bit JPEG-compressed sample output");

    pdfr_encoder_write_document_xmp(enc, XMP_metadata);

    write_rgb24_jpeg_page(enc);

    // the document is complete
    pdfr_encoder_end_document(enc);
    // clean up
    fclose(fp);
    pdfr_encoder_destroy(enc);
    printf("  %s\n", filename);
    return 0;
}

void write_gray8_jpeg_multistrip_page(t_pdfrasencoder* enc)
{
	pdfr_encoder_set_resolution(enc, 100.0, 100.0);
	pdfr_encoder_set_rotation(enc, 90);
	pdfr_encoder_start_page(enc, 850);
	pdfr_encoder_set_pixelformat(enc, PDFRAS_GRAY8);
	pdfr_encoder_set_compression(enc, PDFRAS_JPEG);
	// write image as 6 separately compressed strips.
	// yeah, brute force.
	pdfr_encoder_write_strip(enc, 200, gray8_page_850x200_0_jpg, sizeof gray8_page_850x200_0_jpg);
	pdfr_encoder_write_strip(enc, 200, gray8_page_850x200_1_jpg, sizeof gray8_page_850x200_1_jpg);
	pdfr_encoder_write_strip(enc, 200, gray8_page_850x200_2_jpg, sizeof gray8_page_850x200_2_jpg);
	pdfr_encoder_write_strip(enc, 200, gray8_page_850x200_3_jpg, sizeof gray8_page_850x200_3_jpg);
	pdfr_encoder_write_strip(enc, 200, gray8_page_850x200_4_jpg, sizeof gray8_page_850x200_4_jpg);
	pdfr_encoder_write_strip(enc, 100, gray8_page_850x100_5_jpg, sizeof gray8_page_850x100_5_jpg);

	if (pdfr_encoder_get_page_height(enc) != 1100) {
		fprintf(stderr, "wrong page height at end of write_gray8_jpeg_multistrip_page");
		exit(1);
	}
	pdfr_encoder_end_page(enc);
}

int write_gray8_jpeg_multistrip_file(t_OS os, const char* filename)
{
	// Write a file: 8-bit Gray 8.5x11" page in six JPEG strips
	FILE *fp = fopen(filename, "wb");
	if (fp == 0) {
		fprintf(stderr, "unable to open %s for writing\n", filename);
		return 1;
	}
	os.writeoutcookie = fp;
	os.allocsys = pd_alloc_new_pool(&os);

	t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
	pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
	pdfr_encoder_set_subject(enc, "Gray8 JPEG multi-strip sample output");

	write_gray8_jpeg_multistrip_page(enc);

	// the document is complete
	pdfr_encoder_end_document(enc);
	// clean up
	fclose(fp);
	pdfr_encoder_destroy(enc);
	printf("  %s\n", filename);
	return 0;
}

void write_rgb24_jpeg_multistrip_page(t_pdfrasencoder* enc)
{
	pdfr_encoder_set_resolution(enc, 100.0, 100.0);
	pdfr_encoder_set_rotation(enc, 0);
	pdfr_encoder_start_page(enc, 850);
	pdfr_encoder_set_pixelformat(enc, PDFRAS_RGB24);
	pdfr_encoder_set_compression(enc, PDFRAS_JPEG);
	// write image as 4 separately compressed strips.
	// yeah, brute force.
	pdfr_encoder_write_strip(enc, 275, color_strip0_jpg, sizeof color_strip0_jpg);
	pdfr_encoder_write_strip(enc, 275, color_strip1_jpg, sizeof color_strip1_jpg);
	pdfr_encoder_write_strip(enc, 275, color_strip2_jpg, sizeof color_strip2_jpg);
	pdfr_encoder_write_strip(enc, 275, color_strip3_jpg, sizeof color_strip3_jpg);
	// All the same height, but that's in no way required.

	if (pdfr_encoder_get_page_height(enc) != 1100) {
		fprintf(stderr, "wrong page height at end of write_rgb24_jpeg_multistrip_page");
		exit(1);
	}
	pdfr_encoder_end_page(enc);
}

int write_rgb24_jpeg_multistrip_file(t_OS os, const char* filename)
{
	// Write a file: 24-bit RGB color 8.5x11" page in four JPEG strips
	FILE *fp = fopen(filename, "wb");
	if (fp == 0) {
		fprintf(stderr, "unable to open %s for writing\n", filename);
		return 1;
	}
	os.writeoutcookie = fp;
	os.allocsys = pd_alloc_new_pool(&os);

	t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
	pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");
	pdfr_encoder_set_subject(enc, "RGB24 JPEG multi-strip sample output");

	write_rgb24_jpeg_multistrip_page(enc);

	// the document is complete
	pdfr_encoder_end_document(enc);
	// clean up
	fclose(fp);
	pdfr_encoder_destroy(enc);
	printf("  %s\n", filename);
	return 0;
}

int write_allformat_multipage_file(t_OS os, const char *filename)
{
	// Write a multipage file containing all the supported pixel formats
	//
	FILE *fp = fopen(filename, "wb");
	if (fp == 0) {
		fprintf(stderr, "unable to open %s for writing\n", filename);
		return 1;
	}
	os.writeoutcookie = fp;
	os.allocsys = pd_alloc_new_pool(&os);

	// Construct a raster PDF encoder
	t_pdfrasencoder* enc = pdfr_encoder_create(PDFRAS_API_LEVEL, &os);
	pdfr_encoder_set_creator(enc, "raster_encoder_demo 1.0");

	pdfr_encoder_write_document_xmp(enc, XMP_metadata);

	pdfr_encoder_set_physical_page_number(enc, 1);
	pdfr_encoder_set_page_front(enc, 1);					// front side
	write_bitonal_uncomp_page(enc);

	pdfr_encoder_set_physical_page_number(enc, 1);
	pdfr_encoder_set_page_front(enc, 0);					// back side
	write_bitonal_ccitt_page(enc);

	pdfr_encoder_set_physical_page_number(enc, 2);
	write_gray8_uncomp_page(enc);

	pdfr_encoder_set_physical_page_number(enc, 3);
	write_gray8_jpeg_page(enc);

	pdfr_encoder_set_physical_page_number(enc, 4);
	write_gray16_uncomp_page(enc);

	pdfr_encoder_set_physical_page_number(enc, 5);
	write_rgb24_jpeg_page(enc);

	pdfr_encoder_set_physical_page_number(enc, 6);
	write_rgb24_uncomp_page(enc);

	pdfr_encoder_set_physical_page_number(enc, 7);
	write_rgb48_uncomp_page(enc);

	pdfr_encoder_set_physical_page_number(enc, 8);
	write_bitonal_uncomp_multistrip_page(enc);

	pdfr_encoder_set_physical_page_number(enc, 9);
	write_gray8_uncomp_multistrip_page(enc);

	pdfr_encoder_set_physical_page_number(enc, 10);
	write_gray16_uncomp_multistrip_page(enc);

	pdfr_encoder_set_physical_page_number(enc, 11);
	write_rgb48_uncomp_multistrip_page(enc);

	pdfr_encoder_set_physical_page_number(enc, 12);
	write_rgb24_jpeg_multistrip_page(enc);

	pdfr_encoder_set_physical_page_number(enc, 13);
	write_gray8_jpeg_multistrip_page(enc);

	pdfr_encoder_set_physical_page_number(enc, 14);
	write_bitonal_ccitt_multistrip_page(enc);

	// the document is complete
	pdfr_encoder_end_document(enc);
	// clean up
	fclose(fp);
	pdfr_encoder_destroy(enc);

    printf("  %s\n", filename);
    return 0;
}

int main(int argc, char** argv)
{
	t_OS os;
	os.alloc = mymalloc;
	os.free = free;
	os.memset = myMemSet;
	os.writeout = myOutputWriter;

    printf("demo_raster_encoder\n");

	generate_image_data();

	write_0page_file(os, "sample empty.pdf");

	write_bitonal_uncompressed_file(os, "sample bw1 uncompressed.pdf");

    write_bitonal_uncompressed_signed_file(os, "sample bw1 uncompressed signed.pdf", argv[0]);

    write_bitonal_uncompressed_signed_and_encrypted_file(os, "sample bw1 uncompressed signed and encrypted AES128.pdf", argv[0]);

	write_bitonal_uncompressed_multistrip_file(os, "sample bw1 uncompressed multistrip.pdf");

	write_bitonal_ccitt_file(os, "sample bw1 ccitt.pdf", 0);

    write_bitonal_ccitt_file(os, "sample bitonal uncal.pdf", 1);

	write_bitonal_ccitt_multistrip_file(os, "sample bw1 ccitt multistrip.pdf", 0);

	write_gray8_uncompressed_file(os, "sample gray8 uncompressed.pdf");

	write_gray8_uncompressed_multistrip_file(os, "sample gray8 uncompressed multistrip.pdf");

	write_gray8_jpeg_file(os, "sample gray8 jpeg.pdf");

	write_gray8_jpeg_multistrip_file(os, "sample gray8 jpeg multistrip.pdf");

	write_gray16_uncompressed_file(os, "sample gray16 uncompressed.pdf");

	write_gray16_uncompressed_multistrip_file(os, "sample gray16 uncompressed multistrip.pdf");

	write_rgb24_uncompressed_file(os, "sample rgb24 uncompressed.pdf");

	write_rgb24_uncompressed_multistrip_file(os, "sample rgb24 uncompressed multistrip.pdf");

	write_rgb24_jpeg_file(os, "sample rgb24 jpeg.pdf");

	write_rgb24_jpeg_multistrip_file(os, "sample rgb24 jpeg multistrip.pdf");

	write_rgb48_uncompressed_file(os, "sample rgb48 uncompressed.pdf");

	write_rgb48_uncompressed_multistrip_file(os, "sample rgb48 uncompressed multistrip.pdf");

	write_allformat_multipage_file(os, "sample all formats.pdf");

    write_rgb24_jpeg_file_encrypted_rc4_40(os, "sample rgb24 jpeg rc40.pdf");
    write_rgb24_jpeg_file_encrypted_rc4_128(os, "sample rgb24 jpeg rc128.pdf");
    write_rgb24_jpeg_file_encrypted_aes128(os, "sample rgb24 jpeg aes128.pdf");
    write_rgb24_jpeg_file_encrypted_aes256(os, "sample rgb24 jpeg aes256.pdf");

    printf("------------------------------\n");
    printf("Hit [enter] to exit:\n");
    getchar();
    return 0;
}

