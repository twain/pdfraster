// pdfras_tool  tiff.cpp

///////////////////////////////////////////////////////////////////////////////////////
//  Copyright (C) 2017 TWAIN Working Group
//
//  Permission is hereby granted, free of charge, to any person obtaining a
//  copy of this software and associated documentation files (the "Software"),
//  to deal in the Software without restriction, including without limitation
//  the rights to use, copy, modify, merge, publish, distribute, sublicense,
//  and/or sell copies of the Software, and to permit persons to whom the
//  Software is furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
//  THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//  DEALINGS IN THE SOFTWARE.
///////////////////////////////////////////////////////////////////////////////////////

#include <string>
#include <iostream>

#include "os_specific.h"
#ifdef COMPILING_FOR_WIN_MSVC
#	include "io.h"
#else
#	include "unistd.h"
#endif

#include <pdfrasread.h>

#include "journal.h"
#include "error.h"
#include "handles.h"
#include "tiff.h"
#include "configuration.h"
#include "application.h"

tiff::tiff(string filename)
{
	LOG(dbg, ">");

	string ext(".tif");
	bool no_ext = filename.length() < ext.length() 
		|| (filename.substr(filename.length() - ext.length(), ext.length()) != ext);
	ofile.set_name((filename + (no_ext ? ext : "")).c_str());

	LOG(dbg, "> opening for writing TIFF filename=\"%s\"", ofile.get_name().c_str());
	ofile.open("wb");

	LOG(dbg, "<");
}

tiff::~tiff()
{
	ofile.close();
}

static void tiff_byte_to_char_buf(int val, unsigned char *buf)
{
	LOG(dbg, "> val=%d (0x%X)", val, val);
	buf[0] = val >> 0;
	LOG(dbg, "< buf[0]=0x%2.2X", buf[0]);
}

static void tiff_short_to_char_buf(int val, unsigned char *buf)
{
	LOG(dbg, "> val=%d (0x%X)", val, val);
	buf[1] = val >> 0;
	buf[0] = val >> 8;
	LOG(dbg, "< buf[0]=0x%2.2X buf[1]=0x%2.2X", buf[0], buf[1]);
}

static void tiff_long_to_char_buf(int val, unsigned char *buf)
{
	LOG(dbg, "> val=%d (0x%X)",val,val);
	buf[3] = val >> 0;
	buf[2] = val >> 8;
	buf[1] = val >> 16;
	buf[0] = val >> 24;
	LOG(dbg, "< buf[0]=0x%2.2X buf[1]=0x%2.2X buf[2]=0x%2.2X buf[3]=0x%2.2X", buf[0], buf[1], buf[2], buf[3]);
}

void tiff::tiff_write_byte(int val) {
	LOG(dbg, "> val=%d (0x%X)", val, val);
	unsigned char buf[1];
	tiff_byte_to_char_buf(val, buf);
	size_t sz = sizeof(buf);
	size_t wc = fwrite(buf, 1, sz, ofile.get_fp());
	if (wc != sz) {
		LOG(err, "| failed writing tiff 1 byte wc=%zu sz=%zu filename=\"%s\"", wc, sz, ofile.get_name().c_str());
		ERR(FILE_WRITE_FAIL);
	}
	LOG(dbg, "<");
}

void tiff::tiff_write_short(int val) {
	LOG(dbg, "> val=%d (0x%X)", val, val);
	unsigned char buf[2];
	tiff_short_to_char_buf(val, buf);
	size_t sz = sizeof(buf);
	size_t wc = fwrite(buf, 1, sz, ofile.get_fp());
	if (wc != sz) {
		LOG(err, "| failed writing tiff 2 byte short wc=%zu sz=%zu filename=\"%s\"", wc, sz, ofile.get_name().c_str());
		ERR(FILE_WRITE_FAIL);
	}
	LOG(dbg, "<");
}

void tiff::tiff_write_long(int val) {
	LOG(dbg, "> val=%d (0x%X)", val, val);
	unsigned char buf[4];
	tiff_long_to_char_buf(val, buf);
	size_t sz = sizeof(buf);
	size_t wc = fwrite(buf, 1, sz, ofile.get_fp());
	if (wc != sz) {
		LOG(err, "| failed writing tiff 4 byte long wc=%zu sz=%zu filename=\"%s\"", wc, sz, ofile.get_name().c_str());
		ERR(FILE_WRITE_FAIL);
	}
	LOG(dbg, "<");
}

void tiff::tiff_write_ascii(string str) {
	LOG(dbg, "> str=\"%s\"", str.c_str());
	size_t sz = str.length();
	size_t wc = fwrite(str.c_str(), 1, sz, ofile.get_fp());
	if (wc != sz) {
		LOG(err, "| failed writing tiff ascii wc=%zu sz=%zu filename=\"%s\"", wc, sz, ofile.get_name().c_str());
		ERR(FILE_WRITE_FAIL);
	}
	if ((str.length() + 1) & 1) {
		tiff_write_short(0);
	}
	else {
		tiff_write_byte(0);
	}
	LOG(dbg, "<");
}

void tiff::write_header(t_pdfrasreader* reader, int page, int strips, size_t max_strip_size, RasterReaderPixelFormat pixel_format)
{
	LOG(dbg, "> page=%d strips=%d max_strip_size=%zu filename=\"%s\"", page, strips, max_strip_size, ofile.get_name().c_str());
	unsigned tiff_offset = 0;

	// write TIFF header fixed part: byte order
	LOG(dbg, "| write tiff fixed header tiff byte order (0x%X)", TIFF_BYTE_ORDER_ENDIAN_BIG);
	tiff_write_short(TIFF_BYTE_ORDER_ENDIAN_BIG);
	tiff_offset += 2;

	// write TIFF header fixed part: version number
	const int tiff_version = 0x2A;
	LOG(dbg, "| write tiff fixed header tiff version (0x%X)", TIFF_VERSION);
	tiff_write_short(TIFF_VERSION);
	tiff_offset += 2;

	// calculate image data size
	size_t image_data_size = 0;
	for (int s = 0; s < strips; s++) {
		size_t rcvd = pdfrasread_read_raw_strip(reader, page - 1, s, NULL, max_strip_size);
		image_data_size += rcvd;
		LOG(dbg, "| strip=%d rcvd=%d image_data_size=%zu", s, rcvd, image_data_size);
	}

	// TIFF standard says image data size must be even number
	image_data_size_odd = image_data_size & 1;
	if (image_data_size_odd) {
		image_data_size += 1;
		LOG(dbg, "| image_data_size was odd, adjusted image_data_size=%zu", image_data_size);
	}
	tiff_offset += 4;
	offset_image_data = tiff_offset;
	LOG(dbg, "| tiff offset_image_data = %u", offset_image_data);

	// calculate TIFF header variable part: byte offset to IFD = header + image_data + xres + yres + BPS + software + datetime;
	tiff_offset += (unsigned) image_data_size; // size of image data

	offset_xresolution = tiff_offset;
	LOG(dbg, "| tiff offset_xresolution = %u (0x%X)", offset_xresolution, offset_xresolution);
	tiff_offset += 8; // size of xres data

	offset_yresolution = tiff_offset;
	LOG(dbg, "| tiff offset_yresolution = %u (0x%X)", offset_yresolution, offset_yresolution);
	tiff_offset += 8; // size of yres data

	offset_bits_per_sample = 0;
	if ((pixel_format == RASREAD_RGB24) || (pixel_format == RASREAD_RGB48)) {
		offset_bits_per_sample = tiff_offset;
		LOG(dbg, "| tiff offset_bits_per_sample = %u (0x%X)", offset_bits_per_sample, offset_bits_per_sample);
		tiff_offset += 6; // if color image, size of 3 tiff short words
	}

	offset_software = tiff_offset;
	LOG(dbg, "| tiff offset_software = %u (0x%X)", offset_software, offset_software);
	str_software = app_name + " " + app_version;
	tiff_offset += (str_software.length() + 1 + 1) & ~1; // size of software string + 1 for trailing 0, must be even

	time_t t = time(0);   // get time now
	struct tm * now = localtime(&t);
	char tbuf[32]; // only needs to be 20
	strftime(tbuf, sizeof(tbuf), "%Y:%m:%d %H:%M:%S", now); //if change format string, adjust sizeof tbuf decl on prior line
	str_datetime = tbuf;

	offset_datetime = tiff_offset;
	LOG(dbg, "| tiff offset_datetime = %u (0x%X)", offset_software, offset_software);
	tiff_offset += (str_datetime.length() + 1 + 1) & ~1; // size of date time string + 1 for trailing 0, should be even already

	LOG(dbg, "| write tiff variable header (0x%X)", tiff_offset);
	tiff_write_long(tiff_offset);

	LOG(dbg, "<");
}

void tiff::write_body(t_pdfrasreader* reader, int page, int strips, size_t max_strip_size, RasterReaderPixelFormat pixel_format, double xdpi, double ydpi)
{
	LOG(dbg, "> filename=\"%s\"", ofile.get_name().c_str());

	char *rawstrip = new char[max_strip_size];

	for (int s = 0; s < strips; s++) {
		size_t rcvd = pdfrasread_read_raw_strip(reader, page - 1, s, rawstrip, max_strip_size);

		LOG(dbg, "| writing strip=%d size=%zu page=%d max_strip_size=%zu", s, rcvd, page, max_strip_size);

		size_t wrtc = fwrite(rawstrip, rcvd, 1, ofile.get_fp());
		if (wrtc != 1) {
			LOG(err, "| failed writing strip=%d size=%zu page=%d max_strip_size=%zu filename=\"%s\"", s, rcvd, page, max_strip_size, ofile.get_name().c_str());
			ERR(FILE_WRITE_FAIL);
		}
	}

	if (image_data_size_odd) {
		LOG(dbg, "| writing extra byte of image data to make total image data length even");
		tiff_write_byte(0x55);
	}

	tiff_write_long((int)xdpi); // xres numerator
	tiff_write_long(1);
	tiff_write_long((int)ydpi); // yres numerator
	tiff_write_long(1);

	if (offset_bits_per_sample) {
		if (pixel_format == RASREAD_RGB24) {
			tiff_write_short(8);
			tiff_write_short(8);
			tiff_write_short(8);
		}
		else if (pixel_format == RASREAD_RGB48) {
			tiff_write_short(16);
			tiff_write_short(16);
			tiff_write_short(16);
		}
	}

	tiff_write_ascii(str_software);
	tiff_write_ascii(str_datetime);

	delete[] rawstrip;
	LOG(dbg, "<");
}

void tiff::write_dir_preamble(int tag, int type, int len) {
	LOG(dbg, "> write tiff directory preamble, tag=%d (0x%X) type=%d len=%d", tag, tag, type, len);
	tiff_write_short(tag);
	tiff_write_short(type);
	tiff_write_long(len);
}

void tiff::write_dir_entry_ascii(int tag, unsigned offset, string str) {
	LOG(dbg, "> write tiff directory entry, ascii, tag=%d (0x%X)", tag, tag);
	int len = (int) str.length() + 1; // add trailing 0, don't include pad byte if any

	write_dir_preamble(tag, TIFF_TYPE_ASCII, len);

	LOG(dbg, "| write tiff directory entry, offset=%u (0x%X)", (unsigned)offset, offset);
	tiff_write_long(offset);

	LOG(dbg, "<");
}

void tiff::write_dir_entry_rational(int tag, unsigned offset, int len) {
	LOG(dbg, "> write tiff directory entry, rational, tag=%d (0x%X)", tag, tag);
	write_dir_preamble(tag, TIFF_TYPE_RATIONAL, len);

	LOG(dbg, "| write tiff directory entry, offset=%u (0x%X)", (unsigned)offset, offset);
	tiff_write_long(offset);

	LOG(dbg, "<");
}

void tiff::write_dir_entry_short(int tag, int val, int len) {
	LOG(dbg, "> write tiff directory entry, short, tag=%d (0x%X)", tag, tag);
	write_dir_preamble(tag, TIFF_TYPE_SHORT, len);

	if (len < 3) {
		LOG(dbg, "| write tiff directory entry, value=%d (0x%X)", val, val);
		tiff_write_short(val);
		tiff_write_short(0x5555);
	}
	else {
		LOG(dbg, "| write tiff directory entry, offset=%u (0x%X)", (unsigned)val, val);
		tiff_write_long(val);
	}

	LOG(dbg, "<");
}

void tiff::write_dir_entry_long(int tag, int val, int len) {
	LOG(dbg, "> write tiff directory entry, long, tag=%d (0x%X)", tag, tag);
	write_dir_preamble(tag, TIFF_TYPE_LONG, len);

	LOG(dbg, "| write tiff directory entry, value=%d (0x%X)", val, val);
	tiff_write_long(val);

	LOG(dbg, "<");
}

//  write the IFD and DEs
void tiff::write_trailer(RasterReaderPixelFormat pixel_format, int width, int length, RasterReaderCompression cmprs, int rotation)
{
	LOG(dbg, ">");
	
	int num_de = TIFF_TAG_NUM_COLOR;
	// if ((pixel_format != RASREAD_RGB24) && (pixel_format != RASREAD_RGB48)) {
	//	num_de -= 1; //gray and bitonal don't use TIFF_TAG_SAMPLESPERPIXEL
	// }

	// wite the IFD Entry Count
	LOG(dbg, "| write tiff IFD Number of Entries (%d)", num_de);
	tiff_write_short(num_de);

	// Directory Entries must be written in ascending order by tag number

	LOG(dbg, "| write tiff NewSubFileType Directory Entry");
	write_dir_entry_long(TIFF_TAG_NEWSUBFILETYPE, 0);

	LOG(dbg, "| write tiff ImageWidth Directory Entry");
	write_dir_entry_long(TIFF_TAG_IMAGEWIDTH, width);

	LOG(dbg, "| write tiff ImageLength Directory Entry");
	write_dir_entry_long(TIFF_TAG_IMAGELENGTH, length);

	int bps_len;
    unsigned bps_val;
	if (pixel_format == RASREAD_BITONAL) {
		bps_len = 1;
		bps_val = 1;
	}
	else if (pixel_format == RASREAD_GRAY8) {
		bps_len = 1;
		bps_val = 8;
	}
	else if (pixel_format == RASREAD_GRAY16) {
		bps_len = 1;
		bps_val = 16;
	}
	else {
		bps_len = 3;
		bps_val = offset_bits_per_sample;
	}
	LOG(dbg, "| write tiff BitsPerSample Directory Entry len=%d val=%u(0x%X)",bps_len, bps_val);
	write_dir_entry_short(TIFF_TAG_BITSPERSAMPLE, bps_val, bps_len);

	int tiff_cmprs = (cmprs == RASREAD_CCITTG4) ? TIFF_COMPRESSION_CCITT_G4_FAX : TIFF_COMPRESSION_UNCOMPRESSED;
	LOG(dbg, "| write tiff Compression Directory Entry %d",tiff_cmprs);
	write_dir_entry_short(TIFF_TAG_COMPRESSION, tiff_cmprs);

	int pmi_val;
	if ((pixel_format == RASREAD_RGB24) || (pixel_format == RASREAD_RGB48)) {
		pmi_val = TIFF_PHOTOMETRICINTERPRETATION_RGB;
	}
	else if ((pixel_format == RASREAD_BITONAL) && ((cmprs == RASREAD_CCITTG4))) {
		pmi_val = TIFF_PHOTOMETRICINTERPRETATION_WHITEISZERO;
	}
	else
		{
		pmi_val = TIFF_PHOTOMETRICINTERPRETATION_BLACKISZERO;
	}
	LOG(dbg, "| write tiff PhotometricInterpretation Directory Entry %d", pmi_val);
	write_dir_entry_short(TIFF_TAG_PHOTOMETRICINTERPRETATION, pmi_val);

	LOG(dbg, "| write tiff StripOffset Directory Entry");
	write_dir_entry_long(TIFF_TAG_STRIPOFFSETS, offset_image_data);

	int orientation;
	int rot = rotation % 360;
	if (rot < 0)
		rot += 360;
	if (rot < (45 + 0)) {
		orientation = 1;
	} else if (rot < (45 + 90)) {
		orientation = 6;
	}
	else if (rot < (45 + 180)) {
		orientation = 3;
	}
	else if (rot < (45 + 270)) {
		orientation = 8;
	}
	else {
		orientation = 1;
	}
	LOG(dbg, "| write tiff Orientation Directory Entry, rotation=%d rot=%d degrees, orientation=%d", rotation, rot, orientation);
	write_dir_entry_short(TIFF_TAG_ORIENTATION, orientation);

	int spp_val;
	if ((pixel_format == RASREAD_RGB24) || (pixel_format == RASREAD_RGB48)) {
		spp_val = 3;
	}
	else {
		spp_val = 1;
	}
	LOG(dbg, "| write tiff SamplesPerPixel Directory Entry %d", spp_val);
	write_dir_entry_short(TIFF_TAG_SAMPLESPERPIXEL, spp_val);

	LOG(dbg, "| write tiff RowsPerStrip Directory Entry");
	write_dir_entry_long(TIFF_TAG_ROWSPERSTRIP, length);

	unsigned sbc_val;
	switch(pixel_format) {
	case RASREAD_BITONAL:
		sbc_val = length * ((width + 7) / 8);
		break;
	case RASREAD_GRAY8:
		sbc_val = length * width;
		break;
	case RASREAD_GRAY16:
		sbc_val = length * width * 2;
		break;
	case RASREAD_RGB24:
		sbc_val = length * width * 3;
		break;
	case RASREAD_RGB48:
		sbc_val = length * width * 3 * 2;
		break;
	}
	LOG(dbg, "| write tiff StripByteCounts Directory Entry %u 0x%X", sbc_val, sbc_val);
	write_dir_entry_long(TIFF_TAG_STRIPBYTECOUNTS, sbc_val);

	LOG(dbg, "| write tiff XResolution Directory Entry");
	write_dir_entry_rational(TIFF_TAG_XRESOLUTION, offset_xresolution);

	LOG(dbg, "| write tiff YResolution Directory Entry");
	write_dir_entry_rational(TIFF_TAG_YRESOLUTION, offset_yresolution);

	LOG(dbg, "| write tiff ResolutionUnit Directory Entry");
	write_dir_entry_short(TIFF_TAG_RESOLUTIONUNIT, 2); // inches

	LOG(dbg, "| write tiff Software Directory Entry");
	write_dir_entry_ascii(TIFF_TAG_SOFTWARE, offset_software, str_software); // inches

	LOG(dbg, "| write tiff DateTime Directory Entry");
	write_dir_entry_ascii(TIFF_TAG_DATETIME, offset_datetime, str_datetime); // inches

	// wite the Offest of Next IFD (0)
	LOG(dbg, "| write tiff Offset to Next IFD");
	tiff_write_long(0);

	LOG(dbg, "<");
}