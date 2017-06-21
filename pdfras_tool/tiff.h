// pdfras_tool  tiff.h

#pragma once

// use big endian b/c avoids having to swap 16-bit gray and 48-bit RGB sample bytes
const unsigned short TIFF_BYTE_ORDER_ENDIAN_BIG = 0x4D4D;
const unsigned short TIFF_VERSION = 0x2A;

const unsigned TIFF_TAG_NUM_COLOR = 16; // we define 16 tiff tags here, update if add more tags
const unsigned short TIFF_TAG_NEWSUBFILETYPE = 254;
const unsigned short TIFF_TAG_IMAGEWIDTH = 256;
const unsigned short TIFF_TAG_IMAGELENGTH = 257;
const unsigned short TIFF_TAG_BITSPERSAMPLE = 258;
const unsigned short TIFF_TAG_COMPRESSION = 259;
const unsigned short TIFF_TAG_PHOTOMETRICINTERPRETATION = 262;
const unsigned short TIFF_TAG_STRIPOFFSETS = 273;
const unsigned short TIFF_TAG_ORIENTATION = 274;
const unsigned short TIFF_TAG_SAMPLESPERPIXEL = 277;
const unsigned short TIFF_TAG_ROWSPERSTRIP = 278;
const unsigned short TIFF_TAG_STRIPBYTECOUNTS = 279;
const unsigned short TIFF_TAG_XRESOLUTION = 282;
const unsigned short TIFF_TAG_YRESOLUTION = 283;
const unsigned short TIFF_TAG_RESOLUTIONUNIT = 296;
const unsigned short TIFF_TAG_SOFTWARE = 305;
const unsigned short TIFF_TAG_DATETIME = 306;

const unsigned short TIFF_TYPE_BYTE = 1;
const unsigned short TIFF_TYPE_ASCII = 2;
const unsigned short TIFF_TYPE_SHORT = 3;
const unsigned short TIFF_TYPE_LONG = 4;
const unsigned short TIFF_TYPE_RATIONAL = 5;

const unsigned short TIFF_PHOTOMETRICINTERPRETATION_WHITEISZERO = 0;
const unsigned short TIFF_PHOTOMETRICINTERPRETATION_BLACKISZERO = 1;
const unsigned short TIFF_PHOTOMETRICINTERPRETATION_RGB = 2;

const unsigned short TIFF_COMPRESSION_UNCOMPRESSED = 1;
const unsigned short TIFF_COMPRESSION_CCITT_G4_FAX = 4;

enum tiff_ifd_type { ImageWidth, ImageLength, BitsPerSample, Compression, PhotometricInterpretation, StripOffsets, SamplesPerPixel, RowsPerStrip, StripByteCounts, XResolution, YResolution, ResolutionUnit };

class tiff {
public:
	tiff(string filename);
	~tiff();
	void write_header(t_pdfrasreader* reader, int page, int strips, size_t max_strip_size, RasterReaderPixelFormat pixel_format);
	void write_body(t_pdfrasreader*reader, int page, int strips, size_t max_strip_size, RasterReaderPixelFormat pixel_format, double xdpi, double ydpi);
	void write_trailer(RasterReaderPixelFormat pixel_format, int width, int length, RasterReaderCompression cmprs, int rotation);
private:
	file ofile;
	bool image_data_size_odd;
	unsigned offset_image_data;
	unsigned offset_xresolution;
	unsigned offset_yresolution;
	unsigned offset_bits_per_sample;
	unsigned offset_software;
	unsigned offset_datetime;
	string str_software;
	string str_datetime;
	void tiff::tiff_write_byte(int val);
	void tiff::tiff_write_short(int val);
	void tiff::tiff_write_long(int val);
	void tiff::tiff_write_ascii(string str);
	void tiff::write_dir_preamble(int tag, int type= TIFF_TYPE_LONG, int len=1);
	void tiff::write_dir_entry_short(int tag, int val, int len = 1);
	void tiff::write_dir_entry_long(int tag, int val, int len = 1);
	void tiff::write_dir_entry_rational(int tag, unsigned offset, int len=1);
	void tiff::write_dir_entry_ascii(int tag, unsigned offset, string str);
};