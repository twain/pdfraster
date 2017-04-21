// pdfras_reader_managed.h

#pragma once

using namespace System;

namespace PdfRasterReader {

	public ref class Reader
	{
		///////////////////////////////////////////////////////////////////////////////
		// Public Definitions: PdfRasterReader
		///////////////////////////////////////////////////////////////////////////////
#pragma region Public Definitions: PdfRasterReader
	public:
		value struct PdfRasterConst
		{
			literal int PDFRASREAD_API_LEVEL = RASREAD_API_LEVEL;
			literal String^ PDFRASREAD_LIBRARY_VERSION = PDFRAS_LIBRARY_VERSION;
		};

		// Pixel Formats
		enum struct PdfRasterReaderPixelFormat
		{
			PDFRASREAD_FORMAT_NULL = RASREAD_FORMAT_NULL,			// null value
			PDFRASREAD_BITONAL = RASREAD_BITONAL,					//  1-bit per pixel, 0=black
			PDFRASREAD_GRAYSCALE = RASREAD_GRAY8,					//  8-bit per pixel, 0=black
			PDFRASREAD_GRAYSCALE16 = RASREAD_GRAY16,				// 16-bit per pixel, 0=black
			PDFRASREAD_RGB = RASREAD_RGB24,							// 24-bit per pixel, sRGB
			PDFRASREAD_RGB48 = RASREAD_RGB48,						// 48-bit per pixel
		};

		// Compression Modes
		enum struct PdfRasterReaderCompression
		{
			PDFRASREAD_COMPRESSION_NULL = RASREAD_COMPRESSION_NULL,	// null value
			PDFRASREAD_UNCOMPRESSED = RASREAD_UNCOMPRESSED,			// uncompressed (/Filter null)
			PDFRASREAD_JPEG = RASREAD_JPEG,							// JPEG baseline (DCTDecode)
			PDFRASEARD_CCITTG4 = RASREAD_CCITTG4,					// CCITT Group 4 (CCITTFaxDecode)
		};
#pragma endregion Public Definitions for PdfRasterReader

		///////////////////////////////////////////////////////////////////////////////
		// Public Methods: PdfRasterReader
		///////////////////////////////////////////////////////////////////////////////
#pragma region Public Methods: PdfRasterReader
	public:
		int  decoder_create(int apiLevel, String^ pdfFileName);
		int  decoder_get_page_count(int idx);
		int  decoder_get_width(int idx);
		int  decoder_get_height(int idx);
		double decoder_get_xresolution(int idx);
		double decoder_get_yresolution(int idx);
		PdfRasterReaderPixelFormat decoder_get_pixelformat(int idx);
		PdfRasterReaderCompression decoder_get_compression(int idx);
		array<Byte>^ decoder_read_strips(int idx);
		void decoder_destroy(int idx);
#pragma endregion Public Methods for PdfRasterReader
	};
}
