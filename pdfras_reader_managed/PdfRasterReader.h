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
			literal int PDFRASRD_API_LEVEL = RASREAD_API_LEVEL;
			literal String^ PDFRASRD_LIBRARY_VERSION = PDFRAS_LIBRARY_VERSION;
		};

		// Pixel Formats
		enum struct PdfRasterPixelFormat
		{
			PDFRASRD_BITONAL = PDFRAS_BITONAL,				//  1-bit per pixel, 0=black
			PDFRASRD_GRAYSCALE = PDFRAS_GRAY8,				//  8-bit per pixel, 0=black
			PDFRASRD_GRAYSCALE16 = PDFRAS_GRAY16,			// 16-bit per pixel, 0=black
			PDFRASRD_RGB = PDFRAS_RGB24,					// 24-bit per pixel, sRGB
			PDFRASRD_RGB48 = PDFRAS_RGB48,					// 48-bit per pixel
		};

		// Compression Modes
		enum struct PdfRasterCompression
		{
			PDFRASRD_UNCOMPRESSED = PDFRAS_UNCOMPRESSED,	// uncompressed (/Filter null)
			PDFRASRD_JPEG = PDFRAS_JPEG,					// JPEG baseline (DCTDecode)
			PDFRASRD_CCITTG4 = PDFRAS_CCITTG4,				// CCITT Group 4 (CCITTFaxDecode)
		};
#pragma endregion Public Definitions for PdfRasterReader

		///////////////////////////////////////////////////////////////////////////////
		// Public Methods: PdfRasterReader
		///////////////////////////////////////////////////////////////////////////////
#pragma region Public Methods: PdfRasterReader
	public:
		int  decoder_create(int apiLevel, String^ pdfFileName);
		void decoder_get_creator(int enc, String^ creator);
		void decoder_get_resolution(int enc, double xdpi, double ydpi);
		void decoder_get_pixelformat(int enc, PdfRasterPixelFormat format);
		void decoder_get_compression(int enc, PdfRasterCompression compression);
		void decoder_start_page(int enc, int width);
		void decoder_read_strip(int enc, int rows, array<unsigned char>^ buf, unsigned offset, unsigned len);
		void decoder_end_page(int enc);
		void decoder_end_document(int enc);
		void decoder_destroy(int enc);
#pragma endregion Public Methods for PdfRasterReader
	};
}
