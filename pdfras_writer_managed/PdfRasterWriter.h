// PdfRasterWriter.h

#pragma once

using namespace System;

namespace PdfRasterWriter {

	public ref class Writer
	{
		///////////////////////////////////////////////////////////////////////////////
		// Public Definitions: PdfRasterWriter
		///////////////////////////////////////////////////////////////////////////////
#pragma region Public Definitions: PdfRasterWriter
	public:
		value struct PdfRasterConst
		{
			literal int PDFRASWR_API_LEVEL = PDFRAS_API_LEVEL;
			literal String^ PDFRASWR_LIBRARY_VERSION = PDFRAS_LIBRARY_VERSION;
		};

		// Pixel Formats
		enum struct PdfRasterPixelFormat
		{
			PDFRASWR_BITONAL = PDFRAS_BITONAL,				//  1-bit per pixel, 0=black
			PDFRASWR_GRAYSCALE = PDFRAS_GRAY8,				//  8-bit per pixel, 0=black
			PDFRASWR_GRAYSCALE16 = PDFRAS_GRAY16,			// 16-bit per pixel, 0=black
			PDFRASWR_RGB = PDFRAS_RGB24,					// 24-bit per pixel, sRGB
			PDFRASWR_RGB48 = PDFRAS_RGB48,					// 48-bit per pixel
		};

		// Compression Modes
		enum struct PdfRasterCompression
		{
			PDFRASWR_UNCOMPRESSED = PDFRAS_UNCOMPRESSED,	// uncompressed (/Filter null)
			PDFRASWR_JPEG = PDFRAS_JPEG,					// JPEG baseline (DCTDecode)
			PDFRASWR_CCITTG4 = PDFRAS_CCITTG4,				// CCITT Group 4 (CCITTFaxDecode)
		};
#pragma endregion Public Definitions for PdfRasterWriter

        ///////////////////////////////////////////////////////////////////////////////
        // Public Methods: PdfRasterWriter
        ///////////////////////////////////////////////////////////////////////////////
#pragma region Public Methods: PdfRasterWriter
	public:
		int  encoder_create(int apiLevel, String^ pdfFileName);
		void encoder_set_creator(int enc, String^ creator);
		void encoder_set_resolution(int enc, double xdpi, double ydpi);
		void encoder_set_pixelformat(int enc, PdfRasterPixelFormat format);
		void encoder_set_compression(int enc, PdfRasterCompression compression);
		void encoder_start_page(int enc, int width);
		void encoder_write_strip(int enc, int rows, array<unsigned char>^ buf, unsigned offset, unsigned len);
		void encoder_end_page(int enc);
		void encoder_end_document(int enc);
		void encoder_destroy(int enc);
#pragma endregion Public Methods for PdfRasterWriter
	};
}
