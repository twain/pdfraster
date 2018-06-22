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

        // Security type
        enum struct PdfRasterReaderSecurityType
        {
            PDFRASREAD_SECURITY_UNKNOWN = RASREAD_SECURITY_UNKNOWN, // Unknown, error occurred
            PDFRASREAD_UNENCRYPTED = RASREAD_UNENCRYPTED,           // document is unencrypted
            RASREAD_STANDARD_SECURITY = RASREAD_STANDARD_SECURITY,  // document is encrypted by password security
            RASREAD_PUBLIC_KEY_SECURITY = RASREAD_PUBLIC_KEY_SECURITY, // document is encrypted by certificate security
        };
#pragma endregion Public Definitions for PdfRasterReader

		///////////////////////////////////////////////////////////////////////////////
		// Public Methods: PdfRasterReader
		///////////////////////////////////////////////////////////////////////////////
#pragma region Public Methods: PdfRasterReader
	public:
		int  decoder_create(int apiLevel, String^ pdfFileName);
        int  decoder_create(int apiLevel, String^ pdfFileName, String^ password);
		int  decoder_get_page_count(int idx);
		int  decoder_get_width(int idx);
		int  decoder_get_height(int idx);
		double decoder_get_xresolution(int idx);
		double decoder_get_yresolution(int idx);
		PdfRasterReaderPixelFormat decoder_get_pixelformat(int idx);
		PdfRasterReaderCompression decoder_get_compression(int idx);
        PdfRasterReaderSecurityType decoder_get_security_type(String^ filename);
        array<Byte>^ decoder_read_strips(int idx);
        bool decoder_is_digitally_signed(int idx);
        int decoder_digital_signature_count(int idx);
        int decoder_digital_signature_validate(int idx, int ds_idx);
        String^ decoder_digital_signature_name(int idx, int ds_idx);
        String^ decoder_digital_signature_contactinfo(int idx, int ds_idx);
        String^ decoder_digital_signature_reason(int idx, int ds_idx);
        String^ decoder_digital_signature_location(int idx, int ds_idx);
        String^ decoder_document_metadata(int idx);
        String^ decoder_page_metadata(int idx, int page); // page: number of page indexed from 1 (1st page -> 1), not from 0
		void decoder_destroy(int idx);
#pragma endregion Public Methods for PdfRasterReader
	};
}
