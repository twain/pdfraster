// PdfRasterWriter.h

#pragma once

using namespace System;

// namespace PdfRaster {
namespace PdfRasterWriter {

	public ref class Writer
	{
		// TODO: Add your methods for this class here.
	};

	public value struct PdfRasterConst
	{
		literal int PDFRASWR_API_LEVEL = PDFRAS_API_LEVEL;
		literal String^ PDFRASWR_LIBRARY_VERSION = PDFRAS_LIBRARY_VERSION;
	};

	// Pixel Formats
	public enum struct RasterPixelFormat
	{
		PDFRASWR_BITONAL = PDFRAS_BITONAL,				// 1-bit per pixel, 0=black
		PDFRASWR_GRAYSCALE = PDFRAS_GRAY8,				// 8-bit per pixel, 0=black
		PDFRASWR_RGB = PDFRAS_RGB24,					// 24-bit per pixel, sRGB
	};

	// Compression Modes
	public enum struct RasterCompression
	{
		PDFRASWR_UNCOMPRESSED = PDFRAS_UNCOMPRESSED,	// uncompressed (/Filter null)
		PDFRASWR_JPEG = PDFRAS_JPEG,					// JPEG baseline (DCTDecode)
		PDFRASWR_CCITTG4 = PDFRAS_CCITTG4,				// CCITT Group 4 (CCITTFaxDecode)
	};
}
