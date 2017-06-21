// pdfras_tool  application.h

#pragma once

const string app_version("0.1");
const string app_name("pdfras_tool");

class application {
public:
	application() { page_count = -1; }
	void parse_args(int argc, char * argv[]);
	void application::usage();
	void run();
private:
	handles handle;
	configuration config;

	int page_count;
	RasterReaderPixelFormat page_pixel_format;
	int page_bit_per_component;
	int page_width;
	int page_height;
	int page_rotation; // clockwise rotation in degrees to be applied to page
	double page_xdpi;
	double page_ydpi;
	int page_strips;
	size_t page_max_strip_size;
	RasterReaderCompression page_compression;

	void pdfr_lib_info();
	void pdfr_open();
	void pdfr_parse_details();
	void pdfr_parse_image();
	void pdfr_close();
};