// pdfras_tool  page.h

#pragma once

class page_info {
public:
	page_info() {
		pixel_format = RASREAD_FORMAT_NULL;
		bits_per_component = 0;
		width = 0;
		height = 0;
		rotation = 0;
		x_dpi = 0;
		y_dpi = 0;
		strips = 0;
		max_strip_size = 0;
		compression = RASREAD_COMPRESSION_NULL;
	}

	RasterReaderPixelFormat get_pixel_format() const { return pixel_format; }
	void set_pixel_format(RasterReaderPixelFormat a_pixel_format) { pixel_format = a_pixel_format; }
	char *get_pixel_format_string() const;

	int get_bits_per_component() const { return bits_per_component; }
	void set_bits_per_component(int a_bits_per_component) { bits_per_component = a_bits_per_component; }

	int get_width() const { return width; }
	void set_width(int a_width) { width = a_width; }

	int get_height() const { return height; }
	void set_height(int a_height) { height = a_height; }

	int get_rotation() const { return rotation; }
	void set_rotation(int a_rotation) { rotation = a_rotation; }

	double get_x_dpi() const { return x_dpi; }
	void set_x_dpi(double a_x_dpi) { x_dpi = a_x_dpi; }

	double get_y_dpi() const { return y_dpi; }
	void set_y_dpi(double a_y_dpi) { y_dpi = a_y_dpi; }

	int get_strips() const { return strips; }
	void set_strips(int a_strips) { strips = a_strips; }

	size_t get_max_strip_size() const { return max_strip_size; }
	void set_max_strip_size(size_t a_max_strip_size) { max_strip_size = a_max_strip_size; }

	RasterReaderCompression get_compression() const { return compression; }
	void set_compression(RasterReaderCompression a_compression) { compression = a_compression; }
	char *get_compression_string() const;
private:
	RasterReaderPixelFormat pixel_format;
	int bits_per_component;
	int width;
	int height;
	int rotation; // clockwise rotation in degrees to be applied when displayed
	double x_dpi;
	double y_dpi;
	int strips;
	size_t max_strip_size;
	RasterReaderCompression compression;
};