// pdfras_tool  application.h

#pragma once

const char PROG_NAME[] = "pdfras_tool";

class application {
public:
	application() { page_count = -1; }
	void parse_args(int argc, char * argv[]);
	void application::usage();
	void run();
private:
	handles handle;
	page_info page;
	configuration config;

	int page_count;

	void pdfr_lib_info();
	void pdfr_open();
	void pdfr_parse_details();
	void pdfr_extract_image();
	void pdfr_close();
};