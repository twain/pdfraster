// pdfras_tool  jpeg.h

#pragma once

class jpeg {
public:
	jpeg(string filename);
	~jpeg();
	void write_body(t_pdfrasreader*reader, int page, int strips, size_t max_strip_size);
private:
	file ofile;
};