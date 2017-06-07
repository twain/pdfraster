// pdfras_tool  handles.h

#pragma once

class file {
private:
	FILE *fp;
	string name;
public:
	file() { fp = nullptr;  }
	~file() { if (fp) fclose(fp); }

	FILE* get_fp() const { return fp; }

	string get_name() const { return name; };
	void set_name(const char *a_name) { name = a_name; };

	void readable() {
		LOG(dbg, "> file=\"%s\"", name.c_str());
		bool is_readable = (ACCESS(name.c_str(), ACCESS_READ) == 0) ? true : false;
		if (!is_readable) {
			LOG(err, "| file not found or not readable");
			ERR(FILE_NOT_READABLE);
		}
		LOG(dbg, "<");
	}

	void open(const char *mode) {
		LOG(dbg, "> file=\"%s\" mode=\"%s\"", name.c_str(), mode);
		fp = fopen(name.c_str(), mode);
		if (nullptr == fp) {
			LOG(err, "| file not found or not readable");
			ERR(FILE_OPEN_WRITE_FAIL);
		}
		LOG(dbg, "<");
	}
};

class handles {
private:
	t_pdfrasreader *reader;
public:
	file ifile, ofile;

	handles() { reader = nullptr; }
	~handles() {if (reader) pdfrasread_destroy(reader); }

	t_pdfrasreader* get_reader() const { return reader; }
	void set_reader(t_pdfrasreader* r) { reader = r; }
};