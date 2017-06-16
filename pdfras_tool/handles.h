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
			LOG(err, "| file not found or not readable \"%s\"", name.c_str());
			ERR(FILE_NOT_READABLE);
		}
		LOG(dbg, "<");
	}

	void open(const char *mode) {
		LOG(dbg, "> file=\"%s\" mode=\"%s\"", name.c_str(), mode);
		fp = fopen(name.c_str(), mode);
		if (nullptr == fp) {
			LOG(err, "| unable to fopen file \"%s\"", name.c_str());
			ERR(FILE_OPEN_FAIL);
		}
		LOG(dbg, "<");
	}

	void close()
	{
		LOG(dbg, "> file=\"%s\"", name.c_str());
		if (fp != nullptr) {
			if (fclose(fp)) {
				LOG(err, "| error closing file \"%s\"", name.c_str());
				ERR(FILE_CLOSE_FAIL);
			}
			fp = nullptr;
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