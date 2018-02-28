
# This is a makefile for building on non-Windows platforms.

PROGRAM= demo_raster_encoder

H =	../common/portability.h \
    ../pdfras_writer/PdfOS.h \
    ../pdfras_writer/PdfAlloc.h \
    ../pdfras_writer/PdfDict.h \
    ../pdfras_writer/PdfStreaming.h \
    ../pdfras_writer/PdfAtoms.h \
    ../pdfras_writer/PdfStandardAtoms.h \
    ../pdfras_writer/PdfXrefTable.h \
    ../pdfras_writer/PdfImage.h \
    ../pdfras_writer/PdfStandardObjects.h \
    ../pdfras_writer/PdfContentsGenerator.h \
	../pdfras_encryption/pdfras_encryption.h

CFLAGS = -O -g -I"../common" -I"../pdfras_writer" -I"../pdfras_encryption" -lpdfras_writer

LDFLAGS = -L../pdfras_writer

LIBS = -lpdfras_writer

$(PROGRAM): demo_raster_encoder.c

demo_raster_encoder.c: bw_ccitt_data.h color_page.h gray8_page.h \
	color_strip0.h color_strip1.h color_strip2.h color_strip3.h $(H)

headers: bw_ccitt_data.h color_page.h color_strip0.h color_strip1.h \
		color_strip2.h color_strip3.h gray8_page.h

bw_ccitt_data.h: bw_ccitt_page.bin bin2carray.exe
	./bin2carray.exe -i bw_ccitt_page.bin -s bw_ccitt_page_bin > bw_ccitt_data.h

color_page.h: color_page.jpg bin2carray.exe
	./bin2carray.exe -i color_page.jpg -s color_page_jpg > color_page.h

gray8_page.h: gray8_page.jpg bin2carray.exe
	./bin2carray.exe -i gray8_page.jpg -s gray8_page_jpg > gray8_page.h

color_strip0.h: color_strip0.jpg bin2carray.exe
	./bin2carray.exe -i color_strip0.jpg -s color_strip0_jpg > color_strip0.h

color_strip1.h: color_strip1.jpg bin2carray.exe
	./bin2carray.exe -i color_strip1.jpg -s color_strip1_jpg > color_strip1.h

color_strip2.h: color_strip2.jpg bin2carray.exe
	./bin2carray.exe -i color_strip2.jpg -s color_strip2_jpg > color_strip2.h

color_strip3.h: color_strip3.jpg bin2carray.exe
	./bin2carray.exe -i color_strip3.jpg -s color_strip3_jpg > color_strip3.h

bin2carray.exe: bin2carray.c
	$(CC) -o bin2carray.exe bin2carray.c

clean:
	rm -rf *.dSYM *.o $(PROGRAM)
