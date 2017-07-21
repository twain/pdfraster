#
# This is a makefile for building on non-Windows platforms.
#



# Let's start by offloading platform and common stuff to a central Makefile...
include ../pdfras_writer/Makefile.platform
.SUFFIXES: .o .c .h



# This is what we want to build...
CFLAGS += -I"../pdfras_writer" -fPIC
O =	pdfrasread_files.o \
	pdfrasread.o



# do it all
all: ../bin/$(TARGETDIR)/libpdfras_reader.$(STATICLIBEXT) ../bin/$(TARGETDIR)/libpdfras_reader.$(SHAREDLIBEXT)
debug: ../bin/$(TARGETDIR)/libpdfras_reader.$(STATICLIBEXT) ../bin/$(TARGETDIR)/libpdfras_reader.$(SHAREDLIBEXT)



# how we clean...
clean:
	rm -f ../bin/$(TARGETDIR)/libpdfras_reader.$(STATICLIBEXT) ../bin/$(TARGETDIR)/libpdfras_reader.$(SHAREDLIBEXT) $O



# create a static library for pdfras_reader
../bin/$(TARGETDIR)/libpdfras_reader.$(STATICLIBEXT): $O
	@mkdir -p ../bin/$(TARGETDIR)
	@rm -f $@
	$(STATICLIBCMD) $@ $O



# create a shared library for pdfras_reader
../bin/$(TARGETDIR)/libpdfras_reader.$(SHAREDLIBEXT): $O
	@mkdir -p ../bin/$(TARGETDIR)
	@rm -f ../bin/$@
	$(SHAREDLIBCMD) $(SHAREDFLAGS) $(BINARYFLAGS) $(LFLAGS) -o $@ $O $(LIBDIRS) $(LIBFILES) $(LIBS)



# compile all the individual object modules
pdfrasread.o: pdfrasread.c
pdfrasread_files.o: pdfrasread_files.c

