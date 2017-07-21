#
# This is a makefile for building on non-Windows platforms.
#



# Let's start by offloading platform and common stuff to a central Makefile...
include Makefile.platform
.SUFFIXES: .o .c .h



# This is what we want to build...
CFLAGS += -fPIC
O =	md5.o \
	PdfAlloc.o \
	PdfArray.o \
	PdfAtoms.o \
	PdfContentsGenerator.o \
	PdfDatasink.o \
	PdfDict.o \
	PdfHash.o \
	PdfImage.o \
	PdfOS.o \
	PdfRaster.o \
	PdfSecurityHandler.o \
	PdfStandardObjects.o \
	PdfStreaming.o \
	PdfString.o \
	PdfStrings.o \
	PdfValues.o \
	PdfXrefTable.o



# do it all
all: ../bin/$(TARGETDIR)/libpdfras_writer.$(STATICLIBEXT) ../bin/$(TARGETDIR)/libpdfras_writer.$(SHAREDLIBEXT)
debug: ../bin/$(TARGETDIR)/libpdfras_writer.$(STATICLIBEXT) ../bin/$(TARGETDIR)/libpdfras_writer.$(SHAREDLIBEXT)



# how we clean...
clean:
	rm -f ../bin/$(TARGETDIR)/libpdfras_writer.$(STATICLIBEXT) ../bin/$(TARGETDIR)/libpdfras_writer.$(SHAREDLIBEXT) $O



# create a static library for pdfras_writer
../bin/$(TARGETDIR)/libpdfras_writer.$(STATICLIBEXT): $O
	@mkdir -p ../bin/$(TARGETDIR)
	@rm -f $@
	$(STATICLIBCMD) $@ $O



# create a shared library for pdfras_writer
../bin/$(TARGETDIR)/libpdfras_writer.$(SHAREDLIBEXT): $O
	@mkdir -p ../bin/$(TARGETDIR)
	@rm -f ../bin/$@
	$(SHAREDLIBCMD) $(SHAREDFLAGS) $(BINARYFLAGS) $(LFLAGS) -o $@ $O $(LIBDIRS) $(LIBFILES) $(LIBS)



# compile all the individual object modules
md5.o: md5.c md5.h
PdfAlloc.o: PdfAlloc.c  PdfAlloc.h PdfPlatform.h
PdfArray.o: PdfArray.c  PdfArray.h PdfPlatform.h
PdfAtoms.o: PdfAtoms.c  PdfAtoms.h PdfStandardAtoms.h PdfPlatform.h
PdfContentsGenerator.o: PdfContentsGenerator.c PdfContentsGenerator.h PdfDatasink.h PdfStreaming.h PdfAlloc.h
PdfDatasink.o: PdfDatasink.c PdfDatasink.h PdfAlloc.h
PdfDict.o: PdfDict.c PdfDict.h PdfHash.h PdfAtoms.h PdfDatasink.h PdfXrefTable.h PdfStandardAtoms.h
PdfHash.o: PdfHash.c PdfHash.h PdfStandardAtoms.h PdfStrings.h
PdfImage.o: PdfImage.c PdfImage.h PdfStandardObjects.h PdfStandardAtoms.h PdfDict.h PdfArray.h PdfContentsGenerator.h ../icc_profile/srgb_icc_profile.h
PdfOS.o: PdfOS.c PdfOS.h PdfPlatform.h
PdfRaster.o: PdfRaster.c PdfRaster.h PdfDict.h PdfAtoms.h PdfStandardAtoms.h PdfString.h PdfXrefTable.h PdfStandardObjects.h PdfArray.h
PdfSecurityHandler.o: PdfSecurityHandler.c PdfSecurityHandler.h PdfAlloc.h
PdfStandardObjects.o: PdfStandardObjects.c PdfStandardObjects.h PdfStrings.h PdfStandardAtoms.h PdfDict.h PdfArray.h PdfContentsGenerator.h
PdfStreaming.o: PdfStreaming.c PdfStreaming.h PdfDict.h PdfAtoms.h PdfString.h PdfXrefTable.h PdfSecurityHandler.h PdfStandardObjects.h PdfArray.h
PdfString.o: PdfString.c PdfString.h
PdfStrings.o: PdfStrings.c PdfStrings.h
PdfValues.o: PdfValues.c PdfValues.h PdfString.h PdfStrings.h PdfDict.h PdfArray.h
PdfXrefTable.o: PdfXrefTable.c PdfXrefTable.h
