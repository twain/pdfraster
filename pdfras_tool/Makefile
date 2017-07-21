#
# This is a makefile for building on non-Windows platforms.
#



# Let's start by offloading platform and common stuff to a central Makefile...
include ../pdfras_writer/Makefile.platform
.SUFFIXES: .o .cpp .h



# This is what we want to build...
CXXFLAGS += -I"../pdfras_writer" -I"../pdfras_reader" -Wno-c++0x-compat -std=c++0x
O =	application.o \
	configuration.o \
	error.o \
	journal.o \
	jpeg.o \
	main.o \
	tiff.o



# do it all
all: ../bin/$(TARGETDIR)/pdfras_tool
debug: ../bin/$(TARGETDIR)/pdfras_tool



# how we clean...
clean:
	rm -f ../bin/$(TARGETDIR)/pdfras_tool $O



# create the pdfras_tool
../bin/$(TARGETDIR)/pdfras_tool: $O
	@mkdir -p ../bin/$(TARGETDIR)
	@rm -f $@
	$(Cxx) $(BINARYFLAGS) -o $@ $O ../bin/$(TARGETDIR)/libpdfras_reader.$(STATICLIBEXT)



# compile all the individual object modules
application.o: application.cpp
configuration.o: configuration.cpp
error.o: error.cpp
journal.o: journal.cpp
jpeg.o: jpeg.cpp
main.o: main.cpp
tiff.o: tiff.cpp

