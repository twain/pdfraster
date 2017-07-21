
#include "PdfAtoms.h"
#include "PdfStandardAtoms.h"
#include "PdfStrings.h"
#include "PdfHash.h"

#include <memory.h>
#include <assert.h>

struct t_pdatomtable {
	// number of elements this table can currently hold
	pduint32 capacity;
	// number of elements currently stored in this table
	pduint32 elements;
	// array of capacity entries.
	t_pdatom *buckets;
};


// Standard Atoms
char *__ATOM_UNDEFINED_ATOM = "<undefined>";
char *__ATOM_Type = "Type";
char *__ATOM_Pages = "Pages";
char *__ATOM_Size = "Size";
char *__ATOM_Root = "Root";
char *__ATOM_Info = "Info";
char *__ATOM_ID = "ID";
char *__ATOM_Catalog = "Catalog";
char *__ATOM_Parent = "Parent";
char *__ATOM_Kids = "Kids";
char* __ATOM_Count = "Count";
char* __ATOM_Page = "Page";
char* __ATOM_Resources = "Resources";
char* __ATOM_MediaBox = "MediaBox";
char* __ATOM_CropBox = "CropBox";
char* __ATOM_Contents = "Contents";
char* __ATOM_Rotate = "Rotate";
char* __ATOM_Length = "Length";
char* __ATOM_Filter = "Filter";
char* __ATOM_DecodeParms = "DecodeParms";
char *__ATOM_Subtype = "Subtype";
char *__ATOM_Width = "Width";
char *__ATOM_Height = "Height";
char *__ATOM_BitsPerComponent = "BitsPerComponent";
char *__ATOM_ColorSpace = "ColorSpace";
char *__ATOM_Image = "Image";
char *__ATOM_XObject = "XObject";
char *__ATOM_Title = "Title";
char *__ATOM_Subject = "Subject";
char *__ATOM_Author = "Author";
char *__ATOM_Keywords = "Keywords";
char *__ATOM_Creator = "Creator";
char *__ATOM_Producer = "Producer";
char *__ATOM_None = "None";
char *__ATOM_FlateDecode = "FlateDecode";
char *__ATOM_CCITTFaxDecode = "CCITTFaxDecode";
char *__ATOM_DCTDecode = "DCTDecode";
char *__ATOM_JBIG2Decode = "JBIG2Decode";
char *__ATOM_JPXDecode = "JPXDecode";
char *__ATOM_K = "K";
char *__ATOM_Columns = "Columns";
char *__ATOM_Rows = "Rows";
char *__ATOM_BlackIs1 = "BlackIs1";
char *__ATOM_DeviceGray = "DeviceGray";
char *__ATOM_DeviceRGB = "DeviceRGB";
char *__ATOM_DeviceCMYK = "DeviceCMYK";
char *__ATOM_Indexed = "Indexed";
char *__ATOM_ICCBased = "ICCBased";
char *__ATOM_PieceInfo = "PieceInfo";
char *__ATOM_LastModified = "LastModified";
char *__ATOM_Private = "Private";
char *__ATOM_PDFRaster = "PDFRaster";
char *__ATOM_PhysicalPageNumber = "PhysicalPageNumber";
char *__ATOM_FrontSide = "FrontSide";
char *__ATOM_CreationDate = "CreationDate";
char *__ATOM_ModDate = "ModDate";
char *__ATOM_Metadata = "Metadata";
char *__ATOM_XML = "XML";
char *__ATOM_CalGray = "CalGray";
char *__ATOM_BlackPoint = "BlackPoint";
char *__ATOM_WhitePoint = "WhitePoint";
char *__ATOM_Gamma = "Gamma";
char *__ATOM_N = "N";
char *__ATOM_ASCIIHexDecode = "ASCIIHexDecode";
char* __ATOM_CalRGB = "CalRGB";
char* __ATOM_Matrix = "Matrix";


const char *pd_atom_name(t_pdatom atom)
{
	return (const char*)atom;
}

extern t_pdatomtable* pd_atom_table_new(t_pdmempool* pool, int initialCap)
{
	t_pdatomtable* table = (t_pdatomtable*)pd_alloc(pool, sizeof(t_pdatomtable));
	if (table) {
		table->elements = 0;
		table->buckets = (t_pdatom*)pd_alloc(pool, initialCap * sizeof(table->buckets[0]));
		if (table->buckets) {
			table->capacity = initialCap;
			return table;
		}
		pd_free(table); table = NULL;
	}
	return table;
}

extern void pd_atom_table_free(t_pdatomtable* atoms)
{
	if (atoms) {
		unsigned i;
		for (i = 0; i < atoms->elements; i++) {
			pd_free(atoms->buckets[i]);
		}
		pd_free(atoms->buckets);
		pd_free(atoms);
	}
}

int pd_atom_table_count(t_pdatomtable* atoms)
{
	return atoms ? atoms->elements : 0;
}

// Search atomtable for atom with given name.
// Returns the bucket index of the matching entry if found, otherwise
static int search_atom_table(t_pdatomtable *atoms, const char* name)
{
	int i;
	for (i = 0; i < (int)atoms->elements; i++) {
		if (0 == pd_strcmp(pd_atom_name(atoms->buckets[i]), name)) {
			return i;
		}
	}
	return -1;
}

static pdbool expand_atom_table(t_pdatomtable* atoms)
{
	pduint32 newCap = atoms->capacity * 2;
	t_pdatom* newBuckets = (t_pdatom*)pd_alloc_same_pool(atoms, newCap * sizeof(atoms->buckets[0]));
	if (!newBuckets) {
		return PD_FALSE;
	}
	memcpy(newBuckets, atoms->buckets, atoms->elements * sizeof(atoms->buckets[0]));
	pd_free(atoms->buckets);
	atoms->buckets = newBuckets;
	atoms->capacity = newCap;
	return PD_TRUE;
}

t_pdatom pd_atom_intern(t_pdatomtable* atoms, const char* name)
{
	int index = search_atom_table(atoms, name);
	if (index < 0) {
		// not found, add to table
		if (atoms->elements == atoms->capacity) {
			// table is full, (try to) expand it
			if (!expand_atom_table(atoms)) {
				// Failed. What can we do?
				// Maybe return an error atom?
				return (t_pdatom)NULL;
			}
		}
		assert(atoms->elements < atoms->capacity);
		index = atoms->elements++;
		atoms->buckets[index] = pd_strdup(pd_get_pool(atoms), name);
	}
	return atoms->buckets[index];
}
