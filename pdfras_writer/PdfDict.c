#include "PdfDict.h"
#include "PdfHash.h"
#include "PdfValues.h"
#include "PdfAtoms.h"
#include "PdfDatasink.h"
#include "PdfXrefTable.h"
#include "PdfStandardAtoms.h"

// pseudo-inherits from hash table
struct t_pddict
{
	t_pdhashatomtovalue *elems;
	pdbool isStream;
};

// pseudo-inherits from t_pddict
typedef struct t_pdstream
{
	t_pddict dict; /* must be first */
	t_datasink *sink;
	f_on_datasink_ready contentWriter;
	void *contentCookie;
} t_pdstream;



t_pdvalue pd_dict_new(t_pdmempool *allocsys, pdint32 initialsize)
{
	// create the atom->value hashmap underlying the dictionary:
	t_pdhashatomtovalue *hash = pd_hashatomtovalue_new(allocsys, initialsize);
	if (hash) {
		t_pddict *dict = (t_pddict *)pd_alloc(allocsys, sizeof(t_pddict));
		if (dict) {
			dict->elems = hash;
			dict->isStream = PD_FALSE;
			{
				t_pdvalue dictvalue = { TPDDICT, { 0 } };
				dictvalue.value.dictvalue = dict;
				return dictvalue;
			}
		}
		pd_hashatomtovalue_free(hash);
	}
	return pdnullvalue();
}

extern void pd_dict_free(t_pdvalue dict)
{
	if (IS_DICT(dict)) {
		if (dict.value.dictvalue) {
			/* this does not free the elements individually.
			 * yes, this will leak memory.
			 * no, this won't ultimately be an issue.
			 * the object may be referenced in multiple places so
			 * this is not our job.
			 */
			// Free the associated hash map:
			pd_hashatomtovalue_free(dict.value.dictvalue->elems);
			// Free the dictionary object:
			pd_free(dict.value.dictvalue);
			// pretty sure this is pointless:
			dict.value.dictvalue = 0;
		}
	}
}

t_pdvalue pd_dict_get(t_pdvalue dict, t_pdatom key, pdbool *success)
{
	DEREFERENCE(dict);
	if (!IS_DICT(dict) || !dict.value.dictvalue) { *success = PD_FALSE; return pdnullvalue(); }
	return pd_hashatomtovalue_get(dict.value.dictvalue->elems, key, success);
}

pdbool pd_dict_contains(t_pdvalue dict, t_pdatom key)
{
	pdbool success = PD_FALSE;
	pd_dict_get(dict, key, &success);
	return success;
}

t_pdvalue pd_dict_put(t_pdvalue dict, t_pdatom key, t_pdvalue value)
{
	DEREFERENCE(dict);
	if (!IS_DICT(dict) || !dict.value.dictvalue) return pderrvalue();
	pd_hashatomtovalue_put(dict.value.dictvalue->elems, key, value);
	return dict;
}

pdbool pd_dict_is_stream(t_pdvalue dict)
{
	DEREFERENCE(dict);
	if (!IS_DICT(dict)) return PD_FALSE;
	return dict.value.dictvalue->isStream;
}

// 
static t_pdstream* pd_dict_as_stream(t_pdvalue dict)
{
	DEREFERENCE(dict);
	if (IS_STREAM(dict)) {
		return (t_pdstream *)(dict.value.dictvalue);
	}
	return NULL;
}

int pd_dict_count(t_pdvalue dict)
{
	DEREFERENCE(dict);
	if (!IS_DICT(dict)) return 0;
	return pd_hashatomtovalue_count(dict.value.dictvalue->elems);
}

int __pd_dict_capacity(t_pdvalue dict)
{
	DEREFERENCE(dict);
	if (!IS_DICT(dict)) return 0;
	return __pd_hashatomtovalue_capacity(dict.value.dictvalue->elems);
}

void pd_dict_foreach(t_pdvalue dict, f_pdhashatomtovalue_iterator iter, void *cookie)
{
	DEREFERENCE(dict);
	if (!IS_DICT(dict) || !dict.value.dictvalue) return;
	pd_hashatomtovalue_foreach(dict.value.dictvalue->elems, iter, cookie);
}

///////////////////////////////////////////////////////////////////////
// Streams (acts like a derived class of Dictionary)

t_pdvalue stream_new(t_pdmempool *pool, t_pdxref *xref, pdint32 initialsize, f_on_datasink_ready ready, void *eventcookie)
{
	// Allocate the hash map that stores the dictionary entries of the Stream
	t_pdhashatomtovalue *hash = pd_hashatomtovalue_new(pool, initialsize);
	if (hash) {
		// Allocate the Stream object, which is a 'derived class' of a t_pddict
		t_pdstream *stream = (t_pdstream *)pd_alloc(pool, sizeof(t_pdstream));
		if (stream) {
			t_pdvalue dictvalue = { TPDDICT, { 0 } };
			dictvalue.value.dictvalue = &stream->dict;
			// plug in the dictionary hash table
			stream->dict.elems = hash;
			// mark this as a Stream as well as a Dictionary:
			stream->dict.isStream = PD_TRUE;
			// attach the deferred content writer
			stream->contentWriter = ready;
			stream->contentCookie = eventcookie;
			// Create & return an indirect reference to this Stream
			return pd_xref_makereference(xref, dictvalue);
		}
		// oops, stream creation failed, clean up.
		pd_hashatomtovalue_free(hash);
	}
	// failed.
	return pdnullvalue();
}

void stream_free(t_pdvalue stream)
{
	DEREFERENCE(stream);
	// is it a stream?
	t_pdstream *stmp = pd_dict_as_stream(stream);
	if (stmp) {
		// it is a stream...
		// free the associated sink if any
		pd_datasink_free(stmp->sink);			// harmless if null
		// it's a stream so it's also a dict
		pd_dict_free(stream);
	}
}

void stream_write_data(t_pdvalue stream, t_datasink* sink)
{
	t_pdstream *stm = pd_dict_as_stream(stream);
	if (stm && stm->contentWriter && sink) {
		// Call the Stream's content generator to write its contents
		// to the sink (which presumably writes it to the outstream):
		stm->contentWriter(sink, stm->contentCookie);
	}
}

