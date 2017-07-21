#include "PdfValues.h"
#include "PdfString.h"
#include "PdfStrings.h"
#include "PdfDict.h"
#include "PdfArray.h"

const t_pdvalue __pdnull = { TPDNULL, { 0 } };
const t_pdvalue __pderr = { TPDERRVALUE, { 0 } };

t_pdvalue pdatomvalue(t_pdatom v)
{
	t_pdvalue val = { TPDNAME, { 0 } };
	val.value.namevalue = v;
	return val;
}

t_pdvalue pderrvalue()
{
	return __pderr;
}

t_pdvalue pdnullvalue()
{
	return __pdnull;
}

t_pdvalue pdintvalue(pdint32 v)
{
	t_pdvalue val = { TPDNUMBERINT, { 0 } };
	val.value.intvalue = v;
	return val;
}

t_pdvalue pdfloatvalue(double v)
{
	t_pdvalue val = { TPDNUMBERFLOAT, { 0 } };
	val.value.floatvalue = v;
	return val;
}

t_pdvalue pdboolvalue(pdbool v)
{
	t_pdvalue val = { TPDBOOL, { 0 } };
	val.value.boolvalue = v;
	return val;
}

t_pdvalue pdarrayvalue(t_pdarray *arr)
{
	t_pdvalue val = { TPDARRAY, { 0 } };
	val.value.arrvalue = arr;
	return val;
}

t_pdvalue pdstringvalue(t_pdstring *str)
{
	t_pdvalue val = { TPDSTRING, { 0 } };
	val.value.stringvalue = str;
	return val;
}

t_pdvalue pdcstrvalue(t_pdmempool *alloc, const char *s)
{
	t_pdstring *str = pd_string_new(alloc, pdstrlen(s), s);
	return str ? pdstringvalue(str) : pderrvalue();
}

int pd_value_eq(t_pdvalue a, t_pdvalue b)
{
	if (a.pdtype == b.pdtype) {
		switch (a.pdtype) {
		case TPDARRAY:
			return a.value.arrvalue == b.value.arrvalue;
		case TPDBOOL:
			return a.value.boolvalue == b.value.boolvalue;
		case TPDDICT:
			return a.value.dictvalue == b.value.dictvalue;
		case TPDNULL:				// all null values are EQ
		case TPDERRVALUE:			// all error values are EQ
			return 1;
		case TPDNAME:
			// why does this work? Because names (atoms) are
			// supposed to be uniquified: EQ iff EQUAL.
			return a.value.namevalue == b.value.namevalue;
		case TPDNUMBERFLOAT:
			return a.value.floatvalue == b.value.floatvalue;
		case TPDNUMBERINT:
			return a.value.intvalue == b.value.intvalue;
		case TPDREFERENCE:
			return a.value.refvalue == b.value.refvalue;
		case TPDSTRING:
			return pd_string_equal(a.value.stringvalue, b.value.stringvalue);
		}
	}
	// different types are presumed not-eq
	// so for example int(0) != float(0.0)
	return 0;
}

void pd_value_free(t_pdvalue *v)
{
	if (v) {
		switch (v->pdtype) {
		case TPDDICT:
			pd_dict_free(*v);
			break;
		case TPDARRAY:
			pd_array_free(v->value.arrvalue);
			break;
		case TPDSTRING:
			pd_string_free(v->value.stringvalue);
			break;
		default:
			break;
		}
		*v = pdnullvalue();
	}
}