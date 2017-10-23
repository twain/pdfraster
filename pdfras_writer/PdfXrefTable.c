#include "PdfXrefTable.h"
#include "PdfString.h"

struct t_pdreference {
	pdint16 isWritten;
	pdint16 objectNumber;
	pduint32 pos;
	t_pdvalue value;
};

pduint32 pd_reference_object_number(t_pdvalue ref)
{
	if (IS_REFERENCE(ref)) {
		return ref.value.refvalue->objectNumber;
	}
	else {
		return 0;
	}
}

pdbool pd_reference_is_written(t_pdvalue ref)
{
	if (IS_REFERENCE(ref)) {
		return ref.value.refvalue->isWritten ? PD_TRUE : PD_FALSE;
	}
	else {
		// internal error
		return PD_FALSE;
	}
}

void pd_reference_mark_written(t_pdvalue ref)
{
	if (IS_REFERENCE(ref)) {
		ref.value.refvalue->isWritten = 1;
	}
	else {
		// internal error
	}
}

t_pdvalue pd_reference_get_value(t_pdvalue ref)
{
	if (IS_REFERENCE(ref)) {
		return ref.value.refvalue->value;
	}
	else {
		// fail
		return pderrvalue();
	}
}

void pd_reference_resolve(t_pdvalue ref, t_pdvalue value)
{
	if (IS_REFERENCE(ref)) {
		t_pdreference *pr = ref.value.refvalue;
		if (pr && IS_NULL(pr->value)) {
			pr->value = value;
		}
		else {
			// internal error - resolving something that is
			// not an unresolved indirect object.
		}
	}
	else {
		return; /* TODO FAIL */
	}
}

pduint32 pd_reference_get_position(t_pdvalue ref)
{
	if (IS_REFERENCE(ref)) {
		return ref.value.refvalue->pos;
	}
	else {
		return 0; /* TODO FAIL */
	}
}

void pd_reference_set_position(t_pdvalue ref, pduint32 pos)
{
	if (IS_REFERENCE(ref)) {
		ref.value.refvalue->pos = pos;
	}
	else {
		// fail
	}
}

typedef struct t_xr {
	t_pdreference *reference;
	struct t_xr *next;
} t_xr;

struct t_pdxref
{
	pduint32 nextObjectNumber;
	t_xr *first, *last;
};

t_pdxref *pd_xref_new(t_pdmempool *alloc)
{
	t_pdxref *xref = (t_pdxref *)pd_alloc(alloc, sizeof(t_pdxref));
	if (xref) {
		xref->nextObjectNumber = 1;
	}
	return xref;
}

void pd_xref_free(t_pdxref *xref)
{
	t_xr *walker, *next;
	if (!xref) return;
	walker = xref->first;
	while (walker)
	{
		next = walker->next;
		if (walker->reference) {
			pd_free(walker->reference);
		}
		pd_free(walker);
		walker = next;
	}
	pd_free(xref);
}

// Return PD_TRUE if the reference refers to the value, otherwise PD_FALSE.
// Dictionaries & Arrays match iff they refer to the same dict or array object.
// Other types of values NEVER MATCH! 
static pdbool __pd_reference_match(t_pdreference *ref, t_pdvalue value)
{
	if (ref->value.pdtype == value.pdtype) {
		switch (value.pdtype)
		{
		case TPDDICT: return value.value.dictvalue == ref->value.value.dictvalue;
		case TPDARRAY: return value.value.arrvalue == ref->value.value.arrvalue;
		case TPDSTRING: return pd_string_equal(value.value.stringvalue, ref->value.value.stringvalue);
		// these never match - we could(?) modify their value after putting into the XREF table!
		case TPDNULL:
		case TPDNAME: 
		case TPDBOOL: 
		case TPDNUMBERINT:
		case TPDNUMBERFLOAT:
		// these never match. They are used to mark forward references to unknown values:
		case TPDERRVALUE:
			// these never match and in any case should never appear in xref table:
		case TPDREFERENCE:
		default: break;
		}
	}
	return PD_FALSE;
}

// Look for a value in an XREF table.
// Returns a pointer to the XREF entry, if found, otherwise NULL.
// Uses match to decide if any existing entry matches the value.
static t_xr *findmatch(t_pdxref *xref, t_pdvalue value)
{
	t_xr *walker;
	for (walker = xref->first; walker; walker = walker->next)
	{
		if (__pd_reference_match(walker->reference, value)) {
			return walker;
		}
	}
	return 0;
}

// Add a new indirect object into an XREF table and return the xref entry.
static t_xr *add_reference(t_pdxref *xref, t_pdvalue value)
{
	if (xref) {
		// create XREF table entry
		t_xr *xr = (t_xr *)pd_alloc_same_pool(xref, sizeof(t_xr));
		if (xr) {
			// create reference object
			xr->reference = (t_pdreference *)pd_alloc_same_pool(xref, sizeof(t_pdreference));
			if (xr->reference) {
				// referenced value:
				xr->reference->value = value;
				// indirect object number
				xr->reference->objectNumber = (pdint16)(xref->nextObjectNumber++);
				// append to XREF table 
				if (!xref->first) {
					xref->first = xref->last = xr;
				}
				else {
					xref->last->next = xr;
					xref->last = xr;
				}
				return xr;
			}
			pd_free(xr);
		}
	}
	return NULL;
}

t_pdvalue pd_xref_create_forward_reference(t_pdxref *xref)
{
	if (xref) {
		t_xr *xr = add_reference(xref, pdnullvalue());
		if (xr) {
			t_pdvalue ref = { TPDREFERENCE, { 0 } };
			ref.value.refvalue = xr->reference;
			return ref;
		}
	}
	return pdnullvalue();
}

t_pdvalue pd_xref_makereference(t_pdxref *xref, t_pdvalue value)
{
	if (IS_REFERENCE(value)) {
		// we don't need no stinkin' XREF table.
		return value;
	}
	if (xref) {
		// Is it in the XREF table already?
		// (technically, is there a matching entry in the table already?)
		t_xr *xr = findmatch(xref, value);
		if (!xr) {
			// No reference to this value, create a reference
			xr = add_reference(xref, value);
		}
		if (xr) {
			t_pdvalue ref = { TPDREFERENCE, { 0 } };
			ref.value.refvalue = xr->reference;
			return ref;
		}
	}
	return pdnullvalue();
}

static int xref_size(t_pdxref *xref)
{
	int i = 0;
	if (xref) {
		t_xr *walker;
		for (walker = xref->first; walker; walker = walker->next)
		{
			i++;
		}
	}
	return i;
}

static void write_entry(t_pdoutstream *os, pduint32 pos, char *gen, char status)
{
	char s[12];
	pditoa((pdint32)pos, s);
	int len = pdstrlen(s);
	int i;

	for (i = 0; i < 10 - len; i++)
		pd_putc(os, '0');
	pd_putn(os, s, 0, len);
	pd_putc(os, ' ');
	pd_puts(os, gen);
	pd_putc(os, ' ');
	pd_putc(os, status);
	pd_putc(os, 13);
	pd_putc(os, 10);
}

void pd_xref_writeallpendingreferences(t_pdxref *xref, t_pdoutstream *os)
{
	if (xref && os) {
		t_xr *walker;
		for (walker = xref->first; walker; walker = walker->next)
		{
			t_pdvalue ref = { TPDREFERENCE, { 0 } };
			ref.value.refvalue = walker->reference;
			pd_write_reference_declaration(os, ref);
		}
	}
}

void pd_xref_writetable(t_pdxref *xref, t_pdoutstream *stm)
{
	if (xref && stm) {
		int size = xref_size(xref);
		t_xr *walker;
		pd_puts(stm, "xref\n");
		pd_putint(stm, 0);
		pd_putc(stm, ' ');
		pd_putint(stm, size + 1);
		pd_putc(stm, '\n');
		write_entry(stm, 0, "65535", 'f');
		for (walker = xref->first; walker; walker = walker->next)
		{
			write_entry(stm, walker->reference->pos, "00000", 'n');
		}
	}
}

pdint32 pd_xref_size(t_pdxref *xref)
{
	return xref ? (pdint32)xref_size(xref) : 0;
}


