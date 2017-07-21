#include "PdfHash.h"
#include "PdfStandardAtoms.h"
#include "PdfStrings.h"

#define kSomeReasonableInitialSize 10

typedef struct {
	t_pdvalue value;
	t_pdatom key;
} t_bucket;

struct t_pdhashatomtovalue {
	// number of elements this table can currently hold
	pduint32 capacity;
	// number of elements currently stored in this table
	pduint32 elements;
	// array of capacity (key,value) pairs. Unused entries have key=PDA_UNDEFINED_ATOM
	t_bucket *buckets;
};


// Initialize hash table to have capacity for size entries
static void init_table(t_pdhashatomtovalue *hash, pduint32 size)
{
	hash->buckets = (t_bucket*)pd_alloc_same_pool(hash, sizeof(t_bucket) * size);
	if (hash->buckets) {
		pduint32 i;
		hash->capacity = size;
		hash->elements = 0;
		for (i = 0; i < size; i++)
		{
			hash->buckets[i].key = PDA_UNDEFINED_ATOM;
			hash->buckets[i].value.value.intvalue = 0;
		}
	}
}


t_pdhashatomtovalue *pd_hashatomtovalue_new(t_pdmempool *pool, pduint32 initialCap)
{
	t_pdhashatomtovalue *hash = NULL;
	if (pool) {
		hash = (t_pdhashatomtovalue*)pd_alloc(pool, sizeof(t_pdhashatomtovalue));
		if (hash) {
			hash->elements = 0;
			init_table(hash, initialCap == 0 ? kSomeReasonableInitialSize : initialCap);
		}
	}
	return hash;
}

void pd_hashatomtovalue_free(t_pdhashatomtovalue *table)
{
	if (table) {
		pd_free(table->buckets);
		pd_free(table);
	}
}

int pd_hashatomtovalue_count(t_pdhashatomtovalue *table)
{
	if (table) {
		return table->elements;
	}
	return 0;
}

int __pd_hashatomtovalue_capacity(t_pdhashatomtovalue *table)
{
	if (table) {
		return table->capacity;
	}
	return 0;
}

// Search hashtable for entry with key and return bucket index.
// Keys are compared using '==', so they must be identical (same address) not just string-equal.
// Returns the bucket index of the matching entry if found, otherwise
// returns the bucket index where that key should be inserted.
// Because hashtables are expanded before they fill up, there is always a
// valid index for insertion.
static pdint32 hash(t_pdhashatomtovalue *table, t_pdatom key)
{
	pduint32 count;
	// cast below is for 64-bit
	// seems dangerous use of void * (t_pdatom) below
	pdint32 i = (size_t)key % table->capacity;
	for (count = 0; count < table->capacity; count++)
	{
		if (table->buckets[i].key == key) {
			return i;								// match, return index of existing table entry
		}
		if (table->buckets[i].key == PDA_UNDEFINED_ATOM)
		{
			return i;								// no match, return next unused entry in table
		}
		i = (i + 1) % table->capacity;
	}
	return i; // won't happen
}

static void rehash_table(t_bucket *buckets, int n, t_pdhashatomtovalue *table)
{
	while (n-- > 0)
	{
		if (buckets->key != PDA_UNDEFINED_ATOM)
			pd_hashatomtovalue_put(table, buckets->key, buckets->value);
		buckets++;
	}
}

void pd_hashatomtovalue_put(t_pdhashatomtovalue *table, t_pdatom key, t_pdvalue value)
{
	if (table && key != PDA_UNDEFINED_ATOM) {
		// Look up key in table.
		// NB Returns the correct free index, if key is new 
		int index = hash(table, key);
		// If we're adding a new entry and the table is too full...
		if (table->buckets[index].key != key && table->elements > (table->capacity * 3) / 4)
		{
			// Enlarge the table to keep it from filling up.
			//
			int oldlimit = table->capacity;
			t_bucket *oldbuckets = table->buckets;
			// resize the table:
			init_table(table, (oldlimit * 5) / 2); /* reasonable ? */
			// rehash the entries modulo the new size
			rehash_table(oldbuckets, oldlimit, table);
			pd_free(oldbuckets);
			// try again (tail recursion!)
			pd_hashatomtovalue_put(table, key, value);
		}
		else {
			if (table->buckets[index].key == PDA_UNDEFINED_ATOM) {
				// new active entry
				table->elements++;
			}
			// set, or replace, (key,value) pair:
			table->buckets[index].key = key;
			table->buckets[index].value = value;
		}
	}
}

t_pdvalue pd_hashatomtovalue_get(t_pdhashatomtovalue *table, t_pdatom key, pdbool *success)
{
	int index;
	if (!table) return pderrvalue();
	if (key == PDA_UNDEFINED_ATOM) {
		*success = 0;
		return pderrvalue();
	}

	index = hash(table, key);
	*success = table->buckets[index].key == key;
	return (*success) ? table->buckets[index].value : pderrvalue();
}

pdbool pd_hashatomtovalue_contains(t_pdhashatomtovalue *table, t_pdatom key)
{
	pdbool success = PD_FALSE;
	pd_hashatomtovalue_get(table, key, &success);
	return success;
}

void pd_hashatomtovalue_foreach(t_pdhashatomtovalue *table, f_pdhashatomtovalue_iterator iter, void *cookie)
{
	if (table && iter) {
		pduint32 i;
		for (i = 0; i < table->capacity; i++)
		{
			if (table->buckets[i].key != PDA_UNDEFINED_ATOM)
			{
				if (!iter(table->buckets[i].key, table->buckets[i].value, cookie))
					break;
			}
		}
	}
}
