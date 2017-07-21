#include "PdfContentsGenerator.h"
#include "PdfDatasink.h"
#include "PdfStreaming.h"

struct t_pdcontents_gen {
	f_gen gen;
	void *gencookie;
	t_datasink *sink;
	t_pdoutstream *os;
};

static int gen_write_out(const pduint8 *data, pduint32 offset, pduint32 length, void *cookie)
{
	t_pdcontents_gen *generator = (t_pdcontents_gen *)cookie;
	pd_datasink_put(generator->sink, data, offset, length);
	return length;
}

t_pdcontents_gen *pd_contents_gen_new(t_pdmempool *alloc, f_gen gen, void *gencookie)
{
	t_OS opsys;
	t_pdcontents_gen *generator = (t_pdcontents_gen *)pd_alloc(alloc, sizeof(t_pdcontents_gen));
	if (!generator)
		return 0;
	generator->gen = gen;
	generator->gencookie = gencookie;
	opsys.writeout = gen_write_out;
	opsys.writeoutcookie = generator;
	generator->os = pd_outstream_new(alloc, &opsys);
	return generator;
}

void pd_contents_gen_free(t_pdcontents_gen *gen)
{
	if (!gen) return;
	pd_outstream_free(gen->os);
	pd_free(gen);
}

void pd_contents_generate(t_datasink *sink, void *gencookie)
{
	t_pdcontents_gen *gen = (t_pdcontents_gen *)gencookie;
	// plug in the sink
	gen->sink = sink;
	// invoke the content-generating function
	gen->gen(gen, gen->gencookie);
}

void pd_gen_moveto(t_pdcontents_gen *gen, pddouble x, pddouble y)
{
	pd_putc(gen->os, ' ');
	pd_putfloat(gen->os, x);
	pd_putc(gen->os, ' ');
	pd_putfloat(gen->os, y);
	pd_puts(gen->os, " m");
}

void pd_gen_lineto(t_pdcontents_gen *gen, pddouble x, pddouble y)
{
	pd_putc(gen->os, ' ');
	pd_putfloat(gen->os, x);
	pd_putc(gen->os, ' ');
	pd_putfloat(gen->os, y);
	pd_puts(gen->os, " l");
}

void pd_gen_closepath(t_pdcontents_gen *gen)
{
	pd_puts(gen->os, " h");
}

void pd_gen_stroke(t_pdcontents_gen *gen)
{
	pd_puts(gen->os, " S");
}

void pd_gen_fill(t_pdcontents_gen *gen, pdbool evenodd)
{
	pd_puts(gen->os, evenodd ? " f*" : " f");
}

void pd_gen_gsave(t_pdcontents_gen *gen)
{
	pd_puts(gen->os, " q");
}

void pd_gen_grestore(t_pdcontents_gen *gen)
{
	pd_puts(gen->os, " Q");
}

void pd_gen_concatmatrix(t_pdcontents_gen *gen, pddouble a, pddouble b, pddouble c, pddouble d, pddouble e, pddouble f)
{
	pd_putc(gen->os, ' ');
	pd_putfloat(gen->os, a);
	pd_putc(gen->os, ' ');
	pd_putfloat(gen->os, b);
	pd_putc(gen->os, ' ');
	pd_putfloat(gen->os, c);
	pd_putc(gen->os, ' ');
	pd_putfloat(gen->os, d);
	pd_putc(gen->os, ' ');
	pd_putfloat(gen->os, e);
	pd_putc(gen->os, ' ');
	pd_putfloat(gen->os, f);
	pd_puts(gen->os, " cm");
}

void pd_gen_xobject(t_pdcontents_gen *gen, t_pdatom xobjectatom)
{
	pd_putc(gen->os, ' ');
	pd_write_value(gen->os, pdatomvalue(xobjectatom));
	pd_puts(gen->os, " Do");
}
