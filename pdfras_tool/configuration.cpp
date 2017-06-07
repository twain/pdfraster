// pdfras_tool  configuration.cpp

#include <iostream>

#include <pdfrasread.h>

#include "error.h"
#include "journal.h"
#include "configuration.h"

configuration::configuration() {
	page = 1;
}

bool configuration::is_valid() {
	LOG(dbg, "> page = %d", page);
	LOG(dbg, "| test_pdfr=%s print_details=%s extract_image=%s", B2PC(op.get_test_pdfr()), B2PC(op.get_print_details()), B2PC(op.get_extract_image()));

	bool rv = true;

	if (page < 1) {
		LOG(err, "| page number (%d) is less than 1", page);
		rv = false;
	}

	if (op.get_nop()) {
		LOG(err, "| configuration operatrion is NOP");
		rv = false;
	}

	LOG(dbg, "<");
	return rv;
}