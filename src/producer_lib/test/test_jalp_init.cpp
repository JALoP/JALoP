#include <jalop/jalp_context.h>

// test-dept doesn't play nice with c++ unless __STRICT_ANSI__ is defined
#ifndef __STRICT_ANSI__
#define __STRICT_ANSI__
#endif
#include <test-dept.h>

extern "C" void test_jalp_init_and_shutdown() {
	enum jal_status r = jalp_init();
	assert_equals(JAL_OK, r);
	jalp_shutdown();
}
