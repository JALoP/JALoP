/*
 * @file jal_asprintf.c
 * Defines the jal_asprintf function and jal_vasprintf functions
 *
 * Copyright (c) 2004 Darren Tucker.
 *
 * Based originally on asprintf.c from OpenBSD:
 * Copyright (c) 1997 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <stdarg.h>
#include <jalop/jal_status.h>

#include "jal_alloc.h"
#include "jal_asprintf_internal.h"
#include "jal_error_callback_internal.h"

#ifndef VA_COPY
#ifdef HAVE_VA_COPY
#define VA_COPY(dest, src) va_copy(dest, src)
#else
#ifdef HAVE___VA_COPY
#define VA_COPY(dest, src) __va_copy(dest, src)
#else
#define VA_COPY(dest, src) (dest) = (src)
#endif
#endif
#endif

#define INIT_SZ	128

int jal_vasprintf(char **str, const char *fmt, va_list ap)
{
	int ret = -1;
	va_list ap2;
	char *string, *newstr;
	size_t len;

	va_copy(ap2, ap);
	string = jal_malloc(INIT_SZ);

	ret = vsnprintf(string, INIT_SZ, fmt, ap2);
	if (ret >= 0 && ret < INIT_SZ) {	/* succeeded with initial alloc */
		*str = string;
	} else if (ret == INT_MAX) {	/* shouldn't happen */
		free(string);
		goto fail;
	} else {		/* bigger than initial, realloc allowing for nul */
		len = (size_t) ret + 1;
		newstr = jal_realloc(string, len);
		va_end(ap2);
		VA_COPY(ap2, ap);
		ret = vsnprintf(newstr, len, fmt, ap2);
		if (ret >= 0 && (size_t) ret < len) {
			*str = newstr;
		} else {	/* failed with realloc'ed string, give up */
			free(newstr);
			goto fail;
		}
	}
	va_end(ap2);
	return ret;

fail:
	*str = NULL;
	va_end(ap2);
	jal_error_handler(JAL_E_NO_MEM);
	return -1;
}

int jal_asprintf(char **str, const char *fmt, ...)
{
	va_list ap;
	int ret;

	*str = NULL;
	va_start(ap, fmt);
	ret = jal_vasprintf(str, fmt, ap);
	va_end(ap);

	return ret;
}
