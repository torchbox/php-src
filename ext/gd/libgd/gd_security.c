/*
   * gd_security.c
   *
   * Implements buffer overflow check routines.
   *
   * Written 2004, Phil Knirsch.
   * Based on netpbm fixes by Alan Cox.
   *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#if HAVE_GD_BUNDLED
# include "gd.h"
#else
# include <gd.h>
#endif

#if !HAVE_GD_BUNDLED
#include "php.h"
static void php_gd_error(const char *format, ...) {
	va_list args;

	TSRMLS_FETCH();

	va_start(args, format);
	php_verror(NULL, "", E_WARNING, format, args TSRMLS_CC);
	va_end(args);
}
#endif

int overflow2(int a, int b)
{
	if(a <= 0 || b <= 0) {
		php_gd_error("gd warning: one parameter to a memory allocation multiplication is negative or zero, failing operation gracefully\n");
		return 1;
	}
	if(a > INT_MAX / b) {
		php_gd_error("gd warning: product of memory allocation multiplication would exceed INT_MAX, failing operation gracefully\n");
		return 1;
	}
	return 0;
}
