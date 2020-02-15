#ifndef TRANSPILER_SYSTEM_ENDIANNESS_H
#define TRANSPILER_SYSTEM_ENDIANNESS_H
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>

/* endianness */

/* endiannesses */
enum endianness {
  ENDIANNESS_BIG,
  ENDIANNESS_LITTLE
};

/* determine the native endianness */
int endianness_native(enum endianness *dest);

/* toggle endianness of an array */
int endianness_toggle(char *a, size_t len);

#endif

