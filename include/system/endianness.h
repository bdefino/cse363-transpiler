#ifndef TRANSPILER_SYSTEM_ENDIANNESS_H
#define TRANSPILER_SYSTEM_ENDIANNESS_H
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>

/* endianness */

#undef ENDIANNESS_BIG
#undef ENDIANNESS_LITTLE

#define ENDIANNESS_BIG (~0x0)
#define ENDIANNESS_LITTLE 0x0

/* determine the native endianness */
int
endianness_native(int *dest);

/* toggle endianness of an array */
int
endianness_toggle(char *a, size_t len);

#endif

