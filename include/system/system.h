#ifndef TRANSPILE_SYSTEM_H
#define TRANSPILE_SYSTEM_H
#include <stdlib.h>
#include <sys/types.h>

#include "system/endianness.h"

/* system descriptions */

/* system abstraction */
struct system {
  enum endianness endianness;
  size_t ptrlen;
};

#endif

