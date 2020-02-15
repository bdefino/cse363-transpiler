#ifndef TRANSPILER_SYSTEM_FRAME_H
#define TRANSPILER_SYSTEM_FRAME_H
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "system/system.h"

/* stack frames */

/* stack frame abstraction */
struct frame {
  /*
  pointers (in native endianness):
  lengths are retrieved via a `struct system`
  */

  char *base;
  char *canary; /* optional */
  char *retaddr;
};

/* dump a frame to a file based on a system's constraints */
int frame_dump(const struct frame *frame, const int fd,
  const struct system *system);

/* load a frame from a file based on a system's constraints */
int frame_load(const struct frame *dest, const int fd,
  const struct system *system);

#endif

