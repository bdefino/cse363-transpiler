#ifndef TRANSPILER_ISET_IA_32_H
#define TRANSPILER_ISET_IA_32_H
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "iset/iset.h"

/* IA-32 instruction set */

/* IA-32 instruction set */
struct ia_32_iset {
  struct iset super;
};

int ia_32_iset_init(struct ia_32_iset *dest);

/* read the next instruction from a file */
int ia_32_iset_read(struct ia_32_iset *iset, struct instruction *dest,
  const int fd);

/* write the next instruction to a file */
int ia_32_iset_write(struct ia_32_iset *iset,
  const struct instruction *instruction, const int fd);

#endif

