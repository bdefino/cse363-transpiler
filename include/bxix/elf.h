#ifndef TRANSPILER_BXIX_ELF_H
#define TRANSPILER_BXIX_ELF_H
#include <elf.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "bxix/bxix.h"

/* ELF binary executable instruction examiner */

extern const struct bxix bxix_elf;

/* contextualize the examiner with a file */
int
bxix_elf_examine(struct bxix *bxix, const int fd);

/* read the next instruction */
int
bxix_elf_read_instruction(struct bxix *bxix, struct iset *iset,
	struct instruction *dest);

#endif

