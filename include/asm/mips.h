#ifndef TRANSPILER_ASM_MIPS_H
#define TRANSPILER_ASM_MIPS_H
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "asm/iset.h"
#include "io.h"

/* MIPS instruction set */

/* MIPS instruction set */
struct mips_iset {
	struct iset super;
};

int
mips_iset_init(struct mips_iset *dest);

/* read the next instruction from a file */
int
mips_iset_read(struct mips_iset *iset, struct instruction *dest, const int fd);

/* write the next instruction to a file */
int
mips_iset_write(struct mips_iset *iset, const struct instruction *instruction,
	const int fd);

#endif

