#ifndef TRANSPILER_ASM_X86_64_H
#define TRANSPILER_ASM_X86_64_H
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "asm/iset.h"

/* x86-64 instruction set */

/* x86-64 instruction set */
struct x86_64_iset {
	struct iset super;
};

int
x86_64_iset_init(struct x86_64_iset *dest);

/* read the next instruction from a file */
int
x86_64_iset_read(struct x86_64_iset *iset, struct instruction *dest,
	const int fd);

/* write the next instruction to a file */
int
x86_64_iset_write(struct x86_64_iset *iset,
	const struct instruction *instruction, const int fd);

#endif

