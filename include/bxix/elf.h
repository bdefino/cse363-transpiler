#ifndef TRANSPILER_BXIX_ELF_H
#define TRANSPILER_BXIX_ELF_H
#include <elf.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "bxix/bxix.h"
#include "io.h"

/* ELF binary executable instruction examiner */

#undef BXIX_ELF_BAD_CLASS
#undef BXIX_ELF_WIDTH_32
#undef BXIX_ELF_WIDTH_64

#define BXIX_ELF_BAD_CLASS	0x1
#define BXIX_ELF_WIDTH_32	0x20
#define BXIX_ELF_WIDTH_64	0x40

extern const struct bxix_elf {
	struct bxix super;
	union {
		Elf32_Ehdr	_32;
		Elf64_Ehdr	_64;
		char		raw[sizeof(Elf64_Ehdr)]; /* force packing */
	}	header;
} bxix_elf;

/* contextualize the examiner with a file */
int
bxix_elf_examine(struct bxix *bxix, const int fd);

/* read the next instruction */
int
bxix_elf_read_instruction(struct bxix *bxix, struct iset *iset,
	struct instruction *dest);

#endif

