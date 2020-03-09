#include "bxix/bxix.h"

/* ELF binary executable instruction examiner */

const struct bxix bxix_elf = {
	.examine = &bxix_elf_examine,
	.read_instruction = &bxix_elf_read_instruction
};

/* contextualize the examiner with a file */
int
bxix_elf_examine(struct bxix *bxix, const int fd);

/* read the next instruction */
int
bxix_elf_read_instruction(struct bxix *bxix, struct iset *iset,
	struct instruction *dest);

