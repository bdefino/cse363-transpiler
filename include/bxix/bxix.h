#ifndef TRANSPILER_BXIX_H
#define TRANSPILER_BXIX_H
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include "asm/iset.h"

/* binary executable instruction examiners */

/* binary executable instruction examiner API */
struct bxix {
	/* contextualize the examiner with a file */
	int	(*examine)(struct bxix *bxix, const int fd);
	int	fd;
	/* read the next instruction */
	int	(*read_instruction)(struct bxix *bxix, struct iset *iset,
			struct instruction *dest);
};

#endif

