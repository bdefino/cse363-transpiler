#ifndef TRANSPILER_ASM_ISET_H
#define TRANSPILER_ASM_ISET_H
#include <stdint.h>
#include <sys/types.h>

/* instruction sets */

/* dependency-conscious instruction */
struct instruction {
  int branch; /* instruction is a branch, jump, leave, return, etc. */

  /* (machine-)encoded instruction */

  char *encoded;
  size_t encodedlen;

  /* input registers */

  struct rid *inregs;
  unsigned short inregslen;
  
  /* output registers */

  struct rid *outregs;
  unsigned short outregslen;
};

/* instruction set API */
struct iset {
  /* read the next instruction from a file */
  int (*read)(struct iset *iset, struct instruction *dest, const int fd);

  /* write the next instruction to a file */
  int (*write)(struct iset *iset, const struct instruction *instruction,
    const int fd);
};

/* register identifier */
struct rid {
  size_t id;
};

#endif

