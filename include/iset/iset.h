#ifndef TRANSPILER_ISET_H
#define TRANSPILER_ISET_H

/* instruction sets */

/* dependency-conscious instruction */
struct instruction {
  /* input registers */

  struct rid *inregs;
  unsigned short inregslen;
  
  /* output registers */

  struct rid *outregs;
  unsigned short outregslen;

  /* raw instruction */

  char *raw;
  unsigned short rawlen;
};

/* instruction set API */
struct iset {
  /* read the next instruction from a file */
  int (*read)(struct instruction *dest, const int fd);

  /* write the next instruction to a file */
  int (*write)(const struct instruction *instruction, const int fd);
};

/* register identifier */
struct rid {
  unsigned long id;
};

#endif

