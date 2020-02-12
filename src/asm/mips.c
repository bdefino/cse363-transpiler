#include "iset/mips.h"

/* MIPS instruction set */

/* MIPS instruction set */
/*struct mips_iset {
  struct iset super;
};*/

int mips_iset_init(struct mips_iset *dest) {
  if (dest == NULL) {
    return -EFAULT;
  }
  *dest = (struct mips_iset) {
    (struct iset) {
      .read = (int (*)(struct iset *, struct instruction *, const int)) \
        &mips_iset_read,
      .write = (int (*)(struct mips_iset *, const struct instruction *,
        const int)) &mips_iset_write
    }
  };
}

/* read the next instruction from a file */
int mips_iset_read(struct mips_iset *iset, struct instruction *dest,
    const int fd) {
  int _errno;

  if (dest == NULL) {
    return -EFAULT;
  }

  if (fd < 0) {
    return -EBADF;
  }

  if (iset == NULL) {
    return -EFAULT;
  }

  /* allocate */

  dest->encodedlen = sizeof(uint32_t);
  dest->encoded = (char *) calloc(1, dest->encodedlen);

  if (dest->encoded == NULL) {
    return -errno;
  }

  /* read */

  if (read(fd, dest->encoded, dest->encodedlen) != dest->encodedlen) {
    _errno = errno;
    free(dest->encoded);
    dest->encoded = NULL;
    return -_errno;
  }

  /* parse I/O registers */

  //////////////////////////////////////////////////////////////////////////////////
  return 0;
}

/* write the next instruction to a file */
int mips_iset_write(struct mips_iset *iset,
    const struct instruction *instruction, const int fd) {
  if (fd < 0) {
    return -EBADF;
  }

  if (instruction == NULL) {
    return -EFAULT;
  }

  if (iset == NULL) {
    return -EFAULT;
  }

  /* write */
  
  if (write(fd, instruction->encoded, instruction->encoded_len)
      != instruction->encodedlen) {
    return -errno;
  }
  return 0;
}

