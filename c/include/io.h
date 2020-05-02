#ifndef TRANSPILER_IO_H
#define TRANSPILER_IO_H
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

/* I/O utilities */

/* read all */
int
io_readall(const int fd, void *dest, size_t buflen);

/* write all */
int
io_writeall(const int fd, const void *buf, size_t buflen);

#endif

