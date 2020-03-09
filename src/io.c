#include "io.h"

/* I/O utilities */

int
io_readall(const int fd, void *dest, size_t buflen)
{
	int	iobuflen;
	int	retval;

	retval = 0;

	if (dest == NULL) {
		retval = -EFAULT;
		goto bubble;
	}

	if (fd < 0) {
		retval = -EBADF;
		goto bubble;
	}

	/* read */

	while (buflen > 0) {
		iobuflen = read(fd, dest, buflen);

		if (iobuflen <= 0) {
			retval = !iobuflen ? -EIO : -errno;
			goto bubble;
		}
		buf += iobuflen;
		buflen -= iobuflen;
	}
bubble:
	return retval;
}

int
io_writeall(const int fd, const void *buf, size_t buflen)
{
	int	iobuflen;
	int	retval;

	retval = 0;

	if (buf == NULL) {
		retval = -EFAULT;
		goto bubble;
	}

	if (fd < 0) {
		retval = -EBADF;
		goto bubble;
	}

	/* write */

	while (buflen > 0) {
		iobuflen = write(fd, buf, buflen);

		if (iobuflen <= 0) {
			retval = !iobuflen ? -EIO : -errno;
			goto bubble;
		}
		buf += iobuflen;
		buflen -= iobuflen;
	}
bubble:
	return retval;
}

#endif

