#include "bxix/bxix.h"

/* ELF binary executable instruction examiner */

/* contextualize the examiner with a file */
int
bxix_elf_examine(struct bxix_elf *bxix, const int fd)
{
	int	class;
	size_t	n;
	int	retval;
	off_t	text;

	retval = 0;

	if (bxix == NULL) {
		retval = -EFAULT;
		goto bubble;
	}
	((struct bxix *) bxix)->fd = fd;

	/* seek to beginning */

	if (lseek(fd, 0, SEEK_SET)) {
		retval = -errno;
		goto bubble;
	}
	
	/* read header identity */

	retval = io_readall(buf->fd, &bxix->header._32.e_ident,
		sizeof(bxix->header._32.e_ident[EI_CLASS]));
	
	if (retval) {
		goto bubble;
	}

	/* read the remainder */

	class = bxix->header._32.e_ident[EI_CLASS];

	if (class != ELFCLASS32
			&& class != ELFCLASS64) {
		retval = BXIX_ELF_BAD_CLASS;
		goto bubble;
	}
	retval = io_readall(buf->fd, &bxix->header._32.e_type,
		class == ELFCLASS32
			? sizeof(bxix->header._32)
			: sizeof(bxix->header._64));

	if (retval) {
		goto bubble;
	}

	/* read program header */

	/*************************************************************************/

	/* seek to text section */

	/*******************************************************************************************/

bubble:
	return retval;
}

/* read the next instruction */
int
bxix_elf_read_instruction(struct bxix *bxix, struct iset *iset,
		struct instruction *dest)
{
	if (bxix == NULL) {
		return -EFAULT;
	}

	if (bxix->fd < 0) {
		return -EBADF;
	}

	if (dest == NULL) {
		return -EFAULT;
	}

	if (iset == NULL) {
		return -EFAULT;
	}

	if (iset->read == NULL) {
		return -EFAULT;
	}
	
	/* read */

	return (*iset->read)(iset, dest, bxix->fd);
}

