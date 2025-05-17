#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>

#include "../../log.h"

#include "posix.h"

#define MMAP_CHUNK_SIZE		(1024 * 1024 * 1024)

/*
 * discard_pages should not be run within Rosetta. Native arm64 or x86 only.
 */
static int discard_pages(int fd, off_t offset, off_t size)
{
	void *addr;
	uint64_t chunk_size = MMAP_CHUNK_SIZE;

	/*
	 * mmap the file in 1GB chunks and msync(MS_INVALIDATE).
	 */
	while (size > 0) {
		uint64_t mmap_size = MIN(chunk_size, size);

		addr = mmap(0, mmap_size, PROT_NONE, MAP_SHARED, fd, offset);
		if (addr == MAP_FAILED) {
                        int __map_errno = errno;
			log_err("discard_pages: failed to mmap (%s), offset = %llu, size = %llu\n",
				strerror(errno), offset, mmap_size);
                        errno = __map_errno;
			return errno;
		}

		if (msync(addr, mmap_size, MS_INVALIDATE)) {
                        int __msync_errno = errno;
			log_err("discard_pages: msync failed to free cache pages.\n");
                        errno = __msync_errno;
			return errno;
		}

		/* Destroy the above mappings used to invalidate cache - cleaning up */
		if (munmap(addr, mmap_size) < 0) {
                        int __munmap_errno = errno;
			log_err("discard_pages: munmap failed, error = %d.\n", errno);
                        errno = __munmap_errno;
			return errno;
		}

		size -= mmap_size;
		offset += mmap_size;
	}

	return 0;
}

extern int posix_fadvise(int fd, off_t offset, off_t len, int advice)
{
	int ret;

	switch(advice) {
	case POSIX_FADV_NORMAL:
	case POSIX_FADV_RANDOM:
	case POSIX_FADV_SEQUENTIAL:
		ret = 0;
		break;
	case POSIX_FADV_DONTNEED:
		ret = discard_pages(fd, offset, len);
		break;
        default:
		ret = EINVAL;
        }

	return ret;
}
