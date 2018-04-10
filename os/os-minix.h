#ifndef FIO_OS_MINIX_H
#define FIO_OS_MINIX_H

#define	FIO_OS	os_minix

#include <errno.h>
#include <sys/param.h>
#include <sys/statvfs.h>
#include <sys/ioctl.h>
#include <sys/dkio.h>
#include <sys/disklabel.h>
#include <sys/endian.h>
#include <sys/sysctl.h>

#include "../file.h"

#define FIO_HAVE_ODIRECT
#define FIO_USE_GENERIC_RAND
#define FIO_USE_GENERIC_INIT_RANDOM_STATE
#define FIO_HAVE_FS_STAT
#define FIO_NON_PREEMPTIVE_THREADS

#define OS_MAP_ANON		MAP_ANON

#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 4096
#endif

#define fio_swap16(x)	bswap16(x)
#define fio_swap32(x)	bswap32(x)
#define fio_swap64(x)	bswap64(x)

typedef off_t off64_t;

static inline int blockdev_size(struct fio_file *f, unsigned long long *bytes)
{
	struct disklabel dl;

	if (!ioctl(f->fd, DIOCGDINFO, &dl)) {
		*bytes = ((unsigned long long)dl.d_secperunit) * dl.d_secsize;
		return 0;
	}

	*bytes = 0;
	return errno;
}

static inline int blockdev_invalidate_cache(struct fio_file *f)
{
	return ENOTSUP;
}

static inline unsigned long long os_phys_mem(void)
{
	int mib[2] = { CTL_HW, HW_PHYSMEM64 };
	uint64_t mem;
	size_t len = sizeof(mem);

	sysctl(mib, 2, &mem, &len, NULL, 0);
	return mem;
}

//static inline int gettid(void)
//{
//	return (int) _lwp_self();
//}

static inline unsigned long long get_fs_free_size(const char *path)
{
	unsigned long long ret;
	struct statvfs s;

	if (statvfs(path, &s) < 0)
		return -1ULL;

	ret = s.f_frsize;
	ret *= (unsigned long long) s.f_bfree;
	return ret;
}

//#ifdef MADV_FREE
//#define FIO_MADV_FREE	MADV_FREE
//#endif

static inline int stub_posix_madvise(void *addr, size_t len, int advice)
{
	errno = ENOSYS;
	return -1;
}

static inline int stub_mlock(const void *addr, size_t len)
{
	errno = ENOSYS;
	return -1;
}

static inline int stub_munlock(const void *addr, size_t len)
{
	errno = ENOSYS;
	return -1;
}

static inline int stub_msync(const void *addr, size_t len, int flags)
{
	errno = ENOSYS;
	return -1;
}

#define munlock stub_munlock
#define mlock stub_mlock
#define msync stub_msync
#define posix_madvise stub_posix_madvise
#endif
