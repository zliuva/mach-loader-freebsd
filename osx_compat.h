/**
 * data structures from Apple's header files, APSL
 */
#ifndef OSX_COMPAT_H
#define OSX_COMPAT_H

#include <sys/stat.h>
#include <fts.h>

typedef __uint64_t __darwin_ino64_t;
typedef long __darwin_time_t;

struct __darwin_timespec {
	 __darwin_time_t tv_sec;
	  long tv_nsec;
};

struct __darwin_stat64 { dev_t st_dev; mode_t st_mode; nlink_t st_nlink; __darwin_ino64_t st_ino; uid_t st_uid; gid_t st_gid; dev_t st_rdev; struct timespec st_atimespec; struct timespec st_mtimespec; struct timespec st_ctimespec; struct timespec st_birthtimespec; off_t st_size; blkcnt_t st_blocks; blksize_t st_blksize; __uint32_t st_flags; __uint32_t st_gen; __int32_t st_lspare; __int64_t st_qspare[2]; };

typedef struct {
 struct __darwin_ftsent *fts_cur;
 struct __darwin_ftsent *fts_child;
 struct __darwin_ftsent **fts_array;
 dev_t fts_dev;
 char *fts_path;
 int fts_rfd;
 int fts_pathlen;
 int fts_nitems;
 int (*fts_compar)();
 int fts_options;
} __darwin_FTS;

typedef struct __darwin_ftsent {
 struct __darwin_ftsent *fts_cycle;
 struct __darwin_ftsent *fts_parent;
 struct __darwin_ftsent *fts_link;
 long fts_number;
 void *fts_pointer;
 char *fts_accpath;
 char *fts_path;
 int fts_errno;
 int fts_symfd;
 unsigned short fts_pathlen;
 unsigned short fts_namelen;
 __darwin_ino64_t fts_ino;
 dev_t fts_dev;
 nlink_t fts_nlink;
 short fts_level;
 unsigned short fts_info;
 unsigned short fts_flags;
 unsigned short fts_instr;
 struct stat *fts_statp;
 char fts_name[1];
} __darwin_FTSENT;

static void bsd_stat_2_osx_stat(struct stat *bsd_stat, struct __darwin_stat64 *osx_stat) {
	osx_stat->st_dev = bsd_stat->st_dev;
	osx_stat->st_mode = bsd_stat->st_mode;
	osx_stat->st_nlink = bsd_stat->st_nlink;
	osx_stat->st_ino = bsd_stat->st_ino;
	osx_stat->st_uid = bsd_stat->st_uid;
	osx_stat->st_gid = bsd_stat->st_gid;
	osx_stat->st_rdev = bsd_stat->st_rdev;
	osx_stat->st_atimespec = bsd_stat->st_atim;
	osx_stat->st_mtimespec = bsd_stat->st_mtim;
	osx_stat->st_ctimespec = bsd_stat->st_ctim;
	osx_stat->st_birthtimespec = bsd_stat->st_birthtim;
	osx_stat->st_size = bsd_stat->st_size;
	osx_stat->st_blocks = bsd_stat->st_blocks;
	osx_stat->st_blksize = bsd_stat->st_blksize;
	osx_stat->st_flags = bsd_stat->st_flags;
	osx_stat->st_gen = bsd_stat->st_gen;
	osx_stat->st_lspare = bsd_stat->st_lspare;
}

static int stat$INODE64(const char *restrict path, struct __darwin_stat64 *restrict buf) {
	struct stat st;
	int ret = stat(path, &st);

	bsd_stat_2_osx_stat(&st, buf);

	return ret;
}

static int lstat$INODE64(const char *restrict path, struct __darwin_stat64 *restrict buf) {
	struct stat st;
	int ret = lstat(path, &st);

	bsd_stat_2_osx_stat(&st, buf);

	return ret;
}

static __darwin_FTS *fts_open$INODE64(char * const *path_argv, int options,
							  int (*compar)(const __darwin_FTSENT **, const __darwin_FTSENT **)) {
	FTS *bsd_fts = fts_open(path_argv, options, compar);
}

static inline bool compat_mode(const char *function, const char *mode) {
	return true;
}

#endif //OSX_COMPAT_H

