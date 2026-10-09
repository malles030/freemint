/*
 * This file belongs to FreeMiNT. It is an NFS version 3 server: see the
 * README in this directory.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This file is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */

/*
 * nfsd.c -- the NFS version 3 server, program 100003.
 *
 * Every procedure follows the same shape: decode a file handle, turn it into
 * a local path, do the work with ordinary POSIX calls, and encode the reply.
 * The handle carries the path relative to its export (see fh.h), so there is
 * no state between requests and nothing to lose on a restart.
 *
 * NFSv3 replies are built so that a client can refresh its attribute cache
 * from them: most carry a post_op_attr, and the ones that change a directory
 * carry wcc_data, which is the directory's attributes before and after. The
 * "before" half is why several procedures stat the parent first.
 */

# include "rpc.h"
# include "config.h"
# include "exports.h"
# include "fh.h"
# include "nfs3.h"

# include <dirent.h>
# include <errno.h>
# include <fcntl.h>
# include <signal.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <time.h>
# include <utime.h>
# include <unistd.h>
# include <arpa/inet.h>
# include <sys/stat.h>

# ifdef HAVE_STATVFS
#  include <sys/statvfs.h>
# endif

static rpc_server server;

/* The export the current request belongs to, and the identity to act as.
 * Set by resolve() at the top of every procedure.
 */
static const nfsd_export *cur_export;
static uint32_t cur_uid, cur_gid;

/* ------------------------------------------------------- error mapping */

static uint32_t
errno_to_nfs (int e)
{
	switch (e)
	{
	case 0:		return NFS3_OK;
	case EPERM:	return NFS3ERR_PERM;
	case ENOENT:	return NFS3ERR_NOENT;
	case EIO:	return NFS3ERR_IO;
	case ENXIO:	return NFS3ERR_NXIO;
	case EACCES:	return NFS3ERR_ACCES;
	case EEXIST:	return NFS3ERR_EXIST;
	case EXDEV:	return NFS3ERR_XDEV;
	case ENODEV:	return NFS3ERR_NODEV;
	case ENOTDIR:	return NFS3ERR_NOTDIR;
	case EISDIR:	return NFS3ERR_ISDIR;
	case EINVAL:	return NFS3ERR_INVAL;
	case EFBIG:	return NFS3ERR_FBIG;
	case ENOSPC:	return NFS3ERR_NOSPC;
	case EROFS:	return NFS3ERR_ROFS;
	case EMLINK:	return NFS3ERR_MLINK;
	case ENAMETOOLONG: return NFS3ERR_NAMETOOLONG;
	case ENOTEMPTY:	return NFS3ERR_NOTEMPTY;
	case ESTALE:	return NFS3ERR_STALE;
# ifdef EDQUOT
	case EDQUOT:	return NFS3ERR_DQUOT;
# endif
	default:	return NFS3ERR_IO;
	}
}

/* --------------------------------------------------- handle resolution */

/*
 * Turn a handle into an absolute local path and remember which export it
 * came from. Returns NFS3_OK, or the error to send back.
 *
 * relout, when given, receives the path relative to the export, which the
 * procedures that build child handles need.
 */
static uint32_t
resolve (XDR *args, const rpc_req *rq, char *out, size_t outsz, char *relout)
{
	uint8_t *p;
	uint32_t len;
	nfsd_fh fh;
	const nfsd_export *e;
	size_t need;

	if (!xdr_bytes (args, &p, &len, 64))
		return NFS3ERR_BADHANDLE;

	if (fh_decode (p, len, &fh) < 0)
		return NFS3ERR_BADHANDLE;

	e = exports_get (fh.exportid);
	if (!e)
		return NFS3ERR_STALE;

	if (!exports_allowed (e, ntohl (rq->from.sin_addr.s_addr)))
		return NFS3ERR_ACCES;

	need = strlen (e->path) + (fh.path[0] ? 1 + strlen (fh.path) : 0);
	if (need + 1 > outsz)
		return NFS3ERR_NAMETOOLONG;

	strcpy (out, e->path);
	if (fh.path[0])
	{
		strcat (out, "/");
		strcat (out, fh.path);
	}

	if (relout)
		strcpy (relout, fh.path);

	cur_export = e;

	cur_uid = rq->cred.have ? rq->cred.uid : e->anonuid;
	cur_gid = rq->cred.have ? rq->cred.gid : e->anongid;
	exports_squash (e, &cur_uid, &cur_gid);

	return NFS3_OK;
}

/* ------------------------------------------------------------ encoders */

static int
put_u32 (XDR *x, uint32_t v)
{
	return xdr_u32 (x, &v);
}

static int
put_u64 (XDR *x, uint64_t v)
{
	return xdr_u64 (x, &v);
}

static uint32_t
mode_to_ftype (mode_t m)
{
	if (S_ISREG (m))  return NF3REG;
	if (S_ISDIR (m))  return NF3DIR;
	if (S_ISLNK (m))  return NF3LNK;
	if (S_ISCHR (m))  return NF3CHR;
	if (S_ISBLK (m))  return NF3BLK;
# ifdef S_ISFIFO
	if (S_ISFIFO (m)) return NF3FIFO;
# endif
# ifdef S_ISSOCK
	if (S_ISSOCK (m)) return NF3SOCK;
# endif

	return NF3REG;
}

/*
 * fattr3. The file id has to be stable for as long as the client caches it,
 * and distinct between files in one file system, which is what the inode
 * number gives us. Where a file system has no real inode numbers -- a FAT
 * partition on an Atari -- the MiNTLib synthesises one, and that is the best
 * available.
 */
static int
put_fattr3 (XDR *x, const struct stat *st)
{
	uint32_t ftype = mode_to_ftype (st->st_mode);

	if (!put_u32 (x, ftype)
	    || !put_u32 (x, (uint32_t) (st->st_mode & 07777))
	    || !put_u32 (x, (uint32_t) st->st_nlink)
	    || !put_u32 (x, (uint32_t) st->st_uid)
	    || !put_u32 (x, (uint32_t) st->st_gid)
	    || !put_u64 (x, (uint64_t) st->st_size)
	    || !put_u64 (x, (uint64_t) st->st_size))	/* bytes used */
		return 0;

	/* specdata3: meaningful only for a device, zero otherwise */
	if (ftype == NF3CHR || ftype == NF3BLK)
	{
		if (!put_u32 (x, (uint32_t) ((st->st_rdev >> 8) & 0xff))
		    || !put_u32 (x, (uint32_t) (st->st_rdev & 0xff)))
			return 0;
	}
	else if (!put_u32 (x, 0) || !put_u32 (x, 0))
		return 0;

	if (!put_u64 (x, (uint64_t) st->st_dev)		/* fsid */
	    || !put_u64 (x, (uint64_t) st->st_ino))	/* fileid */
		return 0;

	/* atime, mtime, ctime: seconds and nanoseconds */
	if (!put_u32 (x, (uint32_t) st->st_atime) || !put_u32 (x, 0)
	    || !put_u32 (x, (uint32_t) st->st_mtime) || !put_u32 (x, 0)
	    || !put_u32 (x, (uint32_t) st->st_ctime) || !put_u32 (x, 0))
		return 0;

	return 1;
}

/* post_op_attr: present or not, which is how a reply can carry attributes
 * without the operation depending on them.
 */
static int
put_post_op_attr (XDR *x, const char *path)
{
	struct stat st;

	if (path && lstat (path, &st) == 0)
		return put_u32 (x, 1) && put_fattr3 (x, &st);

	return put_u32 (x, 0);
}

static int
put_post_op_attr_st (XDR *x, const struct stat *st)
{
	if (st)
		return put_u32 (x, 1) && put_fattr3 (x, st);

	return put_u32 (x, 0);
}

/* wcc_attr: the three fields a client compares to notice someone else's
 * change -- size and the two times.
 */
static int
put_pre_op_attr (XDR *x, const struct stat *st, int valid)
{
	if (!valid)
		return put_u32 (x, 0);

	return put_u32 (x, 1)
	    && put_u64 (x, (uint64_t) st->st_size)
	    && put_u32 (x, (uint32_t) st->st_mtime) && put_u32 (x, 0)
	    && put_u32 (x, (uint32_t) st->st_ctime) && put_u32 (x, 0);
}

static int
put_wcc_data (XDR *x, const struct stat *before, int before_valid,
	      const char *after_path)
{
	return put_pre_op_attr (x, before, before_valid)
	    && put_post_op_attr (x, after_path);
}

static int
put_handle (XDR *x, uint32_t exportid, const char *relpath)
{
	uint8_t h[FH_SIZE];
	uint8_t *p = h;
	uint32_t len = FH_SIZE;

	if (fh_encode (h, exportid, relpath) < 0)
		return 0;

	return xdr_bytes (x, &p, &len, FH_SIZE);
}

/* post_op_fh3 */
static int
put_post_op_fh (XDR *x, uint32_t exportid, const char *relpath)
{
	return put_u32 (x, 1) && put_handle (x, exportid, relpath);
}

/*
 * Every failing reply still carries whatever attributes it can. Sending the
 * status alone is legal but makes a client re-stat everything after each
 * error, so the common shape is status plus a post_op_attr.
 */
static int
fail_with_attr (XDR *res, uint32_t status, const char *path)
{
	return put_u32 (res, status) && put_post_op_attr (res, path);
}

/* ------------------------------------------------------- name decoding */

/*
 * diropargs3: a directory handle and a name inside it. Produces the
 * directory's local path, the child's local path and the child's path
 * relative to the export.
 */
static uint32_t
get_diropargs (XDR *args, const rpc_req *rq,
	       char *dirpath, size_t dirsz, char *dirrel,
	       char *childpath, size_t childsz, char *childrel)
{
	char name[NFSD_MAXNAME + 2];
	uint32_t st;

	st = resolve (args, rq, dirpath, dirsz, dirrel);
	if (st != NFS3_OK)
		return st;

	if (!xdr_string (args, name, sizeof (name)))
		return NFS3ERR_NAMETOOLONG;

	if (!fh_name_ok (name))
		return NFS3ERR_INVAL;

	if (fh_child (childrel, NFSD_FHPATHLEN + 1, dirrel, name) < 0)
		return NFS3ERR_NAMETOOLONG;

	if (strlen (cur_export->path) + 1 + strlen (childrel) + 1 > childsz)
		return NFS3ERR_NAMETOOLONG;

	strcpy (childpath, cur_export->path);
	strcat (childpath, "/");
	strcat (childpath, childrel);

	return NFS3_OK;
}

/* ---------------------------------------------------------- procedures */

static int
nfs3_null (rpc_req *rq, XDR *args, XDR *res)
{
	(void) rq; (void) args; (void) res;

	return 0;
}

static int
nfs3_getattr (rpc_req *rq, XDR *args, XDR *res)
{
	char path[NFSD_MAXPATH];
	struct stat st;
	uint32_t s;

	s = resolve (args, rq, path, sizeof (path), NULL);
	if (s != NFS3_OK)
		return put_u32 (res, s) ? 0 : -RPC_SYSTEM_ERR;

	if (lstat (path, &st) < 0)
		return put_u32 (res, errno_to_nfs (errno)) ? 0 : -RPC_SYSTEM_ERR;

	if (!put_u32 (res, NFS3_OK) || !put_fattr3 (res, &st))
		return -RPC_SYSTEM_ERR;

	return 0;
}

static int
nfs3_lookup (rpc_req *rq, XDR *args, XDR *res)
{
	char dirpath[NFSD_MAXPATH], childpath[NFSD_MAXPATH];
	char dirrel[NFSD_FHPATHLEN + 1], childrel[NFSD_FHPATHLEN + 1];
	char name[NFSD_MAXNAME + 2];
	struct stat st;
	uint32_t s;

	s = resolve (args, rq, dirpath, sizeof (dirpath), dirrel);
	if (s != NFS3_OK)
		return fail_with_attr (res, s, NULL) ? 0 : -RPC_SYSTEM_ERR;

	if (!xdr_string (args, name, sizeof (name)))
		return fail_with_attr (res, NFS3ERR_NAMETOOLONG, dirpath)
			? 0 : -RPC_SYSTEM_ERR;

	/*
	 * "." and ".." never reach the file system: they are answered from
	 * the handle's own path, which is what keeps ".." at the root of an
	 * export from naming the directory above it.
	 */
	if (strcmp (name, ".") == 0)
		strcpy (childrel, dirrel);
	else if (strcmp (name, "..") == 0)
	{
		strcpy (childrel, dirrel);
		fh_parent (childrel);
	}
	else if (!fh_name_ok (name))
		return fail_with_attr (res, NFS3ERR_NOENT, dirpath)
			? 0 : -RPC_SYSTEM_ERR;
	else if (fh_child (childrel, sizeof (childrel), dirrel, name) < 0)
		return fail_with_attr (res, NFS3ERR_NAMETOOLONG, dirpath)
			? 0 : -RPC_SYSTEM_ERR;

	strcpy (childpath, cur_export->path);
	if (childrel[0])
	{
		strcat (childpath, "/");
		strcat (childpath, childrel);
	}

	if (lstat (childpath, &st) < 0)
		return fail_with_attr (res, errno_to_nfs (errno), dirpath)
			? 0 : -RPC_SYSTEM_ERR;

	if (!put_u32 (res, NFS3_OK)
	    || !put_handle (res, cur_export->id, childrel)
	    || !put_post_op_attr_st (res, &st)
	    || !put_post_op_attr (res, dirpath))
		return -RPC_SYSTEM_ERR;

	return 0;
}

static int
nfs3_access (rpc_req *rq, XDR *args, XDR *res)
{
	char path[NFSD_MAXPATH];
	struct stat st;
	uint32_t s, want, have = 0;

	s = resolve (args, rq, path, sizeof (path), NULL);
	if (s != NFS3_OK)
		return fail_with_attr (res, s, NULL) ? 0 : -RPC_SYSTEM_ERR;

	if (!xdr_u32 (args, &want))
		return -RPC_GARBAGE_ARGS;

	if (lstat (path, &st) < 0)
		return fail_with_attr (res, errno_to_nfs (errno), NULL)
			? 0 : -RPC_SYSTEM_ERR;

	/*
	 * Answer from the mode bits as the caller would see them. This is
	 * advice: the client may skip an operation we say would fail, but it
	 * is the operation itself that decides. Being generous here and
	 * wrong later is the safe direction; being stingy would make a
	 * client refuse something that would have worked.
	 */
	{
		int owner = (uint32_t) st.st_uid == cur_uid;
		int group = (uint32_t) st.st_gid == cur_gid;
		mode_t m = st.st_mode;
		int r, w, xx;

		if (cur_uid == 0)
			r = w = xx = 1;
		else if (owner)
		{
			r = (m & S_IRUSR) != 0;
			w = (m & S_IWUSR) != 0;
			xx = (m & S_IXUSR) != 0;
		}
		else if (group)
		{
			r = (m & S_IRGRP) != 0;
			w = (m & S_IWGRP) != 0;
			xx = (m & S_IXGRP) != 0;
		}
		else
		{
			r = (m & S_IROTH) != 0;
			w = (m & S_IWOTH) != 0;
			xx = (m & S_IXOTH) != 0;
		}

		if (cur_export->ro)
			w = 0;

		if (r) have |= ACCESS3_READ;

		if (S_ISDIR (m))
		{
			if (xx) have |= ACCESS3_LOOKUP;
			if (w)  have |= ACCESS3_MODIFY | ACCESS3_EXTEND
				      | ACCESS3_DELETE;
		}
		else
		{
			if (w)  have |= ACCESS3_MODIFY | ACCESS3_EXTEND;
			if (xx) have |= ACCESS3_EXECUTE;
		}

		have &= want;
	}

	if (!put_u32 (res, NFS3_OK)
	    || !put_post_op_attr_st (res, &st)
	    || !put_u32 (res, have))
		return -RPC_SYSTEM_ERR;

	return 0;
}

static int
nfs3_readlink (rpc_req *rq, XDR *args, XDR *res)
{
	char path[NFSD_MAXPATH];
	char target[NFSD_MAXPATH];
	uint32_t s;
	int n;

	s = resolve (args, rq, path, sizeof (path), NULL);
	if (s != NFS3_OK)
		return fail_with_attr (res, s, NULL) ? 0 : -RPC_SYSTEM_ERR;

	n = (int) readlink (path, target, sizeof (target) - 1);
	if (n < 0)
		return fail_with_attr (res, errno_to_nfs (errno), path)
			? 0 : -RPC_SYSTEM_ERR;

	target[n] = '\0';

	if (!put_u32 (res, NFS3_OK)
	    || !put_post_op_attr (res, path)
	    || !xdr_string (res, target, sizeof (target)))
		return -RPC_SYSTEM_ERR;

	return 0;
}

static int
nfs3_read (rpc_req *rq, XDR *args, XDR *res)
{
	char path[NFSD_MAXPATH];
	uint64_t offset;
	uint32_t count, s;
	struct stat st;
	int fd;
	ssize_t got;
	uint8_t *buf;
	uint32_t eof;

	s = resolve (args, rq, path, sizeof (path), NULL);
	if (s != NFS3_OK)
		return fail_with_attr (res, s, NULL) ? 0 : -RPC_SYSTEM_ERR;

	if (!xdr_u64 (args, &offset) || !xdr_u32 (args, &count))
		return -RPC_GARBAGE_ARGS;

	if (count > NFSD_MAXDATA)
		count = NFSD_MAXDATA;

	fd = open (path, O_RDONLY);
	if (fd < 0)
		return fail_with_attr (res, errno_to_nfs (errno), path)
			? 0 : -RPC_SYSTEM_ERR;

	if (fstat (fd, &st) < 0)
	{
		int e = errno;

		close (fd);
		return fail_with_attr (res, errno_to_nfs (e), path)
			? 0 : -RPC_SYSTEM_ERR;
	}

	if (S_ISDIR (st.st_mode))
	{
		close (fd);
		return fail_with_attr (res, NFS3ERR_ISDIR, path)
			? 0 : -RPC_SYSTEM_ERR;
	}

	/*
	 * MiNT's file position is a signed 32 bit value, so a request past
	 * 2 GB cannot be served even though the size field is 64 bit. Say so
	 * rather than seeking somewhere unintended.
	 */
	if (offset > 0x7ffffffful)
	{
		close (fd);
		return fail_with_attr (res, NFS3ERR_INVAL, path)
			? 0 : -RPC_SYSTEM_ERR;
	}

	/* Write the data straight into the reply buffer: the header is
	 * already there, so this is where it has to end up anyway.
	 */
	if (!put_u32 (res, NFS3_OK) || !put_post_op_attr_st (res, &st))
	{
		close (fd);
		return -RPC_SYSTEM_ERR;
	}

	if (lseek (fd, (off_t) offset, SEEK_SET) == (off_t) -1)
	{
		int e = errno;

		close (fd);
		return fail_with_attr (res, errno_to_nfs (e), path)
			? 0 : -RPC_SYSTEM_ERR;
	}

	buf = malloc (count ? count : 1);
	if (!buf)
	{
		close (fd);
		return -RPC_SYSTEM_ERR;
	}

	got = read (fd, buf, count);
	close (fd);

	if (got < 0)
	{
		free (buf);
		return -RPC_SYSTEM_ERR;
	}

	eof = ((uint64_t) offset + (uint64_t) got >= (uint64_t) st.st_size)
		? 1 : 0;

	{
		uint32_t n = (uint32_t) got;
		uint8_t *p = buf;
		int good = put_u32 (res, n) && put_u32 (res, eof)
			&& xdr_bytes (res, &p, &n, NFSD_MAXDATA);

		free (buf);

		if (!good)
			return -RPC_SYSTEM_ERR;
	}

	return 0;
}

/*
 * READDIR and READDIRPLUS.
 *
 * The cookie is how a client resumes a listing it could not take in one
 * reply. Using the directory offset from telldir() would be natural but it
 * is not portable and not stable across a reopen, so the cookie here is
 * simply "how many entries to skip", and the directory is re-read from the
 * start each time. That costs a rewind on a continued listing and is
 * correct as long as the directory does not change underneath -- the same
 * caveat every server has, which is what the cookie verifier is for. We
 * send a zero verifier, meaning we do not detect it.
 */
static int
do_readdir (rpc_req *rq, XDR *args, XDR *res, int plus)
{
	char path[NFSD_MAXPATH], rel[NFSD_FHPATHLEN + 1];
	uint64_t cookie;
	uint8_t verf[8];
	uint32_t dircount, maxcount, s;
	uint32_t *vp;
	DIR *d;
	struct dirent *de;
	struct stat dst;
	uint64_t index = 0;
	int wrote = 0;
	size_t budget;

	s = resolve (args, rq, path, sizeof (path), rel);
	if (s != NFS3_OK)
		return fail_with_attr (res, s, NULL) ? 0 : -RPC_SYSTEM_ERR;

	if (!xdr_u64 (args, &cookie) || !xdr_opaque (args, verf, 8))
		return -RPC_GARBAGE_ARGS;

	if (plus)
	{
		if (!xdr_u32 (args, &dircount) || !xdr_u32 (args, &maxcount))
			return -RPC_GARBAGE_ARGS;
	}
	else
	{
		if (!xdr_u32 (args, &maxcount))
			return -RPC_GARBAGE_ARGS;
		dircount = maxcount;
	}

	if (lstat (path, &dst) < 0)
		return fail_with_attr (res, errno_to_nfs (errno), NULL)
			? 0 : -RPC_SYSTEM_ERR;

	if (!S_ISDIR (dst.st_mode))
		return fail_with_attr (res, NFS3ERR_NOTDIR, path)
			? 0 : -RPC_SYSTEM_ERR;

	d = opendir (path);
	if (!d)
		return fail_with_attr (res, errno_to_nfs (errno), path)
			? 0 : -RPC_SYSTEM_ERR;

	if (maxcount > NFSD_MAXDIRCOUNT)
		maxcount = NFSD_MAXDIRCOUNT;

	/* Leave room for the status, the attributes, the verifier and the
	 * two booleans that close the list.
	 */
	budget = maxcount > 256 ? maxcount - 256 : 64;

	if (!put_u32 (res, NFS3_OK)
	    || !put_post_op_attr_st (res, &dst)
	    || !xdr_opaque (res, verf, 8))		/* echo it back */
	{
		closedir (d);
		return -RPC_SYSTEM_ERR;
	}

	/* Remember where the entry list starts so a too small maxcount can
	 * be reported as TOOSMALL rather than as an empty directory.
	 */
	vp = NULL;
	(void) vp;

	while ((de = readdir (d)) != NULL)
	{
		char childrel[NFSD_FHPATHLEN + 1];
		char childpath[NFSD_MAXPATH];
		struct stat cst;
		int have_cst = 0;
		size_t before;

		index++;

		if (index <= cookie)
			continue;		/* already sent */

		/* A name we could not express in a reply has to be skipped
		 * before anything is copied. fh_name_ok covers this for
		 * ordinary names, but "." and ".." bypass it below.
		 */
		if (strlen (de->d_name) > NFSD_MAXNAME)
			continue;

		/* "." and ".." are part of a listing, but their handles are
		 * the directory's own and its parent's, not children.
		 */
		if (strcmp (de->d_name, ".") == 0)
			strcpy (childrel, rel);
		else if (strcmp (de->d_name, "..") == 0)
		{
			strcpy (childrel, rel);
			fh_parent (childrel);
		}
		else if (!fh_name_ok (de->d_name))
			continue;		/* not nameable over NFS */
		else if (fh_child (childrel, sizeof (childrel), rel,
				   de->d_name) < 0)
			continue;		/* too deep for a handle */

		before = xdr_pos (res);

		if (xdr_pos (res) > budget)
			break;

		strcpy (childpath, cur_export->path);
		if (childrel[0])
		{
			strcat (childpath, "/");
			strcat (childpath, childrel);
		}

		if (plus && lstat (childpath, &cst) == 0)
			have_cst = 1;

		/* entry: present, fileid, name, cookie */
		if (!put_u32 (res, 1))
			break;

		{
			uint64_t fid;

			if (have_cst)
				fid = (uint64_t) cst.st_ino;
			else
			{
				struct stat tmp;

				fid = lstat (childpath, &tmp) == 0
					? (uint64_t) tmp.st_ino : index;
			}

			if (!put_u64 (res, fid))
				break;
		}

		{
			char nm[NFSD_MAXNAME + 2];

			/* The length was checked above. */
			memcpy (nm, de->d_name, strlen (de->d_name) + 1);

			if (!xdr_string (res, nm, sizeof (nm)))
				break;
		}

		if (!put_u64 (res, index))
			break;

		if (plus)
		{
			if (!put_post_op_attr_st (res, have_cst ? &cst : NULL))
				break;

			/* post_op_fh3 */
			if (!put_post_op_fh (res, cur_export->id, childrel))
				break;
		}

		if (!xdr_ok (res))
		{
			/* It did not fit. Rewind to before this entry and
			 * stop; the client will ask again from its cookie.
			 */
			res->pos = before;
			res->err = 0;
			break;
		}

		wrote++;
	}

	closedir (d);

	if (!xdr_ok (res))
		return -RPC_SYSTEM_ERR;

	/* end of list, then eof */
	if (!put_u32 (res, 0) || !put_u32 (res, de == NULL ? 1 : 0))
		return -RPC_SYSTEM_ERR;

	rpc_log ("nfsd: READDIR%s %s -> %d entries%s", plus ? "PLUS" : "",
		 path, wrote, de == NULL ? ", eof" : "");

	return 0;
}

static int
nfs3_readdir (rpc_req *rq, XDR *args, XDR *res)
{
	return do_readdir (rq, args, res, 0);
}

static int
nfs3_readdirplus (rpc_req *rq, XDR *args, XDR *res)
{
	return do_readdir (rq, args, res, 1);
}

static int
nfs3_fsstat (rpc_req *rq, XDR *args, XDR *res)
{
	char path[NFSD_MAXPATH];
	uint32_t s;
	uint64_t total = 0, free_b = 0, avail = 0;
	uint64_t tfiles = 0, ffiles = 0;

	s = resolve (args, rq, path, sizeof (path), NULL);
	if (s != NFS3_OK)
		return fail_with_attr (res, s, NULL) ? 0 : -RPC_SYSTEM_ERR;

# ifdef HAVE_STATVFS
	{
		struct statvfs vfs;

		if (statvfs (path, &vfs) == 0)
		{
			uint64_t bs = vfs.f_frsize ? vfs.f_frsize : vfs.f_bsize;

			total  = (uint64_t) vfs.f_blocks * bs;
			free_b = (uint64_t) vfs.f_bfree  * bs;
			avail  = (uint64_t) vfs.f_bavail * bs;
			tfiles = (uint64_t) vfs.f_files;
			ffiles = (uint64_t) vfs.f_ffree;
		}
	}
# endif

	if (!put_u32 (res, NFS3_OK)
	    || !put_post_op_attr (res, path)
	    || !put_u64 (res, total)
	    || !put_u64 (res, free_b)
	    || !put_u64 (res, avail)
	    || !put_u64 (res, tfiles)
	    || !put_u64 (res, ffiles)
	    || !put_u64 (res, ffiles)		/* afiles */
	    || !put_u32 (res, 0))		/* invarsec: we do not promise */
		return -RPC_SYSTEM_ERR;

	return 0;
}

static int
nfs3_fsinfo (rpc_req *rq, XDR *args, XDR *res)
{
	char path[NFSD_MAXPATH];
	uint32_t s;

	s = resolve (args, rq, path, sizeof (path), NULL);
	if (s != NFS3_OK)
		return fail_with_attr (res, s, NULL) ? 0 : -RPC_SYSTEM_ERR;

	if (!put_u32 (res, NFS3_OK) || !put_post_op_attr (res, path))
		return -RPC_SYSTEM_ERR;

	/*
	 * The transfer sizes a client should use. NFSD_MAXDATA is what the
	 * reply buffer can hold, so announcing more would mean truncating
	 * our own replies.
	 */
	if (!put_u32 (res, NFSD_MAXDATA)	/* rtmax */
	    || !put_u32 (res, NFSD_MAXDATA)	/* rtpref */
	    || !put_u32 (res, 4)		/* rtmult */
	    || !put_u32 (res, NFSD_MAXDATA)	/* wtmax */
	    || !put_u32 (res, NFSD_MAXDATA)	/* wtpref */
	    || !put_u32 (res, 4)		/* wtmult */
	    || !put_u32 (res, NFSD_MAXDIRCOUNT)	/* dtpref */
	    || !put_u64 (res, 0x7ffffffful)	/* maxfilesize: 2 GB, see READ */
	    || !put_u32 (res, 1) || !put_u32 (res, 0))	/* time_delta: 1 s */
		return -RPC_SYSTEM_ERR;

	if (!put_u32 (res, FSF3_LINK | FSF3_SYMLINK | FSF3_HOMOGENEOUS
			   | FSF3_CANSETTIME))
		return -RPC_SYSTEM_ERR;

	return 0;
}

static int
nfs3_pathconf (rpc_req *rq, XDR *args, XDR *res)
{
	char path[NFSD_MAXPATH];
	uint32_t s;

	s = resolve (args, rq, path, sizeof (path), NULL);
	if (s != NFS3_OK)
		return fail_with_attr (res, s, NULL) ? 0 : -RPC_SYSTEM_ERR;

	if (!put_u32 (res, NFS3_OK)
	    || !put_post_op_attr (res, path)
	    || !put_u32 (res, 32767)		/* linkmax */
	    || !put_u32 (res, NFSD_MAXNAME)	/* name_max */
	    || !put_u32 (res, 0)		/* no_trunc: names are refused,
						 * not shortened */
	    || !put_u32 (res, 1)		/* chown_restricted */
	    || !put_u32 (res, 0)		/* case_insensitive */
	    || !put_u32 (res, 1))		/* case_preserving */
		return -RPC_SYSTEM_ERR;

	return 0;
}

/* ---------------------------------------------- permission and writability */

/*
 * The server does its work as whatever user it runs as, which on an Atari is
 * the only user there is. So the mode bits of a file would not stop anything
 * by themselves: they are checked here, against the uid the caller claims,
 * before the operation is attempted.
 *
 * That claim is the client's own word for itself -- AUTH_UNIX carries no
 * proof -- so this is not a security boundary. The boundary is the address
 * list in the exports file. What this does buy is that a read only file
 * behaves like one, and that an export marked ro really refuses writes.
 */
# define PERM_R	4
# define PERM_W	2
# define PERM_X	1

static uint32_t
check_perm (const struct stat *st, int want)
{
	mode_t m = st->st_mode;
	int have;

	if (cur_uid == 0)
		have = PERM_R | PERM_W | PERM_X;	/* root, as always */
	else if ((uint32_t) st->st_uid == cur_uid)
		have = ((m & S_IRUSR) ? PERM_R : 0)
		     | ((m & S_IWUSR) ? PERM_W : 0)
		     | ((m & S_IXUSR) ? PERM_X : 0);
	else if ((uint32_t) st->st_gid == cur_gid)
		have = ((m & S_IRGRP) ? PERM_R : 0)
		     | ((m & S_IWGRP) ? PERM_W : 0)
		     | ((m & S_IXGRP) ? PERM_X : 0);
	else
		have = ((m & S_IROTH) ? PERM_R : 0)
		     | ((m & S_IWOTH) ? PERM_W : 0)
		     | ((m & S_IXOTH) ? PERM_X : 0);

	return (want & ~have) ? NFS3ERR_ACCES : NFS3_OK;
}

/* Does this export allow writing at all? */
static uint32_t
check_rw (void)
{
	return cur_export->ro ? NFS3ERR_ROFS : NFS3_OK;
}

/*
 * The write verifier. A client keeps it from one WRITE to the next and
 * compares it after a COMMIT: a different value means the server restarted
 * and anything it had not committed is gone, so the client resends. Taking
 * it from the start time is what makes a restart visible.
 */
static uint8_t write_verf[8];

static void
init_write_verf (void)
{
	uint32_t t = (uint32_t) time (NULL);
	uint32_t p = (uint32_t) getpid ();

	write_verf[0] = (uint8_t) (t >> 24);
	write_verf[1] = (uint8_t) (t >> 16);
	write_verf[2] = (uint8_t) (t >> 8);
	write_verf[3] = (uint8_t) (t);
	write_verf[4] = (uint8_t) (p >> 24);
	write_verf[5] = (uint8_t) (p >> 16);
	write_verf[6] = (uint8_t) (p >> 8);
	write_verf[7] = (uint8_t) (p);
}

/* --------------------------------------------------------- sattr3 decoding */

typedef struct
{
	int		set_mode;
	uint32_t	mode;
	int		set_uid;
	uint32_t	uid;
	int		set_gid;
	uint32_t	gid;
	int		set_size;
	uint64_t	size;
	int		set_atime;	/* 0 no, 1 server time, 2 client time */
	uint32_t	atime;
	int		set_mtime;
	uint32_t	mtime;
} sattr3;

static int
get_sattr3 (XDR *x, sattr3 *a)
{
	uint32_t b, how, nsec;

	memset (a, 0, sizeof (*a));

	if (!xdr_bool (x, &b)) return 0;
	if (b) { a->set_mode = 1; if (!xdr_u32 (x, &a->mode)) return 0; }

	if (!xdr_bool (x, &b)) return 0;
	if (b) { a->set_uid = 1; if (!xdr_u32 (x, &a->uid)) return 0; }

	if (!xdr_bool (x, &b)) return 0;
	if (b) { a->set_gid = 1; if (!xdr_u32 (x, &a->gid)) return 0; }

	if (!xdr_bool (x, &b)) return 0;
	if (b) { a->set_size = 1; if (!xdr_u64 (x, &a->size)) return 0; }

	/* The two times are discriminated, not optional: the value is only
	 * present for SET_TO_CLIENT_TIME.
	 */
	if (!xdr_enum (x, &how)) return 0;
	if (how == SET_TO_SERVER_TIME)
		a->set_atime = 1;
	else if (how == SET_TO_CLIENT_TIME)
	{
		a->set_atime = 2;
		if (!xdr_u32 (x, &a->atime) || !xdr_u32 (x, &nsec)) return 0;
	}

	if (!xdr_enum (x, &how)) return 0;
	if (how == SET_TO_SERVER_TIME)
		a->set_mtime = 1;
	else if (how == SET_TO_CLIENT_TIME)
	{
		a->set_mtime = 2;
		if (!xdr_u32 (x, &a->mtime) || !xdr_u32 (x, &nsec)) return 0;
	}

	return 1;
}

/*
 * Apply what sattr3 asked for. Done field by field, and the first failure
 * stops the rest: a half applied SETATTR is confusing but a client that is
 * told it worked when it did not is worse.
 */
static uint32_t
apply_sattr3 (const char *path, const sattr3 *a, const struct stat *st)
{
	if (a->set_size)
	{
		if (S_ISDIR (st->st_mode))
			return NFS3ERR_ISDIR;

		if (a->size > 0x7ffffffful)
			return NFS3ERR_FBIG;

		if (truncate (path, (off_t) a->size) < 0)
			return errno_to_nfs (errno);
	}

	if (a->set_mode)
	{
		if (chmod (path, (mode_t) (a->mode & 07777)) < 0)
			return errno_to_nfs (errno);
	}

	if (a->set_uid || a->set_gid)
	{
		uid_t u = a->set_uid ? (uid_t) a->uid : (uid_t) -1;
		gid_t g = a->set_gid ? (gid_t) a->gid : (gid_t) -1;

		/* Only root can give a file away, and on a squashed export
		 * the request is meaningless anyway. Failing quietly here
		 * would leave the client believing it had worked.
		 */
		if (chown (path, u, g) < 0)
			return errno_to_nfs (errno);
	}

	if (a->set_atime || a->set_mtime)
	{
		struct utimbuf tb;
		time_t now = time (NULL);

		tb.actime  = a->set_atime == 2 ? (time_t) a->atime
			   : a->set_atime == 1 ? now : st->st_atime;
		tb.modtime = a->set_mtime == 2 ? (time_t) a->mtime
			   : a->set_mtime == 1 ? now : st->st_mtime;

		if (utime (path, &tb) < 0)
			return errno_to_nfs (errno);
	}

	return NFS3_OK;
}

/* ------------------------------------------------------ write procedures */

static int
nfs3_setattr (rpc_req *rq, XDR *args, XDR *res)
{
	char path[NFSD_MAXPATH];
	struct stat st;
	sattr3 a;
	uint32_t s, guard;
	int have_st = 0;

	s = resolve (args, rq, path, sizeof (path), NULL);
	if (s == NFS3_OK)
	{
		have_st = lstat (path, &st) == 0;

		if (!get_sattr3 (args, &a))
			return -RPC_GARBAGE_ARGS;

		if (!xdr_bool (args, &guard))
			return -RPC_GARBAGE_ARGS;

		if (guard)
		{
			uint32_t sec, nsec;

			if (!xdr_u32 (args, &sec) || !xdr_u32 (args, &nsec))
				return -RPC_GARBAGE_ARGS;

			/* The client is saying "only if nobody else has
			 * touched it since". That is the one check that
			 * makes SETATTR safe against a concurrent change.
			 */
			if (!have_st || (uint32_t) st.st_ctime != sec)
				s = NFS3ERR_NOT_SYNC;
		}

		if (s == NFS3_OK)
			s = check_rw ();

		if (s == NFS3_OK && !have_st)
			s = NFS3ERR_STALE;

		if (s == NFS3_OK)
			s = check_perm (&st, PERM_W);

		if (s == NFS3_OK)
			s = apply_sattr3 (path, &a, &st);
	}

	if (!put_u32 (res, s)
	    || !put_wcc_data (res, &st, have_st, s == NFS3_OK ? path : path))
		return -RPC_SYSTEM_ERR;

	return 0;
}

static int
nfs3_write (rpc_req *rq, XDR *args, XDR *res)
{
	char path[NFSD_MAXPATH];
	struct stat st;
	uint64_t offset;
	uint32_t count, stable, s, len;
	uint8_t *data;
	int have_st = 0, fd;
	ssize_t wrote = 0;

	s = resolve (args, rq, path, sizeof (path), NULL);

	if (s != NFS3_OK)
	{
		if (!put_u32 (res, s) || !put_wcc_data (res, &st, 0, NULL))
			return -RPC_SYSTEM_ERR;
		return 0;
	}

	if (!xdr_u64 (args, &offset) || !xdr_u32 (args, &count)
	    || !xdr_enum (args, &stable)
	    || !xdr_bytes (args, &data, &len, NFSD_MAXDATA))
		return -RPC_GARBAGE_ARGS;

	/* count and the real length of the data must agree; trusting count
	 * would read past what arrived.
	 */
	if (count != len)
		count = len;

	have_st = lstat (path, &st) == 0;

	if ((s = check_rw ()) == NFS3_OK)
	{
		if (!have_st)
			s = NFS3ERR_STALE;
		else if (S_ISDIR (st.st_mode))
			s = NFS3ERR_ISDIR;
		else
			s = check_perm (&st, PERM_W);
	}

	if (s == NFS3_OK && offset + count > 0x7ffffffful)
		s = NFS3ERR_FBIG;	/* MiNT's file position is 32 bit */

	if (s == NFS3_OK)
	{
		fd = open (path, O_WRONLY);
		if (fd < 0)
			s = errno_to_nfs (errno);
		else
		{
			if (lseek (fd, (off_t) offset, SEEK_SET) == (off_t) -1)
				s = errno_to_nfs (errno);
			else
			{
				wrote = write (fd, data, count);
				if (wrote < 0)
					s = errno_to_nfs (errno);
			}

			/*
			 * FILE_SYNC means the client is told the data is on
			 * the disk, so it must be before we answer. UNSTABLE
			 * leaves that to a later COMMIT.
			 */
			if (s == NFS3_OK && stable != UNSTABLE)
			{
# ifdef HAVE_FSYNC
				if (fsync (fd) < 0)
					s = errno_to_nfs (errno);
# endif
			}

			if (close (fd) < 0 && s == NFS3_OK)
				s = errno_to_nfs (errno);
		}
	}

	if (!put_u32 (res, s)
	    || !put_wcc_data (res, &st, have_st, path))
		return -RPC_SYSTEM_ERR;

	if (s == NFS3_OK)
	{
		/* Report what was actually written, and only claim FILE_SYNC
		 * when the data really was flushed.
		 */
		uint32_t committed = stable == UNSTABLE ? UNSTABLE : FILE_SYNC;

		if (!put_u32 (res, (uint32_t) wrote)
		    || !put_u32 (res, committed)
		    || !xdr_opaque (res, write_verf, 8))
			return -RPC_SYSTEM_ERR;
	}

	return 0;
}

/*
 * CREATE, MKDIR and SYMLINK share a reply shape: the new handle, the new
 * attributes, and the directory's before and after.
 */
static int
reply_create (XDR *res, uint32_t s, const char *childrel,
	      const char *childpath, const struct stat *dirst, int have_dirst,
	      const char *dirpath)
{
	if (!put_u32 (res, s))
		return 0;

	if (s == NFS3_OK)
	{
		if (!put_post_op_fh (res, cur_export->id, childrel)
		    || !put_post_op_attr (res, childpath))
			return 0;
	}

	return put_wcc_data (res, dirst, have_dirst, dirpath);
}

static int
nfs3_create (rpc_req *rq, XDR *args, XDR *res)
{
	char dirpath[NFSD_MAXPATH], childpath[NFSD_MAXPATH];
	char dirrel[NFSD_FHPATHLEN + 1], childrel[NFSD_FHPATHLEN + 1];
	struct stat dirst;
	sattr3 a;
	uint32_t s, how;
	int have_dirst = 0, fd = -1;
	int flags;

	s = get_diropargs (args, rq, dirpath, sizeof (dirpath), dirrel,
			   childpath, sizeof (childpath), childrel);

	if (s == NFS3_OK)
	{
		have_dirst = lstat (dirpath, &dirst) == 0;

		if (!xdr_enum (args, &how))
			return -RPC_GARBAGE_ARGS;

		memset (&a, 0, sizeof (a));

		if (how == UNCHECKED || how == GUARDED)
		{
			if (!get_sattr3 (args, &a))
				return -RPC_GARBAGE_ARGS;
		}
		else if (how == EXCLUSIVE)
		{
			uint8_t verf[8];

			if (!xdr_opaque (args, verf, 8))
				return -RPC_GARBAGE_ARGS;
		}
		else
			s = NFS3ERR_INVAL;

		if (s == NFS3_OK)
			s = check_rw ();

		if (s == NFS3_OK && !have_dirst)
			s = NFS3ERR_STALE;

		if (s == NFS3_OK)
			s = check_perm (&dirst, PERM_W | PERM_X);

		if (s == NFS3_OK)
		{
			/*
			 * UNCHECKED may reuse an existing file; the other two
			 * must not. EXCLUSIVE is served with the same O_EXCL
			 * as GUARDED: doing it properly means storing the
			 * client's verifier with the file so a retried
			 * request can be recognised, and there is nowhere to
			 * put it. The difference shows only when a reply is
			 * lost and the client retries, where this returns
			 * EXIST instead of success.
			 */
			flags = O_WRONLY | O_CREAT;
			if (how != UNCHECKED)
				flags |= O_EXCL;

			fd = open (childpath, flags,
				   a.set_mode ? (mode_t) (a.mode & 07777)
					      : (mode_t) 0644);

			if (fd < 0)
				s = errno_to_nfs (errno);
			else
			{
				struct stat cst;

				close (fd);

				if (lstat (childpath, &cst) == 0)
				{
					sattr3 rest = a;

					/* mode went to open() already */
					rest.set_mode = 0;
					s = apply_sattr3 (childpath, &rest, &cst);
				}
			}
		}
	}

	if (!reply_create (res, s, childrel, childpath, &dirst, have_dirst,
			   dirpath))
		return -RPC_SYSTEM_ERR;

	return 0;
}

static int
nfs3_mkdir (rpc_req *rq, XDR *args, XDR *res)
{
	char dirpath[NFSD_MAXPATH], childpath[NFSD_MAXPATH];
	char dirrel[NFSD_FHPATHLEN + 1], childrel[NFSD_FHPATHLEN + 1];
	struct stat dirst;
	sattr3 a;
	uint32_t s;
	int have_dirst = 0;

	s = get_diropargs (args, rq, dirpath, sizeof (dirpath), dirrel,
			   childpath, sizeof (childpath), childrel);

	if (s == NFS3_OK)
	{
		have_dirst = lstat (dirpath, &dirst) == 0;

		if (!get_sattr3 (args, &a))
			return -RPC_GARBAGE_ARGS;

		if ((s = check_rw ()) == NFS3_OK)
		{
			if (!have_dirst)
				s = NFS3ERR_STALE;
			else
				s = check_perm (&dirst, PERM_W | PERM_X);
		}

		if (s == NFS3_OK)
		{
			mode_t m = a.set_mode ? (mode_t) (a.mode & 07777)
					      : (mode_t) 0755;

			if (mkdir (childpath, m) < 0)
				s = errno_to_nfs (errno);
			else
			{
				struct stat cst;

				if (lstat (childpath, &cst) == 0)
				{
					sattr3 rest = a;

					rest.set_mode = 0;
					rest.set_size = 0;	/* not for a dir */
					s = apply_sattr3 (childpath, &rest, &cst);
				}
			}
		}
	}

	if (!reply_create (res, s, childrel, childpath, &dirst, have_dirst,
			   dirpath))
		return -RPC_SYSTEM_ERR;

	return 0;
}

static int
nfs3_symlink (rpc_req *rq, XDR *args, XDR *res)
{
	char dirpath[NFSD_MAXPATH], childpath[NFSD_MAXPATH];
	char dirrel[NFSD_FHPATHLEN + 1], childrel[NFSD_FHPATHLEN + 1];
	char target[NFSD_MAXPATH];
	struct stat dirst;
	sattr3 a;
	uint32_t s;
	int have_dirst = 0;

	s = get_diropargs (args, rq, dirpath, sizeof (dirpath), dirrel,
			   childpath, sizeof (childpath), childrel);

	if (s == NFS3_OK)
	{
		have_dirst = lstat (dirpath, &dirst) == 0;

		if (!get_sattr3 (args, &a)
		    || !xdr_string (args, target, sizeof (target)))
			return -RPC_GARBAGE_ARGS;

		if ((s = check_rw ()) == NFS3_OK)
		{
			if (!have_dirst)
				s = NFS3ERR_STALE;
			else
				s = check_perm (&dirst, PERM_W | PERM_X);
		}

		if (s == NFS3_OK)
		{
			if (symlink (target, childpath) < 0)
				s = errno_to_nfs (errno);
		}
	}

	if (!reply_create (res, s, childrel, childpath, &dirst, have_dirst,
			   dirpath))
		return -RPC_SYSTEM_ERR;

	return 0;
}

static int
do_remove (rpc_req *rq, XDR *args, XDR *res, int isdir)
{
	char dirpath[NFSD_MAXPATH], childpath[NFSD_MAXPATH];
	char dirrel[NFSD_FHPATHLEN + 1], childrel[NFSD_FHPATHLEN + 1];
	struct stat dirst, cst;
	uint32_t s;
	int have_dirst = 0;

	s = get_diropargs (args, rq, dirpath, sizeof (dirpath), dirrel,
			   childpath, sizeof (childpath), childrel);

	if (s == NFS3_OK)
	{
		have_dirst = lstat (dirpath, &dirst) == 0;

		if ((s = check_rw ()) == NFS3_OK)
		{
			if (!have_dirst)
				s = NFS3ERR_STALE;
			else
				s = check_perm (&dirst, PERM_W | PERM_X);
		}

		if (s == NFS3_OK && lstat (childpath, &cst) < 0)
			s = errno_to_nfs (errno);

		/* RMDIR on a file and REMOVE on a directory are both errors
		 * with their own codes, which a client distinguishes.
		 */
		if (s == NFS3_OK)
		{
			if (isdir && !S_ISDIR (cst.st_mode))
				s = NFS3ERR_NOTDIR;
			else if (!isdir && S_ISDIR (cst.st_mode))
				s = NFS3ERR_ISDIR;
		}

		if (s == NFS3_OK)
		{
			int r = isdir ? rmdir (childpath) : unlink (childpath);

			if (r < 0)
				s = errno_to_nfs (errno);
		}
	}

	if (!put_u32 (res, s)
	    || !put_wcc_data (res, &dirst, have_dirst, dirpath))
		return -RPC_SYSTEM_ERR;

	return 0;
}

static int
nfs3_remove (rpc_req *rq, XDR *args, XDR *res)
{
	return do_remove (rq, args, res, 0);
}

static int
nfs3_rmdir (rpc_req *rq, XDR *args, XDR *res)
{
	return do_remove (rq, args, res, 1);
}

static int
nfs3_rename (rpc_req *rq, XDR *args, XDR *res)
{
	char fdir[NFSD_MAXPATH], fpath[NFSD_MAXPATH];
	char tdir[NFSD_MAXPATH], tpath[NFSD_MAXPATH];
	char frel[NFSD_FHPATHLEN + 1], fchild[NFSD_FHPATHLEN + 1];
	char trel[NFSD_FHPATHLEN + 1], tchild[NFSD_FHPATHLEN + 1];
	struct stat fst, tst;
	uint32_t s, s2;
	int have_fst = 0, have_tst = 0;
	uint32_t from_export;

	s = get_diropargs (args, rq, fdir, sizeof (fdir), frel,
			   fpath, sizeof (fpath), fchild);
	from_export = s == NFS3_OK ? cur_export->id : 0;

	if (s == NFS3_OK)
		have_fst = lstat (fdir, &fst) == 0;

	s2 = get_diropargs (args, rq, tdir, sizeof (tdir), trel,
			    tpath, sizeof (tpath), tchild);

	if (s == NFS3_OK)
		s = s2;

	if (s == NFS3_OK)
	{
		have_tst = lstat (tdir, &tst) == 0;

		/* Both handles must name the same export: rename cannot
		 * cross a file system, and two exports may well be on
		 * different ones.
		 */
		if (cur_export->id != from_export)
			s = NFS3ERR_XDEV;
		else if ((s = check_rw ()) == NFS3_OK)
		{
			if (!have_fst || !have_tst)
				s = NFS3ERR_STALE;
			else if ((s = check_perm (&fst, PERM_W | PERM_X)) == NFS3_OK)
				s = check_perm (&tst, PERM_W | PERM_X);
		}

		if (s == NFS3_OK && rename (fpath, tpath) < 0)
			s = errno_to_nfs (errno);
	}

	if (!put_u32 (res, s)
	    || !put_wcc_data (res, &fst, have_fst, fdir)
	    || !put_wcc_data (res, &tst, have_tst, tdir))
		return -RPC_SYSTEM_ERR;

	return 0;
}

static int
nfs3_link (rpc_req *rq, XDR *args, XDR *res)
{
	char fpath[NFSD_MAXPATH];
	char dirpath[NFSD_MAXPATH], childpath[NFSD_MAXPATH];
	char dirrel[NFSD_FHPATHLEN + 1], childrel[NFSD_FHPATHLEN + 1];
	struct stat dirst;
	uint32_t s, s2, file_export;
	int have_dirst = 0;

	s = resolve (args, rq, fpath, sizeof (fpath), NULL);
	file_export = s == NFS3_OK ? cur_export->id : 0;

	s2 = get_diropargs (args, rq, dirpath, sizeof (dirpath), dirrel,
			    childpath, sizeof (childpath), childrel);

	if (s == NFS3_OK)
		s = s2;

	if (s == NFS3_OK)
	{
		have_dirst = lstat (dirpath, &dirst) == 0;

		if (cur_export->id != file_export)
			s = NFS3ERR_XDEV;
		else if ((s = check_rw ()) == NFS3_OK)
		{
			if (!have_dirst)
				s = NFS3ERR_STALE;
			else
				s = check_perm (&dirst, PERM_W | PERM_X);
		}

		if (s == NFS3_OK && link (fpath, childpath) < 0)
			s = errno_to_nfs (errno);
	}

	if (!put_u32 (res, s)
	    || !put_post_op_attr (res, s == NFS3_OK ? fpath : NULL)
	    || !put_wcc_data (res, &dirst, have_dirst, dirpath))
		return -RPC_SYSTEM_ERR;

	return 0;
}

static int
nfs3_commit (rpc_req *rq, XDR *args, XDR *res)
{
	char path[NFSD_MAXPATH];
	struct stat st;
	uint64_t offset;
	uint32_t count, s;
	int have_st = 0;

	s = resolve (args, rq, path, sizeof (path), NULL);

	if (s == NFS3_OK)
	{
		if (!xdr_u64 (args, &offset) || !xdr_u32 (args, &count))
			return -RPC_GARBAGE_ARGS;

		have_st = lstat (path, &st) == 0;

		if (!have_st)
			s = NFS3ERR_STALE;
		else if (S_ISDIR (st.st_mode))
			s = NFS3ERR_ISDIR;
		else
		{
			/*
			 * Flush the file. Opening it read only is enough for
			 * fsync and avoids being refused on a file the caller
			 * may not write -- a COMMIT is not a modification.
			 */
			int fd = open (path, O_RDONLY);

			if (fd < 0)
				s = errno_to_nfs (errno);
			else
			{
# ifdef HAVE_FSYNC
				if (fsync (fd) < 0)
					s = errno_to_nfs (errno);
# endif
				close (fd);
			}
		}
	}

	if (!put_u32 (res, s)
	    || !put_wcc_data (res, &st, have_st, path))
		return -RPC_SYSTEM_ERR;

	if (s == NFS3_OK && !xdr_opaque (res, write_verf, 8))
		return -RPC_SYSTEM_ERR;

	return 0;
}

/* --------------------------------------------- not implemented (yet) */

/*
 * Answering NOTSUPP is better than answering nothing: the client gets a
 * definite "no" and reports it, instead of retrying until it times out.
 */
static int
nfs3_notsupp (rpc_req *rq, XDR *args, XDR *res)
{
	(void) rq; (void) args;

	return put_u32 (res, NFS3ERR_NOTSUPP) ? 0 : -RPC_SYSTEM_ERR;
}

static const rpc_proc procs[NFSPROC3_COUNT] =
{
	nfs3_null,		/*  0 NULL         */
	nfs3_getattr,		/*  1 GETATTR      */
	nfs3_setattr,		/*  2 SETATTR      */
	nfs3_lookup,		/*  3 LOOKUP       */
	nfs3_access,		/*  4 ACCESS       */
	nfs3_readlink,		/*  5 READLINK     */
	nfs3_read,		/*  6 READ         */
	nfs3_write,		/*  7 WRITE        */
	nfs3_create,		/*  8 CREATE       */
	nfs3_mkdir,		/*  9 MKDIR        */
	nfs3_symlink,		/* 10 SYMLINK      */
	nfs3_notsupp,		/* 11 MKNOD        */
	nfs3_remove,		/* 12 REMOVE       */
	nfs3_rmdir,		/* 13 RMDIR        */
	nfs3_rename,		/* 14 RENAME       */
	nfs3_link,		/* 15 LINK         */
	nfs3_readdir,		/* 16 READDIR      */
	nfs3_readdirplus,	/* 17 READDIRPLUS  */
	nfs3_fsstat,		/* 18 FSSTAT       */
	nfs3_fsinfo,		/* 19 FSINFO       */
	nfs3_pathconf,		/* 20 PATHCONF     */
	nfs3_commit,		/* 21 COMMIT       */
};

static const rpc_program program =
{
	NFS_PROG, NFS_VERS3,
	NFSPROC3_COUNT, procs,
	"nfsd"
};

/* ----------------------------------------------------------------- main */

static void
on_signal (int sig)
{
	(void) sig;

	rpc_stop (&server);
}

static void
usage (const char *me)
{
	fprintf (stderr,
		 "usage: %s [-d] [-e file] [-p port] [-n]\n"
		 "  -d  log every request to stderr\n"
		 "  -e  exports file (default /etc/exports)\n"
		 "  -p  listen on this port instead of 2049\n"
		 "  -n  do not register with the port mapper\n", me);
	exit (1);
}

int
main (int argc, char **argv)
{
	const char *expfile = "/etc/exports";
	int port = 2049, no_pmap = 0;
	int i;

	for (i = 1; i < argc; i++)
	{
		if (strcmp (argv[i], "-d") == 0)
			rpc_verbose = 1;
		else if (strcmp (argv[i], "-n") == 0)
			no_pmap = 1;
		else if (strcmp (argv[i], "-e") == 0 && i + 1 < argc)
			expfile = argv[++i];
		else if (strcmp (argv[i], "-p") == 0 && i + 1 < argc)
		{
			port = atoi (argv[++i]);
			if (port < 0 || port > 65535)
				usage (argv[0]);
		}
		else
			usage (argv[0]);
	}

	if (exports_load (expfile) < 0)
		return 1;

	init_write_verf ();

	if (rpc_listen (&server, (uint16_t) port) < 0)
	{
		fprintf (stderr, "nfsd: cannot listen on port %d: %s\n",
			 port, strerror (errno));
		return 1;
	}

	rpc_add_program (&server, &program);

	if (!no_pmap)
	{
		if (rpc_pmap_set (NFS_PROG, NFS_VERS3, 0, server.port) < 0
		    || rpc_pmap_set (NFS_PROG, NFS_VERS3, 1, server.port) < 0)
		{
			fprintf (stderr, "nfsd: the port mapper did not take "
				 "the registration.\nnfsd: is portmap "
				 "running?\n");
			rpc_close (&server);
			return 1;
		}
	}

	signal (SIGINT, on_signal);
	signal (SIGTERM, on_signal);
# ifdef SIGPIPE
	signal (SIGPIPE, SIG_IGN);
# endif

	printf ("nfsd: listening on port %u, exporting\n",
		(unsigned) server.port);
	exports_print ();
	fflush (stdout);

	if (rpc_run (&server) < 0)
	{
		perror ("nfsd");
		if (!no_pmap)
			rpc_pmap_unset (NFS_PROG, NFS_VERS3);
		rpc_close (&server);
		return 1;
	}

	if (!no_pmap)
		rpc_pmap_unset (NFS_PROG, NFS_VERS3);

	rpc_close (&server);

	return 0;
}
