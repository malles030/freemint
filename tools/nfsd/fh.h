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
 * fh.h -- NFSv3 file handles.
 *
 * A handle is an opaque blob, up to 64 bytes, that the client keeps and
 * hands back for every later operation on that file. The server has to be
 * able to turn it back into a file, and it must keep working across a
 * server restart, or every client gets ESTALE and has to remount.
 *
 * Linux builds its handles from the device number, the inode number and an
 * inode generation count, then relies on the kernel's ability to find a file
 * by inode. Userspace has no such ability: there is no portable way to go
 * from an inode number back to a path. The classic userspace servers work
 * around it with a cache of handles they have issued, which has to be
 * persisted or the restart problem comes back.
 *
 * This server puts the path itself in the handle. That makes it stateless:
 * nothing to cache, nothing to persist, nothing to go stale across a
 * restart, and no table to size on a machine with 4 MB. The price is a limit
 * on how deep inside an export a file can sit, which NFSD_FHPATHLEN sets.
 * On an Atari, where paths are short, that is a reasonable trade; the limit
 * is reported honestly as NFS3ERR_NAMETOOLONG rather than silently failing.
 *
 * Because the path travels through the client, it comes back under the
 * client's control, so fh_decode treats it as hostile input. A handle naming
 * "../../etc" must not escape the export. There is no cryptographic check
 * and none is needed: validation confines a decoded handle to the export it
 * names, and inside that export the client could reach the same file with
 * LOOKUP anyway. A keyed checksum would add a secret that itself would have
 * to survive restarts, buying nothing.
 */

# ifndef _nfsd_fh_h
# define _nfsd_fh_h

# include "config.h"
# include "xdr.h"

/*
 * 4 + 2 + 2 + 56 = 64, which is the NFSv3 maximum. Keep it exactly there:
 * a shorter handle saves nothing on the wire that matters, and the room is
 * better spent on path depth.
 */
# define FH_MAGIC	0x4d4e4633ul		/* "MNF3" */

# define FH_SIZE	(4 + 2 + 2 + NFSD_FHPATHLEN)

typedef struct
{
	uint32_t	exportid;
	char		path[NFSD_FHPATHLEN + 1];	/* relative, '/' separated,
							 * "" is the export root */
} nfsd_fh;

/*
 * Build the wire form. Returns 0, or -1 when the path does not fit, which
 * the caller turns into NFS3ERR_NAMETOOLONG.
 */
int	fh_encode	(uint8_t *out, uint32_t exportid, const char *relpath);

/*
 * Take the wire form apart, rejecting anything that is not a handle we
 * issued or that names a path outside its export. Returns 0, or -1.
 */
int	fh_decode	(const uint8_t *in, uint32_t len, nfsd_fh *fh);

/*
 * Join a relative path and a single component, the way LOOKUP needs.
 * Returns 0, or -1 if the result would not fit in a handle.
 */
int	fh_child	(char *out, size_t outsz, const char *parent,
			 const char *name);

/*
 * Strip the last component, for LOOKUP of "..". The export root's parent is
 * itself, which is what keeps ".." at the top of an export from escaping.
 */
void	fh_parent	(char *path);

/*
 * Is this a component a client may name? Rejects "", ".", "..", anything
 * holding a '/' or a backslash, and anything too long. The backslash matters
 * on MiNT, where it is also a separator.
 */
int	fh_name_ok	(const char *name);

# endif /* _nfsd_fh_h */
