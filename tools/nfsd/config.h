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
 * config.h -- sizes and limits for the FreeMiNT NFS server.
 *
 * Every one of these costs memory on a machine that may have 4 MB, so they
 * are deliberately modest. A client is told the real figures through
 * FSINFO3 and MOUNT, so lowering them here does not break anything; it only
 * makes transfers smaller.
 */

# ifndef _nfsd_config_h
# define _nfsd_config_h

/*
 * The largest READ or WRITE payload, reported to the client as rtmax/wtmax
 * in FSINFO3. 8192 matches what the client driver in sys/xfs/nfs3 settled
 * on, and a Linux client adapts to whatever we announce.
 */
# ifndef NFSD_MAXDATA
#  define NFSD_MAXDATA		8192
# endif

/*
 * One RPC record. Must hold the largest request (a WRITE3 of MAXDATA plus
 * its header) and the largest reply (a READ3 of the same). The slack covers
 * the RPC header, the file handle, the credentials and the attributes.
 */
# define NFSD_MAXRECORD		(NFSD_MAXDATA + 1024)

/*
 * READDIR and READDIRPLUS replies. A client asks for a byte count and we
 * must not exceed it, but we also cap it here so one listing cannot claim
 * the whole heap.
 */
# define NFSD_MAXDIRCOUNT	8192

/* How many exports /etc/exports may define. */
# define NFSD_MAXEXPORTS	8

/*
 * The path inside an export that a file handle can carry. See fh.h: the
 * handle holds the path itself, which keeps the server stateless and lets
 * handles survive a restart, at the cost of a depth limit.
 */
# define NFSD_FHPATHLEN		56

/* Longest absolute path the server will build. */
# define NFSD_MAXPATH		256

/* Longest single component. NFSv3 reports this as name_max in PATHCONF. */
# define NFSD_MAXNAME		64

# endif /* _nfsd_config_h */
