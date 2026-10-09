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
 * nfs3.h -- the constants of NFS version 3, RFC 1813.
 *
 * Only the numbers. The encoders live in nfsd.c, where they can be written
 * against the one XDR stream the server uses.
 */

# ifndef _nfsd_nfs3_h
# define _nfsd_nfs3_h

# define NFS_PROG		100003ul
# define NFS_VERS3		3ul

/* procedures */
# define NFSPROC3_NULL		0
# define NFSPROC3_GETATTR	1
# define NFSPROC3_SETATTR	2
# define NFSPROC3_LOOKUP	3
# define NFSPROC3_ACCESS	4
# define NFSPROC3_READLINK	5
# define NFSPROC3_READ		6
# define NFSPROC3_WRITE		7
# define NFSPROC3_CREATE	8
# define NFSPROC3_MKDIR		9
# define NFSPROC3_SYMLINK	10
# define NFSPROC3_MKNOD		11
# define NFSPROC3_REMOVE	12
# define NFSPROC3_RMDIR		13
# define NFSPROC3_RENAME	14
# define NFSPROC3_LINK		15
# define NFSPROC3_READDIR	16
# define NFSPROC3_READDIRPLUS	17
# define NFSPROC3_FSSTAT	18
# define NFSPROC3_FSINFO	19
# define NFSPROC3_PATHCONF	20
# define NFSPROC3_COMMIT	21
# define NFSPROC3_COUNT		22

/* nfsstat3 */
# define NFS3_OK		0
# define NFS3ERR_PERM		1
# define NFS3ERR_NOENT		2
# define NFS3ERR_IO		5
# define NFS3ERR_NXIO		6
# define NFS3ERR_ACCES		13
# define NFS3ERR_EXIST		17
# define NFS3ERR_XDEV		18
# define NFS3ERR_NODEV		19
# define NFS3ERR_NOTDIR		20
# define NFS3ERR_ISDIR		21
# define NFS3ERR_INVAL		22
# define NFS3ERR_FBIG		27
# define NFS3ERR_NOSPC		28
# define NFS3ERR_ROFS		30
# define NFS3ERR_MLINK		31
# define NFS3ERR_NAMETOOLONG	63
# define NFS3ERR_NOTEMPTY	66
# define NFS3ERR_DQUOT		69
# define NFS3ERR_STALE		70
# define NFS3ERR_REMOTE		71
# define NFS3ERR_BADHANDLE	10001ul
# define NFS3ERR_NOT_SYNC	10002ul
# define NFS3ERR_BAD_COOKIE	10003ul
# define NFS3ERR_NOTSUPP	10004ul
# define NFS3ERR_TOOSMALL	10005ul
# define NFS3ERR_SERVERFAULT	10006ul
# define NFS3ERR_BADTYPE	10007ul
# define NFS3ERR_JUKEBOX	10008ul

/* ftype3 */
# define NF3REG			1
# define NF3DIR			2
# define NF3BLK			3
# define NF3CHR			4
# define NF3LNK			5
# define NF3SOCK		6
# define NF3FIFO		7

/* ACCESS3 bits */
# define ACCESS3_READ		0x0001
# define ACCESS3_LOOKUP		0x0002
# define ACCESS3_MODIFY		0x0004
# define ACCESS3_EXTEND		0x0008
# define ACCESS3_DELETE		0x0010
# define ACCESS3_EXECUTE	0x0020

/* stable_how for WRITE */
# define UNSTABLE		0
# define DATA_SYNC		1
# define FILE_SYNC		2

/* createmode3 */
# define UNCHECKED		0
# define GUARDED		1
# define EXCLUSIVE		2

/* time_how, the discriminator of sattr3's time fields */
# define DONT_CHANGE		0
# define SET_TO_SERVER_TIME	1
# define SET_TO_CLIENT_TIME	2

/* FSINFO3 properties */
# define FSF3_LINK		0x0001
# define FSF3_SYMLINK		0x0002
# define FSF3_HOMOGENEOUS	0x0008
# define FSF3_CANSETTIME	0x0010

/*
 * The NFSv3 epoch is the Unix one, and nfstime3 is seconds plus
 * nanoseconds, both unsigned 32 bit.
 */

# endif /* _nfsd_nfs3_h */
