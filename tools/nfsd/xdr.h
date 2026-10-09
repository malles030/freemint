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
 * xdr.h -- XDR (RFC 4506) encoding and decoding for the NFS server.
 *
 * Deliberately built on <stdint.h> rather than on `long'. The client driver
 * in sys/xfs/nfs3 uses `long' as its 32 bit unit, which is right inside the
 * kernel, where -mshort makes `int' 16 bits wide. This code has to compile
 * for MiNT userspace (ILP32) and for a 64 bit host, where `long' is 8 bytes
 * and would silently misalign every field. Fixed widths are correct on both,
 * which is also what makes the server testable against a Linux client before
 * it ever runs on an Atari.
 *
 * One stream serves both directions: the same xdr_* call encodes or decodes
 * depending on x->op, so a request type and its reply type need one routine
 * each rather than two.
 *
 * Errors are sticky. A failed call sets x->err and every later call turns
 * into a no-op, so a long chain of fields can be written without testing
 * each one; the caller checks once at the end.
 */

# ifndef _nfsd_xdr_h
# define _nfsd_xdr_h

# include <stdint.h>
# include <stddef.h>

# define XDR_ENCODE	0
# define XDR_DECODE	1

/* Everything in XDR is a multiple of four bytes. */
# define XDR_UNIT	4
# define XDR_ROUNDUP(n)	(((n) + 3) & ~((size_t) 3))

typedef struct
{
	uint8_t *	buf;	/* the buffer being built or read */
	size_t		len;	/* its size: capacity when encoding, the
				 * number of valid bytes when decoding */
	size_t		pos;	/* how far along we are */
	int		op;	/* XDR_ENCODE or XDR_DECODE */
	int		err;	/* sticky; 0 while all is well */
} XDR;

void	xdr_init	(XDR *x, void *buf, size_t len, int op);
size_t	xdr_pos		(const XDR *x);
int	xdr_ok		(const XDR *x);

/* Skip n bytes of padding or an unwanted field. */
int	xdr_skip	(XDR *x, size_t n);

int	xdr_u32		(XDR *x, uint32_t *v);
int	xdr_i32		(XDR *x, int32_t *v);
int	xdr_u64		(XDR *x, uint64_t *v);
int	xdr_i64		(XDR *x, int64_t *v);
int	xdr_bool	(XDR *x, uint32_t *v);
int	xdr_enum	(XDR *x, uint32_t *v);

/*
 * Fixed length opaque: exactly n bytes, padded to a multiple of four.
 */
int	xdr_opaque	(XDR *x, void *p, size_t n);

/*
 * Variable length opaque: a length followed by that many bytes. On decode
 * *lenp is set and *pp points INTO the stream buffer -- no copy is made, so
 * it stays valid only as long as the buffer does. maxlen rejects a length
 * the caller cannot handle, which is what keeps a hostile or broken peer
 * from steering us past the end of the buffer.
 */
int	xdr_bytes	(XDR *x, uint8_t **pp, uint32_t *lenp, uint32_t maxlen);

/*
 * A counted string, same wire form as variable opaque. On decode the result
 * is copied into dst and terminated, because callers want a C string; dstsz
 * includes room for the terminator.
 */
int	xdr_string	(XDR *x, char *dst, size_t dstsz);

# endif /* _nfsd_xdr_h */
