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
 * xdr.c -- see xdr.h
 *
 * Values are moved byte by byte rather than through a cast to a wider type.
 * XDR is big endian, which matches the 68000 but not the host this gets
 * tested on, and a 4 byte field in an RPC record is not guaranteed to sit
 * on a 4 byte boundary once variable length opaques are in play -- the
 * 68000 would fault on the misaligned access that works on x86.
 */

# include "xdr.h"

# include <string.h>

void
xdr_init (XDR *x, void *buf, size_t len, int op)
{
	x->buf = (uint8_t *) buf;
	x->len = len;
	x->pos = 0;
	x->op  = op;
	x->err = 0;
}

size_t
xdr_pos (const XDR *x)
{
	return x->pos;
}

int
xdr_ok (const XDR *x)
{
	return x->err == 0;
}

/*
 * Claim n bytes of the stream and return where they start, or NULL when
 * that would run past the end. Also the one place the sticky error is set.
 */
static uint8_t *
take (XDR *x, size_t n)
{
	uint8_t *p;

	if (x->err)
		return NULL;

	if (n > x->len || x->pos > x->len - n)
	{
		x->err = 1;
		return NULL;
	}

	p = x->buf + x->pos;
	x->pos += n;

	return p;
}

int
xdr_skip (XDR *x, size_t n)
{
	size_t pad = XDR_ROUNDUP (n);
	uint8_t *p = take (x, pad);

	if (!p)
		return 0;

	if (x->op == XDR_ENCODE)
		memset (p, 0, pad);

	return 1;
}

int
xdr_u32 (XDR *x, uint32_t *v)
{
	uint8_t *p = take (x, 4);

	if (!p)
		return 0;

	if (x->op == XDR_ENCODE)
	{
		p[0] = (uint8_t) (*v >> 24);
		p[1] = (uint8_t) (*v >> 16);
		p[2] = (uint8_t) (*v >> 8);
		p[3] = (uint8_t) (*v);
	}
	else
		*v = ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
		   | ((uint32_t) p[2] << 8)  | ((uint32_t) p[3]);

	return 1;
}

int
xdr_i32 (XDR *x, int32_t *v)
{
	uint32_t u = (uint32_t) *v;

	if (!xdr_u32 (x, &u))
		return 0;

	if (x->op == XDR_DECODE)
		*v = (int32_t) u;

	return 1;
}

int
xdr_u64 (XDR *x, uint64_t *v)
{
	uint32_t hi, lo;

	if (x->op == XDR_ENCODE)
	{
		hi = (uint32_t) (*v >> 32);
		lo = (uint32_t) (*v);

		return xdr_u32 (x, &hi) && xdr_u32 (x, &lo);
	}

	if (!xdr_u32 (x, &hi) || !xdr_u32 (x, &lo))
		return 0;

	*v = ((uint64_t) hi << 32) | (uint64_t) lo;

	return 1;
}

int
xdr_i64 (XDR *x, int64_t *v)
{
	uint64_t u = (uint64_t) *v;

	if (!xdr_u64 (x, &u))
		return 0;

	if (x->op == XDR_DECODE)
		*v = (int64_t) u;

	return 1;
}

int
xdr_bool (XDR *x, uint32_t *v)
{
	if (!xdr_u32 (x, v))
		return 0;

	/* RFC 4506: a boolean is 0 or 1 and nothing else. Letting anything
	 * non-zero through would make a discriminated union take a branch
	 * the sender did not mean.
	 */
	if (x->op == XDR_DECODE && *v > 1)
	{
		x->err = 1;
		return 0;
	}

	return 1;
}

int
xdr_enum (XDR *x, uint32_t *v)
{
	return xdr_u32 (x, v);
}

int
xdr_opaque (XDR *x, void *v, size_t n)
{
	size_t pad = XDR_ROUNDUP (n);
	uint8_t *p = take (x, pad);

	if (!p)
		return 0;

	if (x->op == XDR_ENCODE)
	{
		memcpy (p, v, n);
		if (pad > n)
			memset (p + n, 0, pad - n);
	}
	else
		memcpy (v, p, n);

	return 1;
}

int
xdr_bytes (XDR *x, uint8_t **pp, uint32_t *lenp, uint32_t maxlen)
{
	uint32_t n;
	uint8_t *p;
	size_t pad;

	if (x->op == XDR_ENCODE)
	{
		n = *lenp;
		if (n > maxlen)
		{
			x->err = 1;
			return 0;
		}

		if (!xdr_u32 (x, &n))
			return 0;

		pad = XDR_ROUNDUP (n);
		p = take (x, pad);
		if (!p)
			return 0;

		memcpy (p, *pp, n);
		if (pad > n)
			memset (p + n, 0, pad - n);

		return 1;
	}

	if (!xdr_u32 (x, &n))
		return 0;

	if (n > maxlen)
	{
		x->err = 1;
		return 0;
	}

	pad = XDR_ROUNDUP (n);
	p = take (x, pad);
	if (!p)
		return 0;

	*pp = p;		/* points into the stream, no copy */
	*lenp = n;

	return 1;
}

int
xdr_string (XDR *x, char *dst, size_t dstsz)
{
	uint8_t *p;
	uint32_t n;

	if (dstsz == 0)
	{
		x->err = 1;
		return 0;
	}

	if (x->op == XDR_ENCODE)
	{
		n = (uint32_t) strlen (dst);
		p = (uint8_t *) dst;

		return xdr_bytes (x, &p, &n, (uint32_t) (dstsz - 1));
	}

	if (!xdr_bytes (x, &p, &n, (uint32_t) (dstsz - 1)))
		return 0;

	memcpy (dst, p, n);
	dst[n] = '\0';

	/* A name with an embedded NUL would mean one thing on the wire and
	 * something shorter to every path call here, so refuse it.
	 */
	if (strlen (dst) != n)
	{
		x->err = 1;
		return 0;
	}

	return 1;
}
