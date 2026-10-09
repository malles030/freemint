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
 * t_xdr.c -- tests for the XDR core. Built and run on the host.
 *
 *   cc -o t_xdr t_xdr.c xdr.c && ./t_xdr
 *
 * Checks the things that actually go wrong: byte order (XDR is big endian,
 * the test host is not), the padding of lengths that are not a multiple of
 * four, misaligned access, and whether a bad length from the peer is
 * refused rather than read past the end of the buffer.
 */

# include "xdr.h"

# include <stdio.h>
# include <string.h>

static int fails = 0;
static int checks = 0;

static void
ok (int cond, const char *what)
{
	checks++;
	if (!cond)
	{
		printf ("  FAIL  %s\n", what);
		fails++;
	}
}

static void
test_byte_order (void)
{
	uint8_t b[4];
	XDR x;
	uint32_t v = 0x01020304ul;

	xdr_init (&x, b, sizeof (b), XDR_ENCODE);
	ok (xdr_u32 (&x, &v), "u32 encodes");
	ok (b[0] == 1 && b[1] == 2 && b[2] == 3 && b[3] == 4,
	    "u32 is big endian on the wire");
	ok (xdr_pos (&x) == 4, "u32 advances four bytes");
}

static void
test_round_trip (void)
{
	uint8_t b[64];
	XDR x;
	uint32_t u = 0xdeadbeeful, u2 = 0;
	int32_t  i = -12345, i2 = 0;
	uint64_t q = 0x0102030405060708ull, q2 = 0;
	int64_t  s = -1099511627776ll, s2 = 0;

	xdr_init (&x, b, sizeof (b), XDR_ENCODE);
	xdr_u32 (&x, &u);
	xdr_i32 (&x, &i);
	xdr_u64 (&x, &q);
	xdr_i64 (&x, &s);
	ok (xdr_ok (&x), "mixed encode succeeds");
	ok (xdr_pos (&x) == 4 + 4 + 8 + 8, "sizes add up");

	xdr_init (&x, b, sizeof (b), XDR_DECODE);
	xdr_u32 (&x, &u2);
	xdr_i32 (&x, &i2);
	xdr_u64 (&x, &q2);
	xdr_i64 (&x, &s2);
	ok (xdr_ok (&x), "mixed decode succeeds");
	ok (u2 == u, "u32 round trips");
	ok (i2 == i, "i32 round trips, sign kept");
	ok (q2 == q, "u64 round trips");
	ok (s2 == s, "i64 round trips, sign kept");
}

static void
test_u64_halves (void)
{
	/* The high word comes first; getting this backwards is the classic
	 * NFSv3 bug, and it only shows up above 4 GB.
	 */
	uint8_t b[8];
	XDR x;
	uint64_t v = 0x00000001FFFFFFFFull;

	xdr_init (&x, b, sizeof (b), XDR_ENCODE);
	xdr_u64 (&x, &v);
	ok (b[3] == 0x01, "u64 high word first");
	ok (b[4] == 0xFF && b[7] == 0xFF, "u64 low word second");
}

static void
test_padding (void)
{
	uint8_t b[32];
	uint8_t data[5] = { 'h', 'e', 'l', 'l', 'o' };
	uint8_t *p;
	uint32_t n = 5;
	XDR x;

	p = data;
	n = 5;
	xdr_init (&x, b, sizeof (b), XDR_ENCODE);
	ok (xdr_bytes (&x, &p, &n, 16), "5 byte opaque encodes");
	ok (xdr_pos (&x) == 4 + 8, "5 bytes occupy 8, padded");
	ok (b[9] == 0 && b[10] == 0 && b[11] == 0, "padding is zeroed");

	xdr_init (&x, b, xdr_pos (&x), XDR_DECODE);
	ok (xdr_bytes (&x, &p, &n, 16), "5 byte opaque decodes");
	ok (n == 5, "length survives");
	ok (memcmp (p, data, 5) == 0, "content survives");
}

static void
test_string (void)
{
	uint8_t b[64];
	char s[32];
	XDR x;

	strcpy (s, "autoexec.bat");
	xdr_init (&x, b, sizeof (b), XDR_ENCODE);
	ok (xdr_string (&x, s, sizeof (s)), "string encodes");

	memset (s, 0, sizeof (s));
	xdr_init (&x, b, xdr_pos (&x), XDR_DECODE);
	ok (xdr_string (&x, s, sizeof (s)), "string decodes");
	ok (strcmp (s, "autoexec.bat") == 0, "string round trips");
}

static void
test_bounds (void)
{
	uint8_t b[8];
	XDR x;
	uint32_t v = 0;

	/* Two u32 fit, the third must not. */
	xdr_init (&x, b, sizeof (b), XDR_ENCODE);
	ok (xdr_u32 (&x, &v), "first u32 fits");
	ok (xdr_u32 (&x, &v), "second u32 fits");
	ok (!xdr_u32 (&x, &v), "third u32 is refused");
	ok (!xdr_ok (&x), "error is recorded");
	ok (!xdr_u32 (&x, &v), "error is sticky");
}

static void
test_hostile_length (void)
{
	/* A peer claims a 4 GB opaque in an 8 byte record. Reading it must
	 * fail, not walk off the buffer.
	 */
	uint8_t b[8];
	XDR x;
	uint8_t *p;
	uint32_t n;

	memset (b, 0xff, sizeof (b));
	xdr_init (&x, b, sizeof (b), XDR_DECODE);
	ok (!xdr_bytes (&x, &p, &n, 0xffffffful), "absurd length refused");
	ok (!xdr_ok (&x), "and recorded");

	/* And one that passes maxlen but still exceeds the buffer. */
	b[0] = 0; b[1] = 0; b[2] = 0; b[3] = 100;
	xdr_init (&x, b, sizeof (b), XDR_DECODE);
	ok (!xdr_bytes (&x, &p, &n, 1024), "length past the buffer refused");
}

static void
test_bool (void)
{
	uint8_t b[4];
	XDR x;
	uint32_t v;

	b[0] = 0; b[1] = 0; b[2] = 0; b[3] = 2;
	xdr_init (&x, b, sizeof (b), XDR_DECODE);
	ok (!xdr_bool (&x, &v), "bool of 2 is refused");

	b[3] = 1;
	xdr_init (&x, b, sizeof (b), XDR_DECODE);
	ok (xdr_bool (&x, &v) && v == 1, "bool of 1 is accepted");
}

static void
test_misaligned (void)
{
	/* After a 5 byte opaque plus its length the stream sits at offset 12,
	 * but start the buffer at an odd address and every field inside is
	 * misaligned. A cast to uint32_t* would fault on a 68000; the byte
	 * loop must not care.
	 */
	uint8_t raw[64];
	uint8_t *b = raw + 1;
	XDR x;
	uint32_t v = 0x11223344ul, v2 = 0;

	xdr_init (&x, b, 32, XDR_ENCODE);
	ok (xdr_u32 (&x, &v), "u32 at an odd address encodes");

	xdr_init (&x, b, 32, XDR_DECODE);
	ok (xdr_u32 (&x, &v2) && v2 == v, "and decodes to the same value");
}

int
main (void)
{
	printf ("xdr core\n");

	test_byte_order ();
	test_round_trip ();
	test_u64_halves ();
	test_padding ();
	test_string ();
	test_bounds ();
	test_hostile_length ();
	test_bool ();
	test_misaligned ();

	printf ("%d checks, %d failed\n", checks, fails);

	return fails ? 1 : 0;
}
