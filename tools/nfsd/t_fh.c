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
 * t_fh.c -- tests for file handle encoding, and above all for the
 *           validation that keeps a handle from naming a file outside its
 *           export.
 *
 *   cc -o t_fh t_fh.c fh.c xdr.c && ./t_fh
 *
 * The handle carries a path and travels through the client, so it comes back
 * under the client's control. Every case below that starts "escape" is an
 * attempt to leave the export; all of them must be refused.
 */

# include "fh.h"

# include <stdio.h>
# include <string.h>

static int checks = 0;
static int fails = 0;

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

/* Build a handle by hand, bypassing fh_encode, the way a hostile client
 * would: it never calls our encoder.
 */
static void
forge (uint8_t *h, uint32_t magic, uint32_t exportid, const char *path,
       int claimed_len)
{
	size_t n = strlen (path);

	memset (h, 0, FH_SIZE);

	h[0] = (uint8_t) (magic >> 24);
	h[1] = (uint8_t) (magic >> 16);
	h[2] = (uint8_t) (magic >> 8);
	h[3] = (uint8_t) (magic);
	h[4] = (uint8_t) (exportid >> 8);
	h[5] = (uint8_t) (exportid);

	{
		int l = claimed_len < 0 ? (int) n : claimed_len;

		h[6] = (uint8_t) (l >> 8);
		h[7] = (uint8_t) (l);
	}

	if (n > NFSD_FHPATHLEN)
		n = NFSD_FHPATHLEN;

	memcpy (h + 8, path, n);
}

static void
test_round_trip (void)
{
	uint8_t h[FH_SIZE];
	nfsd_fh fh;

	ok (fh_encode (h, 0, "") == 0, "the export root encodes");
	ok (fh_decode (h, FH_SIZE, &fh) == 0, "and decodes");
	ok (fh.exportid == 0 && fh.path[0] == '\0', "as an empty path");

	ok (fh_encode (h, 3, "docs/letter.txt") == 0, "a path encodes");
	ok (fh_decode (h, FH_SIZE, &fh) == 0, "and decodes");
	ok (fh.exportid == 3, "export id survives");
	ok (strcmp (fh.path, "docs/letter.txt") == 0, "path survives");
}

static void
test_size_limits (void)
{
	uint8_t h[FH_SIZE];
	char long_path[NFSD_FHPATHLEN + 10];
	nfsd_fh fh;

	memset (long_path, 'a', sizeof (long_path) - 1);
	long_path[sizeof (long_path) - 1] = '\0';

	ok (fh_encode (h, 0, long_path) == -1,
	    "a path past the handle is refused on encode");

	/* exactly the limit must fit */
	long_path[NFSD_FHPATHLEN] = '\0';
	ok (fh_encode (h, 0, long_path) == 0, "a path of exactly the limit fits");
	ok (fh_decode (h, FH_SIZE, &fh) == 0, "and decodes");
	ok (strlen (fh.path) == NFSD_FHPATHLEN, "at full length");

	ok (fh_decode (h, FH_SIZE - 1, &fh) == -1, "a short handle is refused");
	ok (fh_decode (h, FH_SIZE + 1, &fh) == -1, "a long handle is refused");
	ok (fh_decode (h, 0, &fh) == -1, "a zero length handle is refused");
}

static void
test_magic (void)
{
	uint8_t h[FH_SIZE];
	nfsd_fh fh;

	forge (h, 0xdeadbeeful, 0, "x", -1);
	ok (fh_decode (h, FH_SIZE, &fh) == -1,
	    "a handle with the wrong magic is refused");

	forge (h, 0, 0, "x", -1);
	ok (fh_decode (h, FH_SIZE, &fh) == -1,
	    "an all zero handle is refused");
}

static void
test_escapes (void)
{
	uint8_t h[FH_SIZE];
	nfsd_fh fh;
	int i;

	static const char *bad[] =
	{
		"..",
		"../",
		"../etc",
		"../../etc/passwd",
		"docs/../../etc",
		"docs/..",
		"./x",
		".",
		"/etc/passwd",		/* absolute */
		"\\etc\\passwd",	/* absolute, MiNT style */
		"docs//letter",		/* empty component */
		"docs/",		/* trailing separator, empty component */
		"a/./b",
		"a/../b",
		"docs\\letter",		/* backslash inside a component */
		NULL
	};

	for (i = 0; bad[i]; i++)
	{
		char msg[128];

		forge (h, FH_MAGIC, 0, bad[i], -1);
		snprintf (msg, sizeof (msg), "escape refused: \"%s\"", bad[i]);
		ok (fh_decode (h, FH_SIZE, &fh) == -1, msg);
	}
}

static void
test_length_lies (void)
{
	uint8_t h[FH_SIZE];
	nfsd_fh fh;

	/* Claim more than the path really is: the bytes after it are zero,
	 * so strlen would disagree with the length field.
	 */
	forge (h, FH_MAGIC, 0, "abc", 20);
	ok (fh_decode (h, FH_SIZE, &fh) == -1,
	    "a length longer than the string is refused");

	/* Claim a length past the field itself. */
	forge (h, FH_MAGIC, 0, "abc", NFSD_FHPATHLEN + 1);
	ok (fh_decode (h, FH_SIZE, &fh) == -1,
	    "a length past the handle is refused");

	/* An embedded NUL: "a\0b" with a claimed length of 3. */
	memset (h, 0, FH_SIZE);
	forge (h, FH_MAGIC, 0, "a", 3);
	h[8 + 2] = 'b';
	ok (fh_decode (h, FH_SIZE, &fh) == -1,
	    "a path with an embedded NUL is refused");
}

static void
test_names (void)
{
	ok (fh_name_ok ("letter.txt"), "a plain name is allowed");
	ok (fh_name_ok ("AUTOEXEC.BAT"), "upper case is allowed");
	ok (!fh_name_ok (""), "an empty name is refused");
	ok (!fh_name_ok ("."), "\".\" is refused");
	ok (!fh_name_ok (".."), "\"..\" is refused");
	ok (!fh_name_ok ("a/b"), "a slash in a name is refused");
	ok (!fh_name_ok ("a\\b"), "a backslash in a name is refused");
	ok (!fh_name_ok ("a\tb"), "a control character is refused");

	{
		char n[NFSD_MAXNAME + 2];

		memset (n, 'x', NFSD_MAXNAME);
		n[NFSD_MAXNAME] = '\0';
		ok (fh_name_ok (n), "a name of exactly the limit is allowed");

		n[NFSD_MAXNAME] = 'x';
		n[NFSD_MAXNAME + 1] = '\0';
		ok (!fh_name_ok (n), "one character more is refused");
	}
}

static void
test_child (void)
{
	char out[NFSD_FHPATHLEN + 1];

	ok (fh_child (out, sizeof (out), "", "docs") == 0
	    && strcmp (out, "docs") == 0, "a child of the root has no slash");

	ok (fh_child (out, sizeof (out), "docs", "letter.txt") == 0
	    && strcmp (out, "docs/letter.txt") == 0, "a child is joined");

	ok (fh_child (out, sizeof (out), "docs", "..") == -1,
	    "a child named \"..\" is refused");

	ok (fh_child (out, sizeof (out), "docs", "a/b") == -1,
	    "a child with a separator is refused");

	{
		char deep[NFSD_FHPATHLEN + 1];

		memset (deep, 'a', NFSD_FHPATHLEN - 2);
		deep[NFSD_FHPATHLEN - 2] = '\0';
		ok (fh_child (out, sizeof (out), deep, "bb") == -1,
		    "a child that would not fit is refused");
	}
}

static void
test_parent (void)
{
	char p[NFSD_FHPATHLEN + 1];

	strcpy (p, "a/b/c");
	fh_parent (p);
	ok (strcmp (p, "a/b") == 0, "parent of a/b/c is a/b");

	fh_parent (p);
	ok (strcmp (p, "a") == 0, "parent of a/b is a");

	fh_parent (p);
	ok (strcmp (p, "") == 0, "parent of a is the root");

	fh_parent (p);
	ok (strcmp (p, "") == 0, "the root is its own parent, no escape");
}

int
main (void)
{
	printf ("file handles\n");

	test_round_trip ();
	test_size_limits ();
	test_magic ();
	test_escapes ();
	test_length_lies ();
	test_names ();
	test_child ();
	test_parent ();

	printf ("%d checks, %d failed\n", checks, fails);

	return fails ? 1 : 0;
}
