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
 * exports.c -- see exports.h
 */

# include "exports.h"

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <ctype.h>

static nfsd_export tab[NFSD_MAXEXPORTS];
static int ntab = 0;

int
exports_count (void)
{
	return ntab;
}

const nfsd_export *
exports_get (uint32_t id)
{
	if (id >= (uint32_t) ntab)
		return NULL;

	return &tab[id];
}

/*
 * Collapse repeated separators and drop a trailing one, so that "/c//pub/"
 * and "/c/pub" name the same export. A client is free to send either, and
 * refusing one of them looks like a permission problem to whoever is trying
 * to mount.
 */
static void
normalise (char *p)
{
	char *r = p, *w = p;

	while (*r)
	{
		if (*r == '\\')
			*r = '/';		/* MiNT takes both */

		if (*r == '/' && w > p && w[-1] == '/')
		{
			r++;			/* skip the repeat */
			continue;
		}

		*w++ = *r++;
	}

	/* a trailing separator, unless the whole path is just "/" */
	if (w > p + 1 && w[-1] == '/')
		w--;

	*w = '\0';
}

const nfsd_export *
exports_by_path (const char *path)
{
	char want[NFSD_MAXPATH];
	int i;

	if (strlen (path) >= sizeof (want))
		return NULL;

	strcpy (want, path);
	normalise (want);

	for (i = 0; i < ntab; i++)
	{
		if (strcmp (tab[i].path, want) == 0)
			return &tab[i];
	}

	return NULL;
}

int
exports_allowed (const nfsd_export *e, uint32_t client_addr)
{
	if (!e)
		return 0;

	if (e->mask == 0)
		return 1;		/* "*" */

	return (client_addr & e->mask) == (e->addr & e->mask);
}

void
exports_squash (const nfsd_export *e, uint32_t *uid, uint32_t *gid)
{
	if (e->all_squash)
	{
		*uid = e->anonuid;
		*gid = e->anongid;
		return;
	}

	if (e->root_squash && *uid == 0)
	{
		*uid = e->anonuid;
		*gid = e->anongid;
	}
}

/* --------------------------------------------------------------- parsing */

/* Parse "a.b.c.d" into host order. Returns 0 or -1. */
static int
parse_addr (const char *s, uint32_t *out)
{
	unsigned a, b, c, d;
	char extra;

	if (sscanf (s, "%u.%u.%u.%u%c", &a, &b, &c, &d, &extra) != 4)
		return -1;

	if (a > 255 || b > 255 || c > 255 || d > 255)
		return -1;

	*out = (a << 24) | (b << 16) | (c << 8) | d;

	return 0;
}

/*
 * "192.168.1.0/24", "192.168.1.5", or "*".
 */
static int
parse_client (const char *s, uint32_t *addr, uint32_t *mask)
{
	const char *slash;

	if (strcmp (s, "*") == 0)
	{
		*addr = 0;
		*mask = 0;
		return 0;
	}

	slash = strchr (s, '/');

	if (!slash)
	{
		if (parse_addr (s, addr) < 0)
			return -1;

		*mask = 0xfffffffful;	/* one host */
		return 0;
	}

	{
		char host[32];
		size_t n = (size_t) (slash - s);
		int bits;

		if (n >= sizeof (host))
			return -1;

		memcpy (host, s, n);
		host[n] = '\0';

		if (parse_addr (host, addr) < 0)
			return -1;

		bits = atoi (slash + 1);
		if (bits < 0 || bits > 32)
			return -1;

		*mask = bits == 0 ? 0 : (0xfffffffful << (32 - bits));
	}

	return 0;
}

static int
parse_options (const char *s, nfsd_export *e, const char *file, int line)
{
	char buf[256];
	char *p, *tok;

	if (strlen (s) >= sizeof (buf))
	{
		fprintf (stderr, "%s:%d: option list too long\n", file, line);
		return -1;
	}

	strcpy (buf, s);

	for (tok = strtok_r (buf, ",", &p); tok; tok = strtok_r (NULL, ",", &p))
	{
		while (*tok == ' ' || *tok == '\t')
			tok++;

		if (strcmp (tok, "ro") == 0)
			e->ro = 1;
		else if (strcmp (tok, "rw") == 0)
			e->ro = 0;
		else if (strcmp (tok, "all_squash") == 0)
			e->all_squash = 1;
		else if (strcmp (tok, "no_all_squash") == 0)
			e->all_squash = 0;
		else if (strcmp (tok, "root_squash") == 0)
			e->root_squash = 1;
		else if (strcmp (tok, "no_root_squash") == 0)
			e->root_squash = 0;
		else if (strncmp (tok, "anonuid=", 8) == 0)
			e->anonuid = (uint32_t) atol (tok + 8);
		else if (strncmp (tok, "anongid=", 8) == 0)
			e->anongid = (uint32_t) atol (tok + 8);
		else
		{
			/* Refuse rather than ignore. An option that is
			 * silently dropped is how an export ends up more
			 * permissive than its line says.
			 */
			fprintf (stderr, "%s:%d: unknown option \"%s\"\n",
				 file, line, tok);
			return -1;
		}
	}

	return 0;
}

int
exports_load (const char *file)
{
	FILE *f;
	char buf[512];
	int line = 0;

	ntab = 0;

	f = fopen (file, "r");
	if (!f)
	{
		fprintf (stderr, "nfsd: cannot read %s\n", file);
		return -1;
	}

	while (fgets (buf, sizeof (buf), f))
	{
		char *p = buf;
		char *path, *client, *opts = NULL, *open_paren;
		nfsd_export *e;

		line++;

		/* strip the newline and anything after a '#' */
		{
			char *h = strchr (p, '#');

			if (h)
				*h = '\0';
		}

		{
			size_t n = strlen (p);

			while (n && (p[n - 1] == '\n' || p[n - 1] == '\r'
				     || p[n - 1] == ' ' || p[n - 1] == '\t'))
				p[--n] = '\0';
		}

		while (*p == ' ' || *p == '\t')
			p++;

		if (*p == '\0')
			continue;

		if (ntab >= NFSD_MAXEXPORTS)
		{
			fprintf (stderr, "%s:%d: more than %d exports\n",
				 file, line, NFSD_MAXEXPORTS);
			fclose (f);
			return -1;
		}

		/* path, then whitespace, then the client specification */
		path = p;
		while (*p && *p != ' ' && *p != '\t')
			p++;

		if (*p == '\0')
		{
			fprintf (stderr, "%s:%d: no client given for \"%s\"\n",
				 file, line, path);
			fclose (f);
			return -1;
		}

		*p++ = '\0';

		while (*p == ' ' || *p == '\t')
			p++;

		client = p;

		open_paren = strchr (p, '(');
		if (open_paren)
		{
			char *close_paren = strrchr (p, ')');

			if (!close_paren || close_paren < open_paren)
			{
				fprintf (stderr, "%s:%d: unbalanced "
					 "parentheses\n", file, line);
				fclose (f);
				return -1;
			}

			*open_paren = '\0';
			*close_paren = '\0';
			opts = open_paren + 1;
		}

		if (strlen (path) >= NFSD_MAXPATH)
		{
			fprintf (stderr, "%s:%d: path too long\n", file, line);
			fclose (f);
			return -1;
		}

		e = &tab[ntab];
		memset (e, 0, sizeof (*e));

		e->id = (uint32_t) ntab;
		strcpy (e->path, path);
		normalise (e->path);

		/*
		 * Read only and root_squash unless the line says otherwise:
		 * a typo in the options must not open an export for writing.
		 */
		e->ro = 1;
		e->root_squash = 1;
		e->anonuid = 65534;
		e->anongid = 65534;

		if (parse_client (client, &e->addr, &e->mask) < 0)
		{
			fprintf (stderr, "%s:%d: cannot parse client \"%s\"\n",
				 file, line, client);
			fclose (f);
			return -1;
		}

		if (opts && parse_options (opts, e, file, line) < 0)
		{
			fclose (f);
			return -1;
		}

		ntab++;
	}

	fclose (f);

	if (ntab == 0)
	{
		fprintf (stderr, "nfsd: %s defines no exports\n", file);
		return -1;
	}

	return ntab;
}

void
exports_print (void)
{
	int i;

	for (i = 0; i < ntab; i++)
	{
		const nfsd_export *e = &tab[i];

		printf ("  %-24s ", e->path);

		if (e->mask == 0)
			printf ("*");
		else
		{
			int bits = 0;
			uint32_t m = e->mask;

			while (m & 0x80000000ul)
			{
				bits++;
				m <<= 1;
			}

			printf ("%lu.%lu.%lu.%lu",
				(unsigned long) ((e->addr >> 24) & 0xff),
				(unsigned long) ((e->addr >> 16) & 0xff),
				(unsigned long) ((e->addr >> 8) & 0xff),
				(unsigned long) (e->addr & 0xff));

			if (bits != 32)
				printf ("/%d", bits);
		}

		printf (" (%s", e->ro ? "ro" : "rw");

		if (e->all_squash)
			printf (",all_squash");
		if (e->root_squash)
			printf (",root_squash");

		printf (",anonuid=%lu,anongid=%lu)\n",
			(unsigned long) e->anonuid,
			(unsigned long) e->anongid);
	}
}
