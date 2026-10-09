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
 * fh.c -- see fh.h
 */

# include "fh.h"

# include <string.h>

int
fh_name_ok (const char *name)
{
	size_t n;

	if (!name)
		return 0;

	n = strlen (name);

	if (n == 0 || n > NFSD_MAXNAME)
		return 0;

	/* "." and ".." are handled by the caller, never looked up as files:
	 * letting them through here would let a path be built that walks out
	 * of the export.
	 */
	if (strcmp (name, ".") == 0 || strcmp (name, "..") == 0)
		return 0;

	/* A separator inside what is supposed to be one component would turn
	 * one LOOKUP into a path traversal. MiNT takes both forms.
	 */
	if (strchr (name, '/') || strchr (name, '\\'))
		return 0;

	/* NFSv3 strings are counted, so a NUL cannot appear, but a control
	 * character in a file name is a sign of a confused or hostile client
	 * and nothing on an Atari wants one.
	 */
	{
		const unsigned char *p = (const unsigned char *) name;

		while (*p)
		{
			if (*p < 0x20)
				return 0;
			p++;
		}
	}

	return 1;
}

/*
 * Walk a relative path and check every component. The path a handle carries
 * was built by us, but it came back through the client, so it is checked
 * again on the way in.
 */
static int
path_ok (const char *path)
{
	const char *p = path;

	if (*p == '\0')
		return 1;		/* the export root */

	if (*p == '/' || *p == '\\')
		return 0;		/* must be relative */

	while (*p)
	{
		char comp[NFSD_MAXNAME + 1];
		const char *slash;
		size_t n;

		slash = strchr (p, '/');
		n = slash ? (size_t) (slash - p) : strlen (p);

		if (n == 0 || n > NFSD_MAXNAME)
			return 0;

		memcpy (comp, p, n);
		comp[n] = '\0';

		if (!fh_name_ok (comp))
			return 0;

		if (!slash)
			break;

		p = slash + 1;

		/* A separator with nothing after it leaves an empty
		 * component, which the loop condition would skip.
		 */
		if (*p == '\0')
			return 0;
	}

	return 1;
}

int
fh_encode (uint8_t *out, uint32_t exportid, const char *relpath)
{
	size_t n = strlen (relpath);

	if (n > NFSD_FHPATHLEN)
		return -1;

	if (exportid > 0xffff)
		return -1;

	memset (out, 0, FH_SIZE);

	out[0] = (uint8_t) (FH_MAGIC >> 24);
	out[1] = (uint8_t) (FH_MAGIC >> 16);
	out[2] = (uint8_t) (FH_MAGIC >> 8);
	out[3] = (uint8_t) (FH_MAGIC);

	out[4] = (uint8_t) (exportid >> 8);
	out[5] = (uint8_t) (exportid);

	out[6] = (uint8_t) (n >> 8);
	out[7] = (uint8_t) (n);

	memcpy (out + 8, relpath, n);

	return 0;
}

int
fh_decode (const uint8_t *in, uint32_t len, nfsd_fh *fh)
{
	uint32_t magic;
	uint32_t n;

	if (len != FH_SIZE)
		return -1;

	magic = ((uint32_t) in[0] << 24) | ((uint32_t) in[1] << 16)
	      | ((uint32_t) in[2] << 8)  | ((uint32_t) in[3]);

	if (magic != FH_MAGIC)
		return -1;

	fh->exportid = ((uint32_t) in[4] << 8) | (uint32_t) in[5];

	n = ((uint32_t) in[6] << 8) | (uint32_t) in[7];

	if (n > NFSD_FHPATHLEN)
		return -1;

	memcpy (fh->path, in + 8, n);
	fh->path[n] = '\0';

	/* The length field and the bytes have to agree: a NUL inside would
	 * mean one path here and a shorter one to every later strlen.
	 */
	if (strlen (fh->path) != n)
		return -1;

	if (!path_ok (fh->path))
		return -1;

	return 0;
}

int
fh_child (char *out, size_t outsz, const char *parent, const char *name)
{
	size_t pn = strlen (parent);
	size_t nn = strlen (name);
	size_t need;

	if (!fh_name_ok (name))
		return -1;

	/* The root needs no separator. */
	need = pn ? pn + 1 + nn : nn;

	if (need > NFSD_FHPATHLEN || need + 1 > outsz)
		return -1;

	if (pn)
	{
		memcpy (out, parent, pn);
		out[pn] = '/';
		memcpy (out + pn + 1, name, nn);
		out[pn + 1 + nn] = '\0';
	}
	else
	{
		memcpy (out, name, nn);
		out[nn] = '\0';
	}

	return 0;
}

void
fh_parent (char *path)
{
	char *slash = strrchr (path, '/');

	if (slash)
		*slash = '\0';
	else
		*path = '\0';		/* one level down: back to the root */
}
