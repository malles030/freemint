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
 * mountd.c -- the MOUNT protocol, program 100005 version 3.
 *
 * A client cannot ask nfsd about a path, only about a file handle, so it has
 * to get the first handle from somewhere: that is this program's whole job.
 * It takes a directory name, decides whether the caller may have it, and
 * returns the handle for the root of that export.
 *
 * Version 3 only. Version 1 returns a file handle in a fixed 32 byte field,
 * and the handles here are 64 bytes, so a v1 MNT could not express them. A
 * client asking for v1 gets PROG_MISMATCH naming version 3, which is what
 * tells it to ask again properly. The FreeMiNT NFSv3 client already does.
 */

# include "rpc.h"
# include "config.h"
# include "exports.h"
# include "fh.h"

# include <errno.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <signal.h>
# include <unistd.h>
# include <arpa/inet.h>
# include <sys/stat.h>

# define MOUNT_PROG	100005ul
# define MOUNT_VERS3	3ul

# define MNT3_OK		0
# define MNT3ERR_PERM		1
# define MNT3ERR_NOENT		2
# define MNT3ERR_IO		5
# define MNT3ERR_ACCES		13
# define MNT3ERR_NOTDIR		20
# define MNT3ERR_INVAL		22
# define MNT3ERR_NAMETOOLONG	63
# define MNT3ERR_NOTSUPP	10004ul
# define MNT3ERR_SERVERFAULT	10006ul

# define MNTPATHLEN	1024
# define MNTNAMLEN	255

/* Who has mounted what, for DUMP. Advisory only: a client that goes away
 * without unmounting leaves a line here, exactly as on any other server.
 */
# define MAXMOUNTS	16

typedef struct
{
	int	used;
	char	host[64];
	char	path[NFSD_MAXPATH];
} mountent;

static mountent mounted[MAXMOUNTS];

static rpc_server server;

static void
remember (const char *host, const char *path)
{
	int i, free_slot = -1;

	for (i = 0; i < MAXMOUNTS; i++)
	{
		if (mounted[i].used)
		{
			if (strcmp (mounted[i].host, host) == 0
			    && strcmp (mounted[i].path, path) == 0)
				return;		/* already listed */
		}
		else if (free_slot < 0)
			free_slot = i;
	}

	if (free_slot < 0)
		return;			/* the list is full; not fatal */

	mounted[free_slot].used = 1;
	snprintf (mounted[free_slot].host, sizeof (mounted[free_slot].host),
		  "%s", host);
	snprintf (mounted[free_slot].path, sizeof (mounted[free_slot].path),
		  "%s", path);
}

static void
forget (const char *host, const char *path)
{
	int i;

	for (i = 0; i < MAXMOUNTS; i++)
	{
		if (mounted[i].used
		    && strcmp (mounted[i].host, host) == 0
		    && (!path || strcmp (mounted[i].path, path) == 0))
			mounted[i].used = 0;
	}
}

/* ------------------------------------------------------------ procedures */

static int
mnt_null (rpc_req *rq, XDR *args, XDR *res)
{
	(void) rq; (void) args; (void) res;

	return 0;
}

static int
put_u32 (XDR *res, uint32_t v)
{
	return xdr_u32 (res, &v);
}

static int
mnt_mnt (rpc_req *rq, XDR *args, XDR *res)
{
	char path[MNTPATHLEN + 1];
	const nfsd_export *e;
	uint8_t handle[FH_SIZE];
	struct stat st;
	uint32_t client;

	if (!xdr_string (args, path, sizeof (path)))
		return -RPC_GARBAGE_ARGS;

	client = ntohl (rq->from.sin_addr.s_addr);

	rpc_log ("mountd: MNT \"%s\" from %s", path,
		 inet_ntoa (rq->from.sin_addr));

	e = exports_by_path (path);

	/*
	 * Deliberately the same answer for "not exported" and "exported but
	 * not to you": otherwise MNT becomes a way to enumerate the export
	 * list from an address that is not allowed to use any of it.
	 */
	if (!e || !exports_allowed (e, client))
	{
		rpc_log ("mountd: refused");
		return put_u32 (res, MNT3ERR_ACCES) ? 0 : -RPC_SYSTEM_ERR;
	}

	if (stat (e->path, &st) < 0)
	{
		rpc_log ("mountd: %s: %s", e->path, strerror (errno));
		return put_u32 (res, MNT3ERR_NOENT) ? 0 : -RPC_SYSTEM_ERR;
	}

	if (!S_ISDIR (st.st_mode))
		return put_u32 (res, MNT3ERR_NOTDIR) ? 0 : -RPC_SYSTEM_ERR;

	if (fh_encode (handle, e->id, "") < 0)
		return put_u32 (res, MNT3ERR_SERVERFAULT) ? 0 : -RPC_SYSTEM_ERR;

	/* mountres3_ok: the handle, then the authentication flavours we take */
	{
		uint8_t *p = handle;
		uint32_t len = FH_SIZE;

		if (!put_u32 (res, MNT3_OK)
		    || !xdr_bytes (res, &p, &len, FH_SIZE)
		    || !put_u32 (res, 1)		/* one flavour */
		    || !put_u32 (res, AUTH_UNIX))
			return -RPC_SYSTEM_ERR;
	}

	/* e->path, not the client's string: they name the same export, but
	 * only e->path is known to fit the table.
	 */
	remember (inet_ntoa (rq->from.sin_addr), e->path);

	rpc_log ("mountd: granted, export %lu%s", (unsigned long) e->id,
		 e->ro ? " (read only)" : "");

	return 0;
}

static int
mnt_dump (rpc_req *rq, XDR *args, XDR *res)
{
	int i;

	(void) rq; (void) args;

	for (i = 0; i < MAXMOUNTS; i++)
	{
		if (!mounted[i].used)
			continue;

		if (!put_u32 (res, 1)
		    || !xdr_string (res, mounted[i].host, MNTNAMLEN + 1)
		    || !xdr_string (res, mounted[i].path, MNTPATHLEN + 1))
			return -RPC_SYSTEM_ERR;
	}

	if (!put_u32 (res, 0))
		return -RPC_SYSTEM_ERR;

	return 0;
}

static int
mnt_umnt (rpc_req *rq, XDR *args, XDR *res)
{
	char path[MNTPATHLEN + 1];

	(void) res;

	if (!xdr_string (args, path, sizeof (path)))
		return -RPC_GARBAGE_ARGS;

	rpc_log ("mountd: UMNT \"%s\" from %s", path,
		 inet_ntoa (rq->from.sin_addr));

	forget (inet_ntoa (rq->from.sin_addr), path);

	/* UMNT returns void: the bookkeeping is advisory, and refusing it
	 * would only leave the client unable to tidy up.
	 */
	return 0;
}

static int
mnt_umntall (rpc_req *rq, XDR *args, XDR *res)
{
	(void) args; (void) res;

	rpc_log ("mountd: UMNTALL from %s", inet_ntoa (rq->from.sin_addr));

	forget (inet_ntoa (rq->from.sin_addr), NULL);

	return 0;
}

static int
mnt_export (rpc_req *rq, XDR *args, XDR *res)
{
	int i, n;

	(void) rq; (void) args;

	n = exports_count ();

	/*
	 * The list every client may see. It names the exports and the
	 * addresses they are offered to, which is what "showmount -e"
	 * prints; it carries no handles, so it grants nothing.
	 */
	for (i = 0; i < n; i++)
	{
		const nfsd_export *e = exports_get ((uint32_t) i);
		char group[64];

		if (!put_u32 (res, 1)
		    || !xdr_string (res, (char *) e->path, MNTPATHLEN + 1))
			return -RPC_SYSTEM_ERR;

		if (e->mask == 0)
			snprintf (group, sizeof (group), "*");
		else
		{
			int bits = 0;
			uint32_t m = e->mask;

			while (m & 0x80000000ul)
			{
				bits++;
				m <<= 1;
			}

			if (bits == 32)
				snprintf (group, sizeof (group),
					  "%lu.%lu.%lu.%lu",
					  (unsigned long) ((e->addr >> 24) & 0xff),
					  (unsigned long) ((e->addr >> 16) & 0xff),
					  (unsigned long) ((e->addr >> 8) & 0xff),
					  (unsigned long) (e->addr & 0xff));
			else
				snprintf (group, sizeof (group),
					  "%lu.%lu.%lu.%lu/%d",
					  (unsigned long) ((e->addr >> 24) & 0xff),
					  (unsigned long) ((e->addr >> 16) & 0xff),
					  (unsigned long) ((e->addr >> 8) & 0xff),
					  (unsigned long) (e->addr & 0xff), bits);
		}

		/* one group, then the end of that export's group list */
		if (!put_u32 (res, 1)
		    || !xdr_string (res, group, MNTNAMLEN + 1)
		    || !put_u32 (res, 0))
			return -RPC_SYSTEM_ERR;
	}

	if (!put_u32 (res, 0))
		return -RPC_SYSTEM_ERR;

	return 0;
}

static const rpc_proc procs[] =
{
	mnt_null,	/* 0 NULL    */
	mnt_mnt,	/* 1 MNT     */
	mnt_dump,	/* 2 DUMP    */
	mnt_umnt,	/* 3 UMNT    */
	mnt_umntall,	/* 4 UMNTALL */
	mnt_export,	/* 5 EXPORT  */
};

static const rpc_program program =
{
	MOUNT_PROG, MOUNT_VERS3,
	sizeof (procs) / sizeof (procs[0]), procs,
	"mountd"
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
		 "  -p  listen on this port instead of asking for any free one\n"
		 "  -n  do not register with the port mapper\n", me);
	exit (1);
}

int
main (int argc, char **argv)
{
	const char *expfile = "/etc/exports";
	int port = 0, no_pmap = 0;
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

	if (rpc_listen (&server, (uint16_t) port) < 0)
	{
		fprintf (stderr, "mountd: cannot listen: %s\n",
			 strerror (errno));
		return 1;
	}

	rpc_add_program (&server, &program);

	if (!no_pmap)
	{
		if (rpc_pmap_set (MOUNT_PROG, MOUNT_VERS3, 0, server.port) < 0
		    || rpc_pmap_set (MOUNT_PROG, MOUNT_VERS3, 1, server.port) < 0)
		{
			fprintf (stderr, "mountd: the port mapper did not take "
				 "the registration.\n"
				 "mountd: is portmap running?\n");
			rpc_close (&server);
			return 1;
		}
	}

	signal (SIGINT, on_signal);
	signal (SIGTERM, on_signal);
# ifdef SIGPIPE
	signal (SIGPIPE, SIG_IGN);
# endif

	printf ("mountd: listening on port %u, exporting\n",
		(unsigned) server.port);
	exports_print ();
	fflush (stdout);

	if (rpc_run (&server) < 0)
	{
		perror ("mountd");
		if (!no_pmap)
			rpc_pmap_unset (MOUNT_PROG, MOUNT_VERS3);
		rpc_close (&server);
		return 1;
	}

	if (!no_pmap)
		rpc_pmap_unset (MOUNT_PROG, MOUNT_VERS3);

	rpc_close (&server);

	return 0;
}
