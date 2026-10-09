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
 * portmap.c -- the port mapper, program 100000 version 2, on port 111.
 *
 * A client that wants to mount asks us which port mountd and nfsd ended up
 * on, so this has to be running before either of them, and it is the only
 * part of the three that needs a fixed, well known port.
 *
 * Two deliberate restrictions:
 *
 *   PMAP_CALLIT (procedure 5) is not implemented. It asks the port mapper to
 *   make an RPC call on the caller's behalf and send the answer back, which
 *   turns any host running it into a reflector: a one packet request with a
 *   forged source address produces a large reply aimed at the victim. There
 *   is nothing NFS needs it for.
 *
 *   PMAP_SET and PMAP_UNSET are accepted only from the loopback address.
 *   Otherwise anyone on the network could point nfsd's registration at a
 *   port of their choosing, and a client that asks us where to mount would
 *   be sent there.
 */

# include "rpc.h"
# include "config.h"

# include <errno.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <signal.h>
# include <unistd.h>
# include <arpa/inet.h>

# define PMAP_PROG	100000ul
# define PMAP_VERS	2ul

# define PMAP_PORT	111

# define IPPROTO_TCP_	6
# define IPPROTO_UDP_	17

# define MAXMAP		32

typedef struct
{
	int		used;
	uint32_t	prog;
	uint32_t	vers;
	uint32_t	prot;
	uint32_t	port;
} mapping;

static mapping map[MAXMAP];

static rpc_server server;

/* ------------------------------------------------------------- the table */

static mapping *
find (uint32_t prog, uint32_t vers, uint32_t prot)
{
	int i;

	for (i = 0; i < MAXMAP; i++)
	{
		if (map[i].used
		    && map[i].prog == prog
		    && map[i].vers == vers
		    && map[i].prot == prot)
			return &map[i];
	}

	return NULL;
}

static int
add (uint32_t prog, uint32_t vers, uint32_t prot, uint32_t port)
{
	mapping *m;
	int i;

	m = find (prog, vers, prot);
	if (m)
	{
		/* Re-registering the same triple is how a restarted daemon
		 * announces its new port, so this replaces rather than fails.
		 */
		m->port = port;
		return 1;
	}

	for (i = 0; i < MAXMAP; i++)
	{
		if (!map[i].used)
		{
			map[i].used = 1;
			map[i].prog = prog;
			map[i].vers = vers;
			map[i].prot = prot;
			map[i].port = port;
			return 1;
		}
	}

	return 0;
}

static int
del (uint32_t prog, uint32_t vers)
{
	int i, n = 0;

	/* UNSET ignores the protocol: it removes every registration of that
	 * program and version, which is what a daemon shutting down wants.
	 */
	for (i = 0; i < MAXMAP; i++)
	{
		if (map[i].used && map[i].prog == prog && map[i].vers == vers)
		{
			map[i].used = 0;
			n++;
		}
	}

	return n > 0;
}

/* ------------------------------------------------------------ procedures */

static int
get_mapping (XDR *args, mapping *m)
{
	memset (m, 0, sizeof (*m));

	if (!xdr_u32 (args, &m->prog) || !xdr_u32 (args, &m->vers)
	    || !xdr_u32 (args, &m->prot) || !xdr_u32 (args, &m->port))
		return 0;

	return 1;
}

static int
put_bool (XDR *res, int v)
{
	uint32_t u = v ? 1 : 0;

	return xdr_u32 (res, &u);
}

static int
is_local (const rpc_req *rq)
{
	return rq->from.sin_addr.s_addr == htonl (INADDR_LOOPBACK);
}

static int
pmap_null (rpc_req *rq, XDR *args, XDR *res)
{
	(void) rq; (void) args; (void) res;

	return 0;
}

static int
pmap_set (rpc_req *rq, XDR *args, XDR *res)
{
	mapping m;

	if (!get_mapping (args, &m))
		return -RPC_GARBAGE_ARGS;

	if (!is_local (rq))
	{
		rpc_log ("portmap: SET from %s refused, not local",
			 inet_ntoa (rq->from.sin_addr));
		put_bool (res, 0);
		return 0;
	}

	if (m.port == 0 || m.port > 65535)
	{
		put_bool (res, 0);
		return 0;
	}

	rpc_log ("portmap: set %lu/%lu %s -> %lu",
		 (unsigned long) m.prog, (unsigned long) m.vers,
		 m.prot == IPPROTO_TCP_ ? "tcp" : "udp",
		 (unsigned long) m.port);

	put_bool (res, add (m.prog, m.vers, m.prot, m.port));

	return 0;
}

static int
pmap_unset (rpc_req *rq, XDR *args, XDR *res)
{
	mapping m;

	if (!get_mapping (args, &m))
		return -RPC_GARBAGE_ARGS;

	if (!is_local (rq))
	{
		rpc_log ("portmap: UNSET from %s refused, not local",
			 inet_ntoa (rq->from.sin_addr));
		put_bool (res, 0);
		return 0;
	}

	rpc_log ("portmap: unset %lu/%lu",
		 (unsigned long) m.prog, (unsigned long) m.vers);

	put_bool (res, del (m.prog, m.vers));

	return 0;
}

static int
pmap_getport (rpc_req *rq, XDR *args, XDR *res)
{
	mapping m, *f;
	uint32_t port = 0;

	(void) rq;

	if (!get_mapping (args, &m))
		return -RPC_GARBAGE_ARGS;

	f = find (m.prog, m.vers, m.prot);
	if (f)
		port = f->port;

	rpc_log ("portmap: getport %lu/%lu %s -> %lu",
		 (unsigned long) m.prog, (unsigned long) m.vers,
		 m.prot == IPPROTO_TCP_ ? "tcp" : "udp",
		 (unsigned long) port);

	/* Zero means "not registered", which is what the caller expects. */
	if (!xdr_u32 (res, &port))
		return -RPC_SYSTEM_ERR;

	return 0;
}

static int
pmap_dump (rpc_req *rq, XDR *args, XDR *res)
{
	int i;

	(void) rq; (void) args;

	/* A list: each entry preceded by TRUE, the end marked by FALSE. */
	for (i = 0; i < MAXMAP; i++)
	{
		if (!map[i].used)
			continue;

		if (!put_bool (res, 1)
		    || !xdr_u32 (res, &map[i].prog)
		    || !xdr_u32 (res, &map[i].vers)
		    || !xdr_u32 (res, &map[i].prot)
		    || !xdr_u32 (res, &map[i].port))
			return -RPC_SYSTEM_ERR;
	}

	if (!put_bool (res, 0))
		return -RPC_SYSTEM_ERR;

	return 0;
}

static const rpc_proc procs[] =
{
	pmap_null,	/* 0 NULL    */
	pmap_set,	/* 1 SET     */
	pmap_unset,	/* 2 UNSET   */
	pmap_getport,	/* 3 GETPORT */
	pmap_dump,	/* 4 DUMP    */
	NULL,		/* 5 CALLIT  -- see the comment at the top */
};

static const rpc_program program =
{
	PMAP_PROG, PMAP_VERS,
	sizeof (procs) / sizeof (procs[0]), procs,
	"portmap"
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
		 "usage: %s [-d] [-f] [-p port]\n"
		 "  -d  log every request to stderr\n"
		 "  -f  stay in the foreground\n"
		 "  -p  listen on this port instead of 111. Only useful for\n"
		 "      testing: a client looking for a port mapper asks 111.\n",
		 me);
	exit (1);
}

int
main (int argc, char **argv)
{
	int foreground = 0;
	int port = PMAP_PORT;
	int i;

	for (i = 1; i < argc; i++)
	{
		if (strcmp (argv[i], "-d") == 0)
		{
			rpc_verbose = 1;
			foreground = 1;
		}
		else if (strcmp (argv[i], "-f") == 0)
			foreground = 1;
		else if (strcmp (argv[i], "-p") == 0 && i + 1 < argc)
		{
			port = atoi (argv[++i]);
			if (port <= 0 || port > 65535)
				usage (argv[0]);
		}
		else
			usage (argv[0]);
	}

	if (rpc_listen (&server, (uint16_t) port) < 0)
	{
		fprintf (stderr, "portmap: cannot listen on port %d: %s\n",
			 port, strerror (errno));
		if (port == PMAP_PORT)
			fprintf (stderr, "portmap: is another one already "
				 "running, or are we not root?\n");
		return 1;
	}

	rpc_add_program (&server, &program);

	/*
	 * Register ourselves, so that a plain "rpcinfo -p" lists the port
	 * mapper too. Done directly in the table, not through a call: we
	 * are the one being asked.
	 */
	add (PMAP_PROG, PMAP_VERS, IPPROTO_TCP_, (uint32_t) port);
	add (PMAP_PROG, PMAP_VERS, IPPROTO_UDP_, (uint32_t) port);

	signal (SIGINT, on_signal);
	signal (SIGTERM, on_signal);
# ifdef SIGPIPE
	signal (SIGPIPE, SIG_IGN);	/* a client that vanishes mid-reply */
# endif

	fprintf (foreground ? stderr : stdout,
		 "portmap: listening on port %d\n", port);
	fflush (foreground ? stderr : stdout);

	if (rpc_run (&server) < 0)
	{
		perror ("portmap");
		rpc_close (&server);
		return 1;
	}

	rpc_close (&server);

	return 0;
}
