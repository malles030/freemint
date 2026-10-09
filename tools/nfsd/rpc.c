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
 * rpc.c -- see rpc.h
 */

# include "rpc.h"
# include "config.h"

# include <errno.h>
# include <stdarg.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <unistd.h>
# include <sys/socket.h>
# include <sys/time.h>
# include <arpa/inet.h>

int rpc_verbose = 0;

void
rpc_log (const char *fmt, ...)
{
	va_list ap;

	if (!rpc_verbose)
		return;

	va_start (ap, fmt);
	vfprintf (stderr, fmt, ap);
	va_end (ap);
	fputc ('\n', stderr);
}

/*
 * A TCP connection in the middle of a record. Records arrive in fragments,
 * each with a 4 byte marker holding a length and a last-fragment bit, and a
 * fragment can itself be split across several reads.
 */
struct rpc_conn
{
	int		fd;
	struct sockaddr_in from;

	uint8_t		mark[4];	/* the marker being collected */
	int		marklen;	/* how much of it we have */

	uint32_t	fraglen;	/* bytes still to come in this fragment */
	int		last;		/* was the last-fragment bit set? */

	uint8_t *	buf;		/* the record being assembled */
	size_t		have;		/* bytes in it */
};

/* ------------------------------------------------------------ sockets */

static int
set_reuse (int fd)
{
	int on = 1;

	return setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof (on));
}

int
rpc_listen (rpc_server *s, uint16_t port)
{
	struct sockaddr_in a;
	socklen_t alen;
	int i;

	memset (s, 0, sizeof (*s));
	s->udp = s->tcp = -1;
	for (i = 0; i < RPC_MAXCONN; i++)
		s->conn[i] = NULL;

	s->udp = socket (AF_INET, SOCK_DGRAM, 0);
	if (s->udp < 0)
		return -1;

	s->tcp = socket (AF_INET, SOCK_STREAM, 0);
	if (s->tcp < 0)
		goto fail;

	set_reuse (s->udp);
	set_reuse (s->tcp);

	memset (&a, 0, sizeof (a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl (INADDR_ANY);
	a.sin_port = htons (port);

	if (bind (s->udp, (struct sockaddr *) &a, sizeof (a)) < 0)
		goto fail;

	/*
	 * With port 0 the UDP bind picked something; TCP has to land on the
	 * same number, because that is the single port we register with the
	 * portmapper for both protocols.
	 */
	alen = sizeof (a);
	if (getsockname (s->udp, (struct sockaddr *) &a, &alen) < 0)
		goto fail;

	s->port = ntohs (a.sin_port);

	if (bind (s->tcp, (struct sockaddr *) &a, sizeof (a)) < 0)
		goto fail;

	if (listen (s->tcp, 5) < 0)
		goto fail;

	return 0;

fail:
	{
		int e = errno;

		if (s->udp >= 0) close (s->udp);
		if (s->tcp >= 0) close (s->tcp);
		s->udp = s->tcp = -1;
		errno = e;
	}

	return -1;
}

int
rpc_add_program (rpc_server *s, const rpc_program *p)
{
	if (s->nprog >= RPC_MAXPROG)
		return -1;

	s->prog[s->nprog++] = p;

	return 0;
}

void
rpc_stop (rpc_server *s)
{
	s->stop = 1;
}

void
rpc_close (rpc_server *s)
{
	int i;

	for (i = 0; i < RPC_MAXCONN; i++)
	{
		if (s->conn[i])
		{
			close (s->conn[i]->fd);
			free (s->conn[i]->buf);
			free (s->conn[i]);
			s->conn[i] = NULL;
		}
	}

	if (s->udp >= 0) close (s->udp);
	if (s->tcp >= 0) close (s->tcp);
	s->udp = s->tcp = -1;
}

/* ------------------------------------------------- credential decoding */

static int
decode_cred (XDR *x, rpc_cred *c)
{
	uint32_t flavour, len, i, n;
	size_t end;

	memset (c, 0, sizeof (*c));

	if (!xdr_u32 (x, &flavour) || !xdr_u32 (x, &len))
		return 0;

	/* The body is `len' bytes whatever we make of it, so remember where
	 * it ends and skip to there: an AUTH_UNIX body with more groups than
	 * we keep must not leave the stream half way through.
	 */
	end = xdr_pos (x) + XDR_ROUNDUP (len);

	if (flavour == AUTH_UNIX)
	{
		uint32_t stamp;

		if (!xdr_u32 (x, &stamp)
		    || !xdr_string (x, c->machine, sizeof (c->machine))
		    || !xdr_u32 (x, &c->uid)
		    || !xdr_u32 (x, &c->gid)
		    || !xdr_u32 (x, &n))
			return 0;

		/* Keep what fits and ignore the rest; a caller in many
		 * groups is not an error.
		 */
		c->ngids = n > RPC_MAXGIDS ? RPC_MAXGIDS : n;
		for (i = 0; i < n; i++)
		{
			uint32_t g;

			if (!xdr_u32 (x, &g))
				return 0;
			if (i < c->ngids)
				c->gids[i] = g;
		}

		c->have = 1;
	}

	if (end > x->len)
		return 0;

	x->pos = end;

	return 1;
}

/* ------------------------------------------------------- reply building */

/*
 * Write an accepted reply header. The body, if any, follows.
 */
static void
put_accepted (XDR *res, uint32_t xid, uint32_t stat)
{
	uint32_t v;

	v = xid;		xdr_u32 (res, &v);
	v = RPC_REPLY;		xdr_u32 (res, &v);
	v = MSG_ACCEPTED;	xdr_u32 (res, &v);
	v = AUTH_NONE;		xdr_u32 (res, &v);	/* verifier flavour */
	v = 0;			xdr_u32 (res, &v);	/* verifier length */
	v = stat;		xdr_u32 (res, &v);
}

static void
put_prog_mismatch (XDR *res, uint32_t xid, uint32_t lo, uint32_t hi)
{
	uint32_t v;

	put_accepted (res, xid, RPC_PROG_MISMATCH);
	v = lo; xdr_u32 (res, &v);
	v = hi; xdr_u32 (res, &v);
}

static void
put_denied (XDR *res, uint32_t xid, uint32_t why, uint32_t a, uint32_t b)
{
	uint32_t v;

	v = xid;	    xdr_u32 (res, &v);
	v = RPC_REPLY;	    xdr_u32 (res, &v);
	v = MSG_DENIED;	    xdr_u32 (res, &v);
	v = why;	    xdr_u32 (res, &v);

	if (why == RPC_MISMATCH)
	{
		v = a; xdr_u32 (res, &v);	/* lowest version */
		v = b; xdr_u32 (res, &v);	/* highest */
	}
	else
	{
		v = a; xdr_u32 (res, &v);	/* auth_stat */
	}
}

/* ------------------------------------------------------------ dispatch */

/*
 * Decode one call and produce the reply. Returns the reply length, or 0 when
 * there is nothing to send -- a malformed header has no xid we can trust, so
 * the only safe answer is silence.
 */
static size_t
serve_one (rpc_server *s, const uint8_t *in, size_t inlen,
	   uint8_t *out, size_t outsz,
	   const struct sockaddr_in *from, int over_tcp)
{
	XDR args, res;
	rpc_req rq;
	uint32_t mtype, rpcvers;
	int i, found_prog = 0;
	uint32_t vlo = 0, vhi = 0;
	int r;

	xdr_init (&args, (void *) in, inlen, XDR_DECODE);
	xdr_init (&res, out, outsz, XDR_ENCODE);

	memset (&rq, 0, sizeof (rq));

	if (!xdr_u32 (&args, &rq.xid)
	    || !xdr_u32 (&args, &mtype)
	    || !xdr_u32 (&args, &rpcvers)
	    || !xdr_u32 (&args, &rq.prog)
	    || !xdr_u32 (&args, &rq.vers)
	    || !xdr_u32 (&args, &rq.proc))
	{
		rpc_log ("rpc: truncated call header, ignored");
		return 0;
	}

	if (mtype != RPC_CALL)
	{
		rpc_log ("rpc: not a call (type %lu), ignored",
			 (unsigned long) mtype);
		return 0;
	}

	if (rpcvers != RPC_VERSION)
	{
		put_denied (&res, rq.xid, RPC_MISMATCH, RPC_VERSION, RPC_VERSION);
		return xdr_pos (&res);
	}

	if (!decode_cred (&args, &rq.cred))
	{
		put_denied (&res, rq.xid, RPC_AUTH_ERROR, AUTH_BADCRED, 0);
		return xdr_pos (&res);
	}

	/* The verifier: flavour and length, which we skip. Nothing but
	 * AUTH_NONE is meaningful without Kerberos.
	 */
	{
		uint32_t vf, vl;

		if (!xdr_u32 (&args, &vf) || !xdr_u32 (&args, &vl)
		    || !xdr_skip (&args, vl))
		{
			put_denied (&res, rq.xid, RPC_AUTH_ERROR, AUTH_BADCRED, 0);
			return xdr_pos (&res);
		}
	}

	rq.from = *from;
	rq.over_tcp = over_tcp;

	for (i = 0; i < s->nprog; i++)
	{
		const rpc_program *p = s->prog[i];

		if (p->prog != rq.prog)
			continue;

		found_prog = 1;

		if (!vlo || p->vers < vlo) vlo = p->vers;
		if (p->vers > vhi) vhi = p->vers;

		if (p->vers != rq.vers)
			continue;

		if (rq.proc >= p->nproc || !p->proc[rq.proc])
		{
			rpc_log ("%s: no procedure %lu", p->name,
				 (unsigned long) rq.proc);
			put_accepted (&res, rq.xid, RPC_PROC_UNAVAIL);
			return xdr_pos (&res);
		}

		put_accepted (&res, rq.xid, RPC_SUCCESS);

		r = (*p->proc[rq.proc]) (&rq, &args, &res);

		if (r != 0)
		{
			/* The handler refused. Rewind and send the error
			 * instead of the half written body.
			 */
			xdr_init (&res, out, outsz, XDR_ENCODE);
			put_accepted (&res, rq.xid, (uint32_t) (-r));
			return xdr_pos (&res);
		}

		if (!xdr_ok (&res))
		{
			rpc_log ("%s: reply for procedure %lu did not fit",
				 p->name, (unsigned long) rq.proc);
			xdr_init (&res, out, outsz, XDR_ENCODE);
			put_accepted (&res, rq.xid, RPC_SYSTEM_ERR);
			return xdr_pos (&res);
		}

		return xdr_pos (&res);
	}

	if (found_prog)
		put_prog_mismatch (&res, rq.xid, vlo, vhi);
	else
	{
		rpc_log ("rpc: program %lu not here",
			 (unsigned long) rq.prog);
		put_accepted (&res, rq.xid, RPC_PROG_UNAVAIL);
	}

	return xdr_pos (&res);
}

/* ---------------------------------------------------------------- UDP */

static void
do_udp (rpc_server *s, uint8_t *in, uint8_t *out)
{
	struct sockaddr_in from;
	socklen_t flen = sizeof (from);
	ssize_t n;
	size_t rlen;

	n = recvfrom (s->udp, in, NFSD_MAXRECORD, 0,
		      (struct sockaddr *) &from, &flen);
	if (n <= 0)
		return;

	rlen = serve_one (s, in, (size_t) n, out, NFSD_MAXRECORD, &from, 0);
	if (rlen == 0)
		return;

	sendto (s->udp, out, rlen, 0, (struct sockaddr *) &from,
		sizeof (from));
}

/* ---------------------------------------------------------------- TCP */

static void
drop_conn (rpc_server *s, int slot)
{
	struct rpc_conn *c = s->conn[slot];

	if (!c)
		return;

	close (c->fd);
	free (c->buf);
	free (c);
	s->conn[slot] = NULL;
}

static void
do_accept (rpc_server *s)
{
	struct sockaddr_in from;
	socklen_t flen = sizeof (from);
	int fd, i;
	struct rpc_conn *c;

	fd = accept (s->tcp, (struct sockaddr *) &from, &flen);
	if (fd < 0)
		return;

	for (i = 0; i < RPC_MAXCONN; i++)
		if (!s->conn[i])
			break;

	if (i == RPC_MAXCONN)
	{
		/* Refusing is better than dropping an established client:
		 * the new one will retry, and NFS over TCP reconnects.
		 */
		rpc_log ("rpc: %d connections already, refusing another",
			 RPC_MAXCONN);
		close (fd);
		return;
	}

	c = calloc (1, sizeof (*c));
	if (!c)
	{
		close (fd);
		return;
	}

	c->buf = malloc (NFSD_MAXRECORD);
	if (!c->buf)
	{
		free (c);
		close (fd);
		return;
	}

	c->fd = fd;
	c->from = from;
	s->conn[i] = c;

	rpc_log ("rpc: connection from %s", inet_ntoa (from.sin_addr));
}

/*
 * Send a record: the marker with the last-fragment bit, then the body. One
 * fragment is always enough here, because a reply is built in one buffer.
 */
static int
send_record (int fd, const uint8_t *p, size_t len)
{
	uint8_t mark[4];
	uint32_t m = 0x80000000ul | (uint32_t) len;
	size_t done;
	ssize_t n;

	mark[0] = (uint8_t) (m >> 24);
	mark[1] = (uint8_t) (m >> 16);
	mark[2] = (uint8_t) (m >> 8);
	mark[3] = (uint8_t) (m);

	for (done = 0; done < 4; done += (size_t) n)
	{
		n = write (fd, mark + done, 4 - done);
		if (n <= 0)
			return -1;
	}

	for (done = 0; done < len; done += (size_t) n)
	{
		n = write (fd, p + done, len - done);
		if (n <= 0)
			return -1;
	}

	return 0;
}

/*
 * Read what is available on one connection and answer every complete record
 * in it. Returns 0 to keep the connection, -1 to drop it.
 */
static int
do_conn (rpc_server *s, int slot, uint8_t *out)
{
	struct rpc_conn *c = s->conn[slot];
	ssize_t n;

	/* Still collecting the 4 byte marker? */
	if (c->marklen < 4)
	{
		n = read (c->fd, c->mark + c->marklen, 4 - c->marklen);
		if (n <= 0)
			return -1;

		c->marklen += (int) n;
		if (c->marklen < 4)
			return 0;

		{
			uint32_t m = ((uint32_t) c->mark[0] << 24)
				   | ((uint32_t) c->mark[1] << 16)
				   | ((uint32_t) c->mark[2] << 8)
				   | ((uint32_t) c->mark[3]);

			c->last = (m & 0x80000000ul) != 0;
			c->fraglen = m & 0x7ffffffful;
		}

		if (c->have + c->fraglen > NFSD_MAXRECORD)
		{
			/* Too big to be anything we serve. Dropping the
			 * connection is the only way out: the stream cannot
			 * be resynchronised without reading it all.
			 */
			rpc_log ("rpc: record of %lu bytes is too large",
				 (unsigned long) (c->have + c->fraglen));
			return -1;
		}

		return 0;
	}

	if (c->fraglen > 0)
	{
		n = read (c->fd, c->buf + c->have, c->fraglen);
		if (n <= 0)
			return -1;

		c->have += (size_t) n;
		c->fraglen -= (uint32_t) n;
	}

	if (c->fraglen > 0)
		return 0;		/* more of this fragment to come */

	if (!c->last)
	{
		/* Another fragment belongs to this record. */
		c->marklen = 0;
		return 0;
	}

	{
		size_t rlen = serve_one (s, c->buf, c->have, out,
					 NFSD_MAXRECORD, &c->from, 1);

		c->have = 0;
		c->marklen = 0;

		if (rlen > 0 && send_record (c->fd, out, rlen) < 0)
			return -1;
	}

	return 0;
}

/* ------------------------------------------------------------- the loop */

int
rpc_run (rpc_server *s)
{
	uint8_t *in, *out;
	int rv = 0;

	in = malloc (NFSD_MAXRECORD);
	out = malloc (NFSD_MAXRECORD);
	if (!in || !out)
	{
		free (in);
		free (out);
		errno = ENOMEM;
		return -1;
	}

	while (!s->stop)
	{
		fd_set r;
		int max = -1, i, n;

		FD_ZERO (&r);

		if (s->udp >= 0)
		{
			FD_SET (s->udp, &r);
			if (s->udp > max) max = s->udp;
		}

		if (s->tcp >= 0)
		{
			FD_SET (s->tcp, &r);
			if (s->tcp > max) max = s->tcp;
		}

		for (i = 0; i < RPC_MAXCONN; i++)
		{
			if (s->conn[i])
			{
				FD_SET (s->conn[i]->fd, &r);
				if (s->conn[i]->fd > max)
					max = s->conn[i]->fd;
			}
		}

		n = select (max + 1, &r, NULL, NULL, NULL);
		if (n < 0)
		{
			if (errno == EINTR)
				continue;

			rv = -1;
			break;
		}

		if (s->udp >= 0 && FD_ISSET (s->udp, &r))
			do_udp (s, in, out);

		for (i = 0; i < RPC_MAXCONN; i++)
		{
			if (s->conn[i] && FD_ISSET (s->conn[i]->fd, &r))
			{
				if (do_conn (s, i, out) < 0)
					drop_conn (s, i);
			}
		}

		if (s->tcp >= 0 && FD_ISSET (s->tcp, &r))
			do_accept (s);
	}

	free (in);
	free (out);

	return rv;
}

/* --------------------------------------------- talking to the portmapper */

# define PMAP_PROG	100000ul
# define PMAP_VERS	2ul
# define PMAP_SET	1ul
# define PMAP_UNSET	2ul

static int
pmap_call (uint32_t proc, uint32_t prog, uint32_t vers,
	   uint32_t proto, uint32_t port, uint32_t *result)
{
	uint8_t buf[128];
	XDR x;
	struct sockaddr_in a;
	int fd;
	uint32_t v;
	ssize_t n;
	struct timeval tv;

	fd = socket (AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	tv.tv_sec = 5;
	tv.tv_usec = 0;
	setsockopt (fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));

	xdr_init (&x, buf, sizeof (buf), XDR_ENCODE);

	v = (uint32_t) (proc * 7919ul + 1);	/* any xid will do */
	xdr_u32 (&x, &v);
	v = RPC_CALL;	xdr_u32 (&x, &v);
	v = RPC_VERSION; xdr_u32 (&x, &v);
	v = PMAP_PROG;	xdr_u32 (&x, &v);
	v = PMAP_VERS;	xdr_u32 (&x, &v);
	v = proc;	xdr_u32 (&x, &v);
	v = AUTH_NONE;	xdr_u32 (&x, &v);	/* cred */
	v = 0;		xdr_u32 (&x, &v);
	v = AUTH_NONE;	xdr_u32 (&x, &v);	/* verf */
	v = 0;		xdr_u32 (&x, &v);

	v = prog;	xdr_u32 (&x, &v);
	v = vers;	xdr_u32 (&x, &v);
	v = proto;	xdr_u32 (&x, &v);
	v = port;	xdr_u32 (&x, &v);

	if (!xdr_ok (&x))
	{
		close (fd);
		return -1;
	}

	memset (&a, 0, sizeof (a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
	a.sin_port = htons (111);

	if (sendto (fd, buf, xdr_pos (&x), 0,
		    (struct sockaddr *) &a, sizeof (a)) < 0)
	{
		close (fd);
		return -1;
	}

	n = recv (fd, buf, sizeof (buf), 0);
	close (fd);

	if (n < 24)
		return -1;

	/* xid, REPLY, MSG_ACCEPTED, verifier, SUCCESS, then the result. */
	xdr_init (&x, buf, (size_t) n, XDR_DECODE);
	{
		uint32_t xid, mt, rs, vf, vl, as;

		if (!xdr_u32 (&x, &xid) || !xdr_u32 (&x, &mt)
		    || !xdr_u32 (&x, &rs) || !xdr_u32 (&x, &vf)
		    || !xdr_u32 (&x, &vl) || !xdr_skip (&x, vl)
		    || !xdr_u32 (&x, &as))
			return -1;

		if (mt != RPC_REPLY || rs != MSG_ACCEPTED || as != RPC_SUCCESS)
			return -1;

		if (result && !xdr_u32 (&x, result))
			return -1;
	}

	return 0;
}

int
rpc_pmap_set (uint32_t prog, uint32_t vers, int is_tcp, uint16_t port)
{
	uint32_t ok = 0;

	if (pmap_call (PMAP_SET, prog, vers, is_tcp ? 6 : 17, port, &ok) < 0)
		return -1;

	return ok ? 0 : -1;
}

int
rpc_pmap_unset (uint32_t prog, uint32_t vers)
{
	uint32_t ok = 0;

	if (pmap_call (PMAP_UNSET, prog, vers, 0, 0, &ok) < 0)
		return -1;

	return ok ? 0 : -1;
}
