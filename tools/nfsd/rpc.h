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
 * rpc.h -- the server half of ONC RPC (RFC 5531), as much of it as an NFS
 *          server needs.
 *
 * Written rather than taken from the MiNTLib on purpose. The library has a
 * server side -- svctcp_create and friends link -- but it has no users
 * anywhere in the tree, so nothing says it works on FreeMiNT. This way the
 * exact same code runs on the host, where it can be driven by a real Linux
 * client, and on the Atari.
 *
 * One process, one select() loop, no forking: a request is decoded,
 * answered and forgotten before the next is looked at. That suits an Atari,
 * and it means the handlers need no locking.
 */

# ifndef _nfsd_rpc_h
# define _nfsd_rpc_h

# include "xdr.h"

# include <sys/types.h>
# include <netinet/in.h>

# define RPC_VERSION		2

/* msg_type */
# define RPC_CALL		0
# define RPC_REPLY		1

/* reply_stat */
# define MSG_ACCEPTED		0
# define MSG_DENIED		1

/* accept_stat */
# define RPC_SUCCESS		0
# define RPC_PROG_UNAVAIL	1
# define RPC_PROG_MISMATCH	2
# define RPC_PROC_UNAVAIL	3
# define RPC_GARBAGE_ARGS	4
# define RPC_SYSTEM_ERR		5

/* reject_stat */
# define RPC_MISMATCH		0
# define RPC_AUTH_ERROR		1

/* auth_stat */
# define AUTH_BADCRED		1
# define AUTH_TOOWEAK		5

/* auth flavours */
# define AUTH_NONE		0
# define AUTH_UNIX		1

# define RPC_MAXGIDS		16
# define RPC_MAXMACHINE		64

/*
 * Who the caller claims to be. AUTH_UNIX is a claim and nothing more -- it
 * is the client's own word for its uid. That is all NFSv3 without Kerberos
 * ever had, which is why an export is restricted by address.
 */
typedef struct
{
	int		have;	/* 0 when the call carried AUTH_NONE */
	uint32_t	uid;
	uint32_t	gid;
	uint32_t	ngids;
	uint32_t	gids[RPC_MAXGIDS];
	char		machine[RPC_MAXMACHINE];
} rpc_cred;

typedef struct
{
	uint32_t		xid;
	uint32_t		prog;
	uint32_t		vers;
	uint32_t		proc;
	rpc_cred		cred;
	struct sockaddr_in	from;
	int			over_tcp;
} rpc_req;

/*
 * A procedure decodes its arguments from `args' and encodes its reply into
 * `res'. Returning 0 means the reply is complete and should be sent; a
 * negative return is one of the RPC_* accept_stat codes to send instead.
 *
 * A procedure that returns 0 without writing anything sends an empty reply,
 * which is what NULL does.
 */
typedef int (*rpc_proc) (rpc_req *rq, XDR *args, XDR *res);

typedef struct
{
	uint32_t	prog;
	uint32_t	vers;
	uint32_t	nproc;		/* size of the table */
	const rpc_proc *proc;		/* indexed by procedure number */
	const char *	name;		/* for messages */
} rpc_program;

/*
 * The server. Several programs can share one: the portmapper runs alone,
 * while nfsd and mountd could be registered in a single process.
 */
# define RPC_MAXPROG		4
# define RPC_MAXCONN		8

typedef struct
{
	int		udp;			/* listening UDP socket, or -1 */
	int		tcp;			/* listening TCP socket, or -1 */
	uint16_t	port;			/* the port both ended up on */

	const rpc_program *prog[RPC_MAXPROG];
	int		nprog;

	struct rpc_conn *conn[RPC_MAXCONN];
	int		stop;
} rpc_server;

/*
 * Create the sockets. port 0 asks the system for any free port, which is
 * what a program that registers with the portmapper wants; the portmapper
 * itself passes 111. Returns 0 or -1 with errno set.
 */
int	rpc_listen	(rpc_server *s, uint16_t port);

int	rpc_add_program	(rpc_server *s, const rpc_program *p);

/* Serve until rpc_stop() is called. Returns 0, or -1 on a fatal error. */
int	rpc_run		(rpc_server *s);
void	rpc_stop	(rpc_server *s);
void	rpc_close	(rpc_server *s);

/*
 * Register with the local portmapper, or remove the registration. These
 * speak PMAP_SET/PMAP_UNSET to 127.0.0.1:111 over UDP, so they work
 * against the portmapper in this package without needing its headers.
 */
int	rpc_pmap_set	(uint32_t prog, uint32_t vers, int is_tcp, uint16_t port);
int	rpc_pmap_unset	(uint32_t prog, uint32_t vers);

/* Diagnostics: set once at startup, read by all three daemons. */
extern int rpc_verbose;

void	rpc_log		(const char *fmt, ...);

# endif /* _nfsd_rpc_h */
