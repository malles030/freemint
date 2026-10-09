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
 * exports.h -- which directories are offered, and to whom.
 *
 * The file is read once at startup, in the spirit of /etc/exports but
 * deliberately smaller: one line per export, a single client specification
 * and a short list of options.
 *
 *   /c/shared       192.168.1.0/24(rw,all_squash,anonuid=0,anongid=0)
 *   /c/pub          *(ro)
 *
 * An NFSv3 export is restricted by address and nothing else. AUTH_UNIX
 * carries the client's own word for its uid, so anyone who can reach the
 * port and spoof an address is inside. That is a property of the protocol,
 * not of this implementation, which is why the address list is the real
 * control and why the default is read only.
 */

# ifndef _nfsd_exports_h
# define _nfsd_exports_h

# include "config.h"

# include <stdint.h>
# include <sys/types.h>

typedef struct
{
	uint32_t	id;		/* index; travels in every handle */
	char		path[NFSD_MAXPATH];	/* the local directory */

	uint32_t	addr;		/* allowed client, host order */
	uint32_t	mask;		/* 0 means any address */

	int		ro;		/* no writes at all */
	int		all_squash;	/* map every caller to anonuid */
	int		root_squash;	/* map uid 0 only; the default */
	uint32_t	anonuid;
	uint32_t	anongid;
} nfsd_export;

/*
 * Read the file. Returns the number of exports, or -1 with a message on
 * stderr. An empty or missing file is an error: a server with nothing to
 * offer is a configuration mistake, not a working state.
 */
int	exports_load	(const char *file);

int	exports_count	(void);
const nfsd_export *exports_get (uint32_t id);

/* Look one up by the path a client asked MOUNT for. NULL when not exported. */
const nfsd_export *exports_by_path (const char *path);

/* May this address use that export? */
int	exports_allowed	(const nfsd_export *e, uint32_t client_addr);

/*
 * Turn the caller's claimed uid/gid into the ones to use, following the
 * export's squash options.
 */
void	exports_squash	(const nfsd_export *e, uint32_t *uid, uint32_t *gid);

/* For the startup banner and for mountd's EXPORT procedure. */
void	exports_print	(void);

# endif /* _nfsd_exports_h */
