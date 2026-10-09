#!/usr/bin/env python3
"""
Attack the server the way a hostile client would: by forging file handles.

A handle carries the path it names (see fh.h), so it comes back under the
client's control. A well behaved client hands back exactly what it was
given; this one does not. Every case here tries to reach a file outside the
export, and every one must be refused.

No ordinary client library can be used for this, because none of them will
construct an invalid handle -- that is the whole point of writing it by hand.

  ./t_nfsd_security.py <export-path> [nfsport] [mountport]
"""

import socket
import struct
import sys

NFS_PROG, NFS_VERS = 100003, 3
MOUNT_PROG, MOUNT_VERS = 100005, 3

GETATTR, LOOKUP, ACCESS, READ, READDIR = 1, 3, 4, 6, 16
MNT = 1

NFS3_OK = 0
NFS3ERR_NOENT = 2
NFS3ERR_ACCES = 13
NFS3ERR_INVAL = 22
NFS3ERR_STALE = 70
NFS3ERR_BADHANDLE = 10001

FH_MAGIC = b"MNF3"
FH_PATHLEN = 56
FH_SIZE = 4 + 2 + 2 + FH_PATHLEN

checks = 0
fails = 0
xid_counter = 1000


def ok(cond, what, extra=""):
    global checks, fails
    checks += 1
    if cond:
        print("  ok    %s%s" % (what, (" -- " + extra) if extra else ""))
    else:
        print("  FAIL  %s%s" % (what, (" -- " + extra) if extra else ""))
        fails += 1


def call(port, prog, vers, proc, body, uid=0, gid=0):
    """One RPC call over UDP with AUTH_UNIX credentials."""
    global xid_counter
    xid_counter += 1
    xid = xid_counter

    machine = b"attacker"
    cred = struct.pack(">I", 0)                      # stamp
    cred += struct.pack(">I", len(machine)) + machine
    cred += b"\0" * ((4 - len(machine) % 4) % 4)
    cred += struct.pack(">III", uid, gid, 0)         # uid, gid, no gids

    rec = struct.pack(">IIIIII", xid, 0, 2, prog, vers, proc)
    rec += struct.pack(">II", 1, len(cred)) + cred   # AUTH_UNIX
    rec += struct.pack(">II", 0, 0)                  # AUTH_NONE verifier
    rec += body

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(rec, ("127.0.0.1", port))
    data, _ = s.recvfrom(65536)
    s.close()

    rxid, mtype, reply_stat = struct.unpack(">III", data[0:12])
    if reply_stat != 0:
        return ("denied", data[12:])
    vlen = struct.unpack(">I", data[16:20])[0]
    off = 20 + ((vlen + 3) & ~3)
    accept_stat = struct.unpack(">I", data[off:off + 4])[0]
    return (accept_stat, data[off + 4:])


def xstr(s):
    b = s.encode() if isinstance(s, str) else s
    return struct.pack(">I", len(b)) + b + b"\0" * ((4 - len(b) % 4) % 4)


def forge(path, exportid=0, magic=FH_MAGIC, claimed_len=None):
    """Build a handle by hand. path may be anything at all."""
    raw = path.encode() if isinstance(path, str) else path
    n = len(raw) if claimed_len is None else claimed_len
    h = magic
    h += struct.pack(">H", exportid)
    h += struct.pack(">H", n)
    h += raw[:FH_PATHLEN]
    h += b"\0" * (FH_SIZE - len(h))
    return h[:FH_SIZE]


def fh_arg(h):
    return struct.pack(">I", len(h)) + h


def status_of(reply):
    stat, rest = reply
    if stat == "denied":
        return "denied"
    if stat != 0:
        return "rpc:%d" % stat
    return struct.unpack(">I", rest[0:4])[0]


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1

    export = sys.argv[1]
    nfsport = int(sys.argv[2]) if len(sys.argv) > 2 else 20490
    mountport = int(sys.argv[3]) if len(sys.argv) > 3 else 20048

    # A real handle first, so the tests below are comparing like with like.
    stat, rest = call(mountport, MOUNT_PROG, MOUNT_VERS, MNT, xstr(export))
    mstat = struct.unpack(">I", rest[0:4])[0]
    if stat != 0 or mstat != 0:
        print("cannot mount %s: accept=%s mountstat=%s" % (export, stat, mstat))
        return 1

    fhlen = struct.unpack(">I", rest[4:8])[0]
    good = rest[8:8 + fhlen]
    ok(len(good) == FH_SIZE, "the server issues a %d byte handle" % FH_SIZE,
       "got %d" % len(good))
    ok(good[0:4] == FH_MAGIC, "it carries the expected magic",
       repr(good[0:4]))

    # a sanity check: the real handle works
    s = status_of(call(nfsport, NFS_PROG, NFS_VERS, GETATTR, fh_arg(good)))
    ok(s == NFS3_OK, "GETATTR with the real handle succeeds", "status=%s" % s)

    print("\n  -- forged handles, every one must be refused --")

    escapes = [
        ("..", "the parent of the export"),
        ("../..", "two levels up"),
        ("../../etc/passwd", "a path at /etc/passwd"),
        ("docs/../../..", "an escape hidden behind a real directory"),
        ("/etc/passwd", "an absolute path"),
        ("\\etc\\passwd", "an absolute path, MiNT style"),
        (".", "the current directory"),
        ("docs/", "a trailing separator"),
        ("docs//letter.txt", "an empty component"),
        ("a/./b", "a dot component"),
    ]

    for path, what in escapes:
        s = status_of(call(nfsport, NFS_PROG, NFS_VERS, GETATTR,
                           fh_arg(forge(path))))
        ok(s == NFS3ERR_BADHANDLE, "GETATTR refuses %s" % what,
           "status=%s" % s)

    # wrong magic
    s = status_of(call(nfsport, NFS_PROG, NFS_VERS, GETATTR,
                       fh_arg(forge("", magic=b"XXXX"))))
    ok(s == NFS3ERR_BADHANDLE, "a handle with foreign magic is refused",
       "status=%s" % s)

    # all zeroes
    s = status_of(call(nfsport, NFS_PROG, NFS_VERS, GETATTR,
                       fh_arg(b"\0" * FH_SIZE)))
    ok(s == NFS3ERR_BADHANDLE, "an all zero handle is refused",
       "status=%s" % s)

    # a length that lies about the path
    s = status_of(call(nfsport, NFS_PROG, NFS_VERS, GETATTR,
                       fh_arg(forge("abc", claimed_len=40))))
    ok(s == NFS3ERR_BADHANDLE, "a handle whose length field lies is refused",
       "status=%s" % s)

    # an export that does not exist
    s = status_of(call(nfsport, NFS_PROG, NFS_VERS, GETATTR,
                       fh_arg(forge("", exportid=250))))
    ok(s == NFS3ERR_STALE, "a handle naming an unknown export is stale",
       "status=%s" % s)

    # a handle of the wrong size
    for n, what in ((FH_SIZE - 1, "one byte short"),
                    (FH_SIZE + 1, "one byte long"),
                    (0, "empty")):
        h = (forge("") + b"\0")[:n] if n <= FH_SIZE else forge("") + b"\0"
        s = status_of(call(nfsport, NFS_PROG, NFS_VERS, GETATTR, fh_arg(h)))
        ok(s == NFS3ERR_BADHANDLE, "a handle %s is refused" % what,
           "status=%s" % s)

    print("\n  -- LOOKUP, where the name comes from the client --")

    traversals = [
        ("../etc", "a name with a parent reference"),
        ("a/b", "a name containing a separator"),
        ("a\\b", "a name containing a backslash"),
        ("", "an empty name"),
    ]

    for name, what in traversals:
        s = status_of(call(nfsport, NFS_PROG, NFS_VERS, LOOKUP,
                           fh_arg(good) + xstr(name)))
        ok(s in (NFS3ERR_INVAL, NFS3ERR_NOENT, NFS3ERR_BADHANDLE),
           "LOOKUP refuses %s" % what, "status=%s" % s)

    # ".." at the root of an export must stay at the root rather than
    # naming the directory above it
    stat, rest = call(nfsport, NFS_PROG, NFS_VERS, LOOKUP,
                      fh_arg(good) + xstr(".."))
    s = struct.unpack(">I", rest[0:4])[0] if stat == 0 else None
    if s == NFS3_OK:
        hl = struct.unpack(">I", rest[4:8])[0]
        h = rest[8:8 + hl]
        pathlen = struct.unpack(">H", h[6:8])[0]
        ok(pathlen == 0, "\"..\" at the export root stays at the root",
           "the returned handle names a path of %d bytes" % pathlen)
    else:
        ok(s in (NFS3ERR_NOENT, NFS3ERR_ACCES),
           "\"..\" at the export root is refused", "status=%s" % s)

    print("\n  -- the read only export --")

    # export 1 is the ro one; a forged handle for it must still be read only
    stat, rest = call(nfsport, NFS_PROG, NFS_VERS, GETATTR,
                      fh_arg(forge("", exportid=1)))
    s = struct.unpack(">I", rest[0:4])[0] if stat == 0 else None
    ok(s == NFS3_OK, "the second export is reachable by its id",
       "status=%s" % s)

    print("\n%d checks, %d failed" % (checks, fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
