#!/usr/bin/env python3
"""
End to end test of nfsd and mountd with libnfs as the client.

libnfs is a complete NFSv3 implementation of its own, written by someone
else and sharing no code with this server, so a test that passes here says
the server follows the protocol rather than that it agrees with itself.
It also runs entirely in userspace, which means no root and no mount(8).

  ./t_nfsd_libnfs.py <export-path> [nfsport] [mountport]

The server must already be running with -n (no port mapper): libnfs is told
the ports explicitly through the URL, so port 111 is not needed.
"""

import ctypes
import os
import sys

lib = ctypes.CDLL("libnfs.so.14")

lib.nfs_init_context.restype = ctypes.c_void_p
lib.nfs_destroy_context.argtypes = [ctypes.c_void_p]
lib.nfs_get_error.restype = ctypes.c_char_p
lib.nfs_get_error.argtypes = [ctypes.c_void_p]
lib.nfs_mount.restype = ctypes.c_int
lib.nfs_mount.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
lib.nfs_opendir.restype = ctypes.c_int
lib.nfs_opendir.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                            ctypes.POINTER(ctypes.c_void_p)]
lib.nfs_readdir.restype = ctypes.c_void_p
lib.nfs_readdir.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
lib.nfs_closedir.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
lib.nfs_open.restype = ctypes.c_int
lib.nfs_open.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int,
                         ctypes.POINTER(ctypes.c_void_p)]
lib.nfs_read.restype = ctypes.c_int
lib.nfs_read.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64,
                         ctypes.c_void_p]
lib.nfs_close.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
lib.nfs_set_version.restype = ctypes.c_int
lib.nfs_set_version.argtypes = [ctypes.c_void_p, ctypes.c_int]
lib.nfs_creat.restype = ctypes.c_int
lib.nfs_creat.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int,
                          ctypes.POINTER(ctypes.c_void_p)]
lib.nfs_write.restype = ctypes.c_int
lib.nfs_write.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64,
                          ctypes.c_void_p]
lib.nfs_mkdir.restype = ctypes.c_int
lib.nfs_mkdir.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
lib.nfs_rmdir.restype = ctypes.c_int
lib.nfs_rmdir.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
lib.nfs_unlink.restype = ctypes.c_int
lib.nfs_unlink.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
lib.nfs_rename.restype = ctypes.c_int
lib.nfs_rename.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
lib.nfs_truncate.restype = ctypes.c_int
lib.nfs_truncate.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint64]
lib.nfs_chmod.restype = ctypes.c_int
lib.nfs_chmod.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
lib.nfs_symlink.restype = ctypes.c_int
lib.nfs_symlink.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
lib.nfs_link.restype = ctypes.c_int
lib.nfs_link.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
lib.nfs_fsync.restype = ctypes.c_int
lib.nfs_fsync.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
lib.nfs_readlink.restype = ctypes.c_int
lib.nfs_readlink.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                             ctypes.c_char_p, ctypes.c_int]


class NfsUrl(ctypes.Structure):
    _fields_ = [
        ("server", ctypes.c_char_p),
        ("path", ctypes.c_char_p),
        ("file", ctypes.c_char_p),
    ]


class NfsDirent(ctypes.Structure):
    """The head of libnfs's struct nfsdirent. Only the first fields are
    read, which are stable across versions: the name and the inode."""
    _fields_ = [
        ("next", ctypes.c_void_p),
        ("name", ctypes.c_char_p),
        ("inode", ctypes.c_uint64),
        ("type", ctypes.c_uint32),
        ("mode", ctypes.c_uint32),
        ("size", ctypes.c_uint64),
    ]


checks = 0
fails = 0


def ok(cond, what, extra=""):
    global checks, fails
    checks += 1
    if cond:
        print("  ok    %s%s" % (what, (" -- " + extra) if extra else ""))
    else:
        print("  FAIL  %s%s" % (what, (" -- " + extra) if extra else ""))
        fails += 1


def err(ctx):
    e = lib.nfs_get_error(ctx)
    return e.decode("utf-8", "replace") if e else "?"


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1

    export = sys.argv[1]
    nfsport = sys.argv[2] if len(sys.argv) > 2 else "20490"
    mountport = sys.argv[3] if len(sys.argv) > 3 else "20048"

    ctx = lib.nfs_init_context()
    if not ctx:
        print("cannot create an NFS context")
        return 1

    # nfs_mount takes server and path separately, so the URL has to go
    # through the parser first: that is what applies the nfsport and
    # mountport parameters to the context and lets libnfs skip the port
    # mapper, which is what makes this runnable without root.
    url = "nfs://127.0.0.1%s?version=3&nfsport=%s&mountport=%s" % (
        export, nfsport, mountport)
    print("mounting %s\n" % url)

    lib.nfs_parse_url_dir.restype = ctypes.POINTER(NfsUrl)
    lib.nfs_parse_url_dir.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

    up = lib.nfs_parse_url_dir(ctx, url.encode())
    if not up:
        print("cannot parse the URL: %s" % err(ctx))
        lib.nfs_destroy_context(ctx)
        return 1

    u = up.contents
    rc = lib.nfs_mount(ctx, u.server, u.path)
    ok(rc == 0, "MOUNT succeeds", "" if rc == 0 else err(ctx))
    if rc != 0:
        lib.nfs_destroy_context(ctx)
        print("\n%d checks, %d failed" % (checks, fails))
        return 1

    # ---------------------------------------------------------- readdir
    d = ctypes.c_void_p()
    rc = lib.nfs_opendir(ctx, b"/", ctypes.byref(d))
    ok(rc == 0, "opendir of the export root", "" if rc == 0 else err(ctx))

    names = {}
    if rc == 0:
        while True:
            p = lib.nfs_readdir(ctx, d)
            if not p:
                break
            e = ctypes.cast(p, ctypes.POINTER(NfsDirent)).contents
            nm = e.name.decode("utf-8", "replace")
            names[nm] = (e.type, e.mode, e.size, e.inode)
        lib.nfs_closedir(ctx, d)

    ok("." in names, "the listing contains \".\"")
    ok(".." in names, "the listing contains \"..\"")
    ok("readme.txt" in names, "the listing contains readme.txt",
       "found: %s" % ", ".join(sorted(k for k in names if not k.startswith("."))))
    ok("docs" in names, "the listing contains the docs directory")

    if "readme.txt" in names:
        t, mode, size, ino = names["readme.txt"]
        ok(t == 1, "readme.txt has type NF3REG", "type=%d" % t)
        ok(size > 0, "readme.txt has a non zero size", "size=%d" % size)
        ok(ino != 0, "readme.txt has a file id", "fileid=%d" % ino)

    if "docs" in names:
        t = names["docs"][0]
        ok(t == 2, "docs has type NF3DIR", "type=%d" % t)

    # ------------------------------------------------------------ lookup
    st = (ctypes.c_char * 256)()
    rc = lib.nfs_stat64(ctx, b"/readme.txt", ctypes.byref(st))
    ok(rc == 0, "stat of /readme.txt", "" if rc == 0 else err(ctx))

    rc = lib.nfs_stat64(ctx, b"/does-not-exist", ctypes.byref(st))
    ok(rc != 0, "stat of a missing file fails")

    rc = lib.nfs_stat64(ctx, b"/docs/letter.txt", ctypes.byref(st))
    ok(rc == 0, "stat through a subdirectory", "" if rc == 0 else err(ctx))

    # -------------------------------------------------------------- read
    fh = ctypes.c_void_p()
    rc = lib.nfs_open(ctx, b"/readme.txt", os.O_RDONLY, ctypes.byref(fh))
    ok(rc == 0, "open of /readme.txt", "" if rc == 0 else err(ctx))

    if rc == 0:
        buf = (ctypes.c_char * 4096)()
        n = lib.nfs_read(ctx, fh, 4096, ctypes.byref(buf))
        got = bytes(buf[:n]) if n > 0 else b""
        ok(n > 0, "read returns data", "%d bytes" % n)
        ok(b"atari" in got, "the content is what the file holds",
           repr(got[:40]))

        # reading again at EOF must return 0, not an error
        n2 = lib.nfs_read(ctx, fh, 4096, ctypes.byref(buf))
        ok(n2 == 0, "a read at the end of the file returns 0",
           "got %d" % n2)
        lib.nfs_close(ctx, fh)

    # NFS has no open: it is a client side notion, so opening a directory
    # cannot fail at the protocol level. What must fail is the READ, which
    # the server answers with NFS3ERR_ISDIR.
    rc = lib.nfs_open(ctx, b"/docs", os.O_RDONLY, ctypes.byref(fh))
    if rc == 0:
        buf = (ctypes.c_char * 256)()
        n = lib.nfs_read(ctx, fh, 256, ctypes.byref(buf))
        ok(n < 0, "reading a directory as a file fails", "returned %d" % n)
        lib.nfs_close(ctx, fh)
    else:
        ok(True, "reading a directory as a file fails",
           "the client refused it before asking")

    # ======================================================== writing

    print()

    # Start from a known state. A run that died half way through would
    # otherwise leave files behind and the next run would report EXIST for
    # everything, which looks like a server fault and is not one.
    import shutil
    for leftover in ("newdir", "newfile.txt"):
        p = os.path.join(export, leftover)
        if os.path.isdir(p):
            shutil.rmtree(p, ignore_errors=True)
        elif os.path.exists(p):
            os.unlink(p)

    # ------------------------------------------------------- CREATE, WRITE
    fh = ctypes.c_void_p()
    rc = lib.nfs_creat(ctx, b"/newfile.txt", 0o644, ctypes.byref(fh))
    ok(rc == 0, "CREATE a new file", "" if rc == 0 else err(ctx))

    payload = b"written over NFS by libnfs\n"
    if rc == 0:
        buf = ctypes.create_string_buffer(payload, len(payload))
        n = lib.nfs_write(ctx, fh, len(payload), ctypes.byref(buf))
        ok(n == len(payload), "WRITE the whole payload",
           "wrote %d of %d" % (n, len(payload)))
        rc2 = lib.nfs_fsync(ctx, fh)
        ok(rc2 == 0, "COMMIT succeeds", "" if rc2 == 0 else err(ctx))
        lib.nfs_close(ctx, fh)

    # read it back through a fresh open: proves it reached the file system
    rc = lib.nfs_open(ctx, b"/newfile.txt", os.O_RDONLY, ctypes.byref(fh))
    if rc == 0:
        buf = (ctypes.c_char * 256)()
        n = lib.nfs_read(ctx, fh, 256, ctypes.byref(buf))
        got = bytes(buf[:n]) if n > 0 else b""
        ok(got == payload, "the data reads back byte for byte", repr(got[:40]))
        lib.nfs_close(ctx, fh)
    else:
        ok(False, "reopen the written file", err(ctx))

    # and that the server really created it on disk
    ok(os.path.exists(os.path.join(export, "newfile.txt")),
       "the file exists locally on the server")

    # ------------------------------------------------------------ SETATTR
    rc = lib.nfs_truncate(ctx, b"/newfile.txt", 5)
    ok(rc == 0, "SETATTR truncates", "" if rc == 0 else err(ctx))
    if rc == 0:
        ok(os.path.getsize(os.path.join(export, "newfile.txt")) == 5,
           "the file is 5 bytes locally")

    rc = lib.nfs_chmod(ctx, b"/newfile.txt", 0o600)
    ok(rc == 0, "SETATTR changes the mode", "" if rc == 0 else err(ctx))
    if rc == 0:
        m = os.stat(os.path.join(export, "newfile.txt")).st_mode & 0o777
        ok(m == 0o600, "the mode is 0600 locally", oct(m))

    # -------------------------------------------------------------- MKDIR
    rc = lib.nfs_mkdir(ctx, b"/newdir")
    ok(rc == 0, "MKDIR", "" if rc == 0 else err(ctx))
    ok(os.path.isdir(os.path.join(export, "newdir")),
       "the directory exists locally")

    # creating it twice must fail
    rc = lib.nfs_mkdir(ctx, b"/newdir")
    ok(rc != 0, "MKDIR of an existing name fails")

    # ------------------------------------------------------------- RENAME
    rc = lib.nfs_rename(ctx, b"/newfile.txt", b"/newdir/moved.txt")
    ok(rc == 0, "RENAME into a subdirectory", "" if rc == 0 else err(ctx))
    ok(os.path.exists(os.path.join(export, "newdir", "moved.txt")),
       "the file is at its new place locally")
    ok(not os.path.exists(os.path.join(export, "newfile.txt")),
       "and gone from the old one")

    # ------------------------------------------------------ SYMLINK, LINK
    rc = lib.nfs_symlink(ctx, b"moved.txt", b"/newdir/link")
    ok(rc == 0, "SYMLINK", "" if rc == 0 else err(ctx))
    if rc == 0:
        tgt = (ctypes.c_char * 256)()
        rc2 = lib.nfs_readlink(ctx, b"/newdir/link", tgt, 256)
        ok(rc2 == 0 and tgt.value == b"moved.txt", "READLINK gives the target",
           repr(tgt.value))

    rc = lib.nfs_link(ctx, b"/newdir/moved.txt", b"/newdir/hard")
    ok(rc == 0, "LINK makes a hard link", "" if rc == 0 else err(ctx))
    if rc == 0:
        a = os.stat(os.path.join(export, "newdir", "moved.txt"))
        ok(a.st_nlink == 2, "the link count is 2", "nlink=%d" % a.st_nlink)

    # ------------------------------------------------------ REMOVE, RMDIR
    rc = lib.nfs_rmdir(ctx, b"/newdir")
    ok(rc != 0, "RMDIR of a non empty directory fails")

    for f in (b"/newdir/moved.txt", b"/newdir/hard", b"/newdir/link"):
        rc = lib.nfs_unlink(ctx, f)
        ok(rc == 0, "REMOVE %s" % f.decode(), "" if rc == 0 else err(ctx))

    rc = lib.nfs_rmdir(ctx, b"/newdir")
    ok(rc == 0, "RMDIR of the emptied directory", "" if rc == 0 else err(ctx))
    ok(not os.path.exists(os.path.join(export, "newdir")),
       "it is gone locally")

    # -------------------------------------------------- the read only export
    # The second export in the test file is ro. Mounting it and trying to
    # write must be refused by the server, not by the client.
    ctx2 = lib.nfs_init_context()
    url2 = "nfs://127.0.0.1%s/pub?version=3&nfsport=%s&mountport=%s" % (
        export, nfsport, mountport)
    up2 = lib.nfs_parse_url_dir(ctx2, url2.encode())
    if up2:
        u2 = up2.contents
        if lib.nfs_mount(ctx2, u2.server, u2.path) == 0:
            fh2 = ctypes.c_void_p()
            rc = lib.nfs_creat(ctx2, b"/nope.txt", 0o644, ctypes.byref(fh2))
            ok(rc != 0, "CREATE on a read only export is refused",
               err(ctx2).split(":")[-1].strip())
            rc = lib.nfs_mkdir(ctx2, b"/nope")
            ok(rc != 0, "MKDIR on a read only export is refused")
        else:
            ok(False, "mount the read only export", err(ctx2))
    lib.nfs_destroy_context(ctx2)

    lib.nfs_destroy_context(ctx)

    print("\n%d checks, %d failed" % (checks, fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
