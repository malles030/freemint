#!/usr/bin/env python3
"""
Independent test of the port mapper, over both UDP and TCP.

Written in Python and encoding the packets by hand on purpose: driving the
C server with the C client would only prove the two agree with each other,
not that either follows RFC 5531. Everything here is built from the RFC's
field order so that a disagreement shows up as a failure.

  ./t_portmap.py [port]        default 10111
"""

import socket
import struct
import subprocess
import sys
import time
import os

PMAP_PROG, PMAP_VERS = 100000, 2
NULL, SET, UNSET, GETPORT, DUMP, CALLIT = 0, 1, 2, 3, 4, 5
IPPROTO_TCP, IPPROTO_UDP = 6, 17

checks = 0
fails = 0


def ok(cond, what):
    global checks, fails
    checks += 1
    if cond:
        print("  ok    %s" % what)
    else:
        print("  FAIL  %s" % what)
        fails += 1


def call_body(xid, prog, vers, proc, body=b""):
    """An RPC call with AUTH_NONE credentials and verifier."""
    return struct.pack(">IIIIII", xid, 0, 2, prog, vers, proc) + \
        struct.pack(">IIII", 0, 0, 0, 0) + body


def parse_reply(buf, xid):
    """Return (accept_stat, rest) or raise."""
    if len(buf) < 24:
        raise ValueError("reply too short: %d bytes" % len(buf))
    rxid, mtype, reply_stat = struct.unpack(">III", buf[0:12])
    if rxid != xid:
        raise ValueError("xid %d != %d" % (rxid, xid))
    if mtype != 1:
        raise ValueError("not a REPLY: %d" % mtype)
    if reply_stat != 0:
        # MSG_DENIED
        return ("denied", buf[12:])
    vflav, vlen = struct.unpack(">II", buf[12:20])
    off = 20 + ((vlen + 3) & ~3)
    (accept_stat,) = struct.unpack(">I", buf[off:off + 4])
    return (accept_stat, buf[off + 4:])


def udp_call(port, proc, body=b"", xid=None, timeout=3):
    xid = xid if xid is not None else int(time.time() * 1000) & 0x7fffffff
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(call_body(xid, PMAP_PROG, PMAP_VERS, proc, body),
             ("127.0.0.1", port))
    data, _ = s.recvfrom(65536)
    s.close()
    return parse_reply(data, xid)


def tcp_call(port, proc, body=b"", xid=None, timeout=3, prog=PMAP_PROG,
             vers=PMAP_VERS):
    """Same call over TCP, which means RPC record marking."""
    xid = xid if xid is not None else int(time.time() * 1000) & 0x7fffffff
    rec = call_body(xid, prog, vers, proc, body)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(("127.0.0.1", port))
    s.sendall(struct.pack(">I", 0x80000000 | len(rec)) + rec)

    # read the marker, then the fragment
    out = b""
    while True:
        hdr = b""
        while len(hdr) < 4:
            c = s.recv(4 - len(hdr))
            if not c:
                raise ValueError("connection closed waiting for marker")
            hdr += c
        (mark,) = struct.unpack(">I", hdr)
        last, flen = mark & 0x80000000, mark & 0x7fffffff
        frag = b""
        while len(frag) < flen:
            c = s.recv(flen - len(frag))
            if not c:
                raise ValueError("connection closed mid fragment")
            frag += c
        out += frag
        if last:
            break
    s.close()
    return parse_reply(out, xid)


def mapping(prog, vers, prot, port):
    return struct.pack(">IIII", prog, vers, prot, port)


def test_null(port):
    stat, rest = udp_call(port, NULL)
    ok(stat == 0, "NULL over UDP is accepted")
    ok(len(rest) == 0, "NULL has an empty body")

    stat, rest = tcp_call(port, NULL)
    ok(stat == 0, "NULL over TCP is accepted")


def test_self_registration(port):
    stat, rest = udp_call(port, GETPORT, mapping(PMAP_PROG, PMAP_VERS,
                                                 IPPROTO_UDP, 0))
    ok(stat == 0, "GETPORT is accepted")
    (p,) = struct.unpack(">I", rest[0:4])
    ok(p == port, "the mapper has registered itself on udp (%d)" % p)

    stat, rest = udp_call(port, GETPORT, mapping(PMAP_PROG, PMAP_VERS,
                                                 IPPROTO_TCP, 0))
    (p,) = struct.unpack(">I", rest[0:4])
    ok(p == port, "and on tcp (%d)" % p)


def test_set_get_unset(port):
    # register a fictional program
    stat, rest = udp_call(port, SET, mapping(999999, 1, IPPROTO_TCP, 2049))
    ok(stat == 0, "SET is accepted")
    (b,) = struct.unpack(">I", rest[0:4])
    ok(b == 1, "SET from loopback returns TRUE")

    stat, rest = udp_call(port, GETPORT, mapping(999999, 1, IPPROTO_TCP, 0))
    (p,) = struct.unpack(">I", rest[0:4])
    ok(p == 2049, "GETPORT finds it")

    # the wrong protocol must not find it
    stat, rest = udp_call(port, GETPORT, mapping(999999, 1, IPPROTO_UDP, 0))
    (p,) = struct.unpack(">I", rest[0:4])
    ok(p == 0, "GETPORT on the other protocol returns 0")

    # an unregistered program
    stat, rest = udp_call(port, GETPORT, mapping(888888, 1, IPPROTO_TCP, 0))
    (p,) = struct.unpack(">I", rest[0:4])
    ok(p == 0, "GETPORT for an unknown program returns 0")

    # re-register on a different port: must replace
    udp_call(port, SET, mapping(999999, 1, IPPROTO_TCP, 2050))
    stat, rest = udp_call(port, GETPORT, mapping(999999, 1, IPPROTO_TCP, 0))
    (p,) = struct.unpack(">I", rest[0:4])
    ok(p == 2050, "re-registering replaces the port")

    stat, rest = udp_call(port, UNSET, mapping(999999, 1, 0, 0))
    (b,) = struct.unpack(">I", rest[0:4])
    ok(b == 1, "UNSET returns TRUE")

    stat, rest = udp_call(port, GETPORT, mapping(999999, 1, IPPROTO_TCP, 0))
    (p,) = struct.unpack(">I", rest[0:4])
    ok(p == 0, "after UNSET the mapping is gone")


def test_dump(port):
    stat, rest = udp_call(port, DUMP)
    ok(stat == 0, "DUMP is accepted")

    entries = []
    off = 0
    while off + 4 <= len(rest):
        (more,) = struct.unpack(">I", rest[off:off + 4])
        off += 4
        if more == 0:
            break
        if off + 16 > len(rest):
            ok(False, "DUMP entry is truncated")
            return
        entries.append(struct.unpack(">IIII", rest[off:off + 16]))
        off += 16

    ok(len(entries) >= 2, "DUMP lists at least the mapper itself (%d entries)"
       % len(entries))
    ok(all(e[0] == PMAP_PROG for e in entries),
       "every DUMP entry is the port mapper")
    ok(off == len(rest), "DUMP list ends exactly at the end of the reply")


def test_callit_refused(port):
    stat, rest = udp_call(port, CALLIT, struct.pack(">IIII", 100003, 3, 0, 0))
    ok(stat == 3, "CALLIT answers PROC_UNAVAIL (%s), not a reflected call"
       % stat)


def test_errors(port):
    # a procedure that does not exist at all
    stat, rest = udp_call(port, 99)
    ok(stat == 3, "unknown procedure gives PROC_UNAVAIL")

    # right program, wrong version
    stat, rest = tcp_call(port, NULL, vers=99)
    ok(stat == 2, "wrong version gives PROG_MISMATCH")
    if stat == 2 and len(rest) >= 8:
        lo, hi = struct.unpack(">II", rest[0:8])
        ok(lo == PMAP_VERS and hi == PMAP_VERS,
           "and reports the version range %d..%d" % (lo, hi))

    # a program we do not serve
    stat, rest = tcp_call(port, NULL, prog=123456)
    ok(stat == 1, "unknown program gives PROG_UNAVAIL")

    # truncated arguments
    stat, rest = udp_call(port, GETPORT, b"\x00\x00")
    ok(stat == 4, "short arguments give GARBAGE_ARGS")


def test_bad_rpc_version(port):
    xid = 4242
    body = struct.pack(">IIIIII", xid, 0, 99, PMAP_PROG, PMAP_VERS, NULL) + \
        struct.pack(">IIII", 0, 0, 0, 0)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.sendto(body, ("127.0.0.1", port))
    data, _ = s.recvfrom(65536)
    s.close()
    rxid, mtype, reply_stat = struct.unpack(">III", data[0:12])
    ok(reply_stat == 1, "RPC version 99 is denied")
    (why,) = struct.unpack(">I", data[12:16])
    ok(why == 0, "with reject_stat RPC_MISMATCH")


def test_tcp_two_calls_one_connection(port):
    """A real client reuses the connection; the record loop must cope."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(("127.0.0.1", port))

    good = 0
    for i in range(3):
        xid = 7000 + i
        rec = call_body(xid, PMAP_PROG, PMAP_VERS, GETPORT,
                        mapping(PMAP_PROG, PMAP_VERS, IPPROTO_UDP, 0))
        s.sendall(struct.pack(">I", 0x80000000 | len(rec)) + rec)
        hdr = b""
        while len(hdr) < 4:
            hdr += s.recv(4 - len(hdr))
        (mark,) = struct.unpack(">I", hdr)
        flen = mark & 0x7fffffff
        frag = b""
        while len(frag) < flen:
            frag += s.recv(flen - len(frag))
        stat, rest = parse_reply(frag, xid)
        if stat == 0 and struct.unpack(">I", rest[0:4])[0] == port:
            good += 1
    s.close()
    ok(good == 3, "three calls on one TCP connection all answered (%d/3)"
       % good)


def test_split_record(port):
    """Send one record in two TCP writes, split mid-header."""
    xid = 7777
    rec = call_body(xid, PMAP_PROG, PMAP_VERS, GETPORT,
                    mapping(PMAP_PROG, PMAP_VERS, IPPROTO_UDP, 0))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(("127.0.0.1", port))
    whole = struct.pack(">I", 0x80000000 | len(rec)) + rec
    s.sendall(whole[:6])
    time.sleep(0.15)
    s.sendall(whole[6:])
    hdr = b""
    while len(hdr) < 4:
        hdr += s.recv(4 - len(hdr))
    (mark,) = struct.unpack(">I", hdr)
    flen = mark & 0x7fffffff
    frag = b""
    while len(frag) < flen:
        frag += s.recv(flen - len(frag))
    s.close()
    stat, rest = parse_reply(frag, xid)
    ok(stat == 0 and struct.unpack(">I", rest[0:4])[0] == port,
       "a record split across two writes is reassembled")


def test_two_fragments(port):
    """A record delivered as two RPC fragments, which is legal."""
    xid = 8888
    rec = call_body(xid, PMAP_PROG, PMAP_VERS, GETPORT,
                    mapping(PMAP_PROG, PMAP_VERS, IPPROTO_UDP, 0))
    half = len(rec) // 2
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect(("127.0.0.1", port))
    s.sendall(struct.pack(">I", half) + rec[:half])          # not last
    s.sendall(struct.pack(">I", 0x80000000 | (len(rec) - half)) + rec[half:])
    try:
        hdr = b""
        while len(hdr) < 4:
            c = s.recv(4 - len(hdr))
            if not c:
                raise ValueError("closed")
            hdr += c
        (mark,) = struct.unpack(">I", hdr)
        flen = mark & 0x7fffffff
        frag = b""
        while len(frag) < flen:
            frag += s.recv(flen - len(frag))
        stat, rest = parse_reply(frag, xid)
        ok(stat == 0, "a two fragment record is reassembled")
    except Exception as e:
        ok(False, "a two fragment record is reassembled (%s)" % e)
    s.close()


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 10111
    binary = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          "portmap")
    if not os.path.exists(binary):
        binary = "/tmp/portmap"

    proc = subprocess.Popen([binary, "-d", "-p", str(port)],
                            stderr=subprocess.PIPE)
    time.sleep(0.4)
    if proc.poll() is not None:
        print("portmap did not start:")
        print(proc.stderr.read().decode())
        return 1

    print("portmap on port %d (pid %d)\n" % (port, proc.pid))

    try:
        test_null(port)
        test_self_registration(port)
        test_set_get_unset(port)
        test_dump(port)
        test_callit_refused(port)
        test_errors(port)
        test_bad_rpc_version(port)
        test_tcp_two_calls_one_connection(port)
        test_split_record(port)
        test_two_fragments(port)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

    print("\n%d checks, %d failed" % (checks, fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
