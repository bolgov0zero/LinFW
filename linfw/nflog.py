"""A minimal NFLOG (nfnetlink_log) client, standard library only.

The hidden "twin" rules send matching packets to an nflog group; this module
binds that group on a netlink socket and decodes what arrives. It needs root
(CAP_NET_ADMIN) and the nfnetlink_log kernel module.
"""
from __future__ import annotations

import errno
import socket
import struct
from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple

NETLINK_NETFILTER = 12
NFNL_SUBSYS_ULOG = 4
NFULNL_MSG_PACKET = 0
NFULNL_MSG_CONFIG = 1
NFULNL_CFG_CMD_BIND = 1
NFULNL_CFG_CMD_PF_BIND = 3
NFULNL_COPY_PACKET = 2
NFULA_CFG_CMD = 1
NFULA_CFG_MODE = 2
NFULA_PAYLOAD = 9
NFULA_PREFIX = 10

NLM_F_REQUEST = 1
NLM_F_ACK = 4
NLMSG_ERROR = 2
AF_UNSPEC = 0
AF_INET = 2

COPY_RANGE = 128  # bytes of each packet we ask for: IP header + the ports is plenty
_PROTOCOLS = {1: "icmp", 6: "tcp", 17: "udp"}


@dataclass(frozen=True)
class Packet:
    prefix: str
    payload: bytes


@dataclass(frozen=True)
class Hit:
    protocol: str
    source: str
    destination: str
    port: str  # destination port for tcp/udp, "-" otherwise


def _align(n: int) -> int:
    return (n + 3) & ~3


def _attr(kind: int, payload: bytes) -> bytes:
    return struct.pack("=HH", 4 + len(payload), kind) + payload + b"\0" * (_align(len(payload)) - len(payload))


def config_message(family: int, group: int, attrs: bytes, seq: int) -> bytes:
    """A NFULNL_MSG_CONFIG request; the group number travels in nfgenmsg.res_id (big endian)."""
    body = struct.pack("!BBH", family, 0, group) + attrs
    header = struct.pack(
        "=IHHII", 16 + len(body), (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG, NLM_F_REQUEST | NLM_F_ACK, seq, 0
    )
    return header + body


def setup_messages(group: int) -> List[Tuple[int, bytes]]:
    """(seq, message) pairs that bind a group and ask for packet copies."""
    cmd = lambda c: _attr(NFULA_CFG_CMD, struct.pack("=B", c))  # noqa: E731
    mode = _attr(NFULA_CFG_MODE, struct.pack("!IBB", COPY_RANGE, NFULNL_COPY_PACKET, 0))
    return [
        (1, config_message(AF_INET, 0, cmd(NFULNL_CFG_CMD_PF_BIND), 1)),  # obsolete, kernels may refuse it
        (2, config_message(AF_UNSPEC, group, cmd(NFULNL_CFG_CMD_BIND), 2)),
        (3, config_message(AF_UNSPEC, group, mode, 3)),
    ]


def iter_packets(data: bytes) -> Iterator[Packet]:
    """Decode every NFULNL_MSG_PACKET message in a buffer read from the socket."""
    pos = 0
    while pos + 16 <= len(data):
        length, kind = struct.unpack_from("=IH", data, pos)
        if length < 16 or pos + length > len(data):
            break
        if kind == (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET:
            prefix, payload = "", b""
            attr = pos + 16 + 4  # nlmsghdr, nfgenmsg
            end = pos + length
            while attr + 4 <= end:
                alen, atype = struct.unpack_from("=HH", data, attr)
                if alen < 4:
                    break
                value = data[attr + 4:attr + alen]
                atype &= 0x3FFF  # strip the NESTED / NET_BYTEORDER flags
                if atype == NFULA_PREFIX:
                    prefix = value.split(b"\0", 1)[0].decode("ascii", "replace")
                elif atype == NFULA_PAYLOAD:
                    payload = bytes(value)
                attr += _align(alen)
            yield Packet(prefix, payload)
        pos += _align(length)


def parse_ipv4(payload: bytes) -> Optional[Hit]:
    if len(payload) < 20 or payload[0] >> 4 != 4:
        return None
    ihl = (payload[0] & 0x0F) * 4
    proto = payload[9]
    name = _PROTOCOLS.get(proto, str(proto))
    port = "-"
    if proto in (6, 17) and len(payload) >= ihl + 4:
        port = str(struct.unpack_from("!H", payload, ihl + 2)[0])
    return Hit(name, socket.inet_ntoa(payload[12:16]), socket.inet_ntoa(payload[16:20]), port)


def _check_acks(sock, expected: int) -> None:
    """Read the replies to the config requests; any error other than the obsolete PF_BIND is fatal."""
    seen = 0
    while seen < expected:
        data = sock.recv(4096)
        pos = 0
        while pos + 20 <= len(data):
            length, kind, _flags, seq, _pid = struct.unpack_from("=IHHII", data, pos)
            if length < 16:
                break
            if kind == NLMSG_ERROR:
                seen += 1
                (error,) = struct.unpack_from("=i", data, pos + 16)
                if error and seq != 1:
                    raise OSError(-error, f"nfnetlink_log: {errno.errorcode.get(-error, error)}")
            pos += _align(length)


class Listener:
    """Binds an nflog group and yields the packets sent to it."""

    def __init__(self, group: int) -> None:
        self.group = group
        self.sock = None

    def __enter__(self) -> "Listener":
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
        self.sock.bind((0, 0))
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 21)
        except OSError:
            pass
        for _seq, message in setup_messages(self.group):
            self.sock.send(message)
        _check_acks(self.sock, 3)
        return self

    def __exit__(self, *exc) -> None:
        if self.sock:
            self.sock.close()

    def packets(self) -> Iterator[Packet]:
        while True:
            try:
                data = self.sock.recv(65535)
            except OSError as exc:
                if exc.errno == errno.ENOBUFS:  # we fell behind: records were dropped, carry on
                    continue
                raise
            yield from iter_packets(data)
