import os
import struct
from datetime import date, datetime

import pytest

from linfw import nflog
from linfw.demo import DemoRunner
from linfw.firewall import Firewall
from linfw.journal import LogEntry, format_hit, parse_hits
from linfw.logd import HitWriter, entry_from_packet
from linfw.model import FirewallError, NewRule, nflog_target
from linfw.parser import parse_save


def ipv4(proto, src, dst, sport=0, dport=0, ihl=5):
    ip = bytearray(ihl * 4)
    ip[0] = 0x40 | ihl
    ip[9] = proto
    ip[12:16] = bytes(map(int, src.split(".")))
    ip[16:20] = bytes(map(int, dst.split(".")))
    return bytes(ip) + struct.pack("!HHxxxx", sport, dport)


def attr(kind, payload, flags=0):
    pad = b"\0" * (-len(payload) % 4)
    return struct.pack("=HH", 4 + len(payload), kind | flags) + payload + pad


def packet_message(prefix, payload, extra=b""):
    body = struct.pack("!BBH", 2, 0, 40) + extra + attr(nflog.NFULA_PREFIX, prefix.encode() + b"\0") + attr(nflog.NFULA_PAYLOAD, payload)
    return struct.pack("=IHHII", 16 + len(body), 0x0400, 0, 7, 0) + body


def test_setup_messages_bind_the_group_and_request_packets():
    msgs = dict(nflog.setup_messages(40))
    for seq, raw in msgs.items():
        length, kind, flags, s, _ = struct.unpack_from("=IHHII", raw)
        assert (length, kind, s) == (len(raw), 0x0401, seq) and flags & nflog.NLM_F_ACK
    family, _version, res_id = struct.unpack_from("!BBH", msgs[2], 16)
    assert (family, res_id) == (0, 40)
    assert msgs[2][20:] == struct.pack("=HHBxxx", 5, nflog.NFULA_CFG_CMD, nflog.NFULNL_CFG_CMD_BIND)
    assert msgs[3][20:] == struct.pack("=HH", 10, nflog.NFULA_CFG_MODE) + struct.pack("!IBB", 128, 2, 0) + b"\0\0"


def test_decode_packets_ip_ports_and_prefix():
    tcp = ipv4(6, "203.0.113.9", "192.168.1.10", 51000, 22)
    udp = ipv4(17, "10.0.0.2", "10.0.0.1", 5353, 53, ihl=6)  # IP options: ports sit after the 24-byte header
    icmp = ipv4(1, "1.2.3.4", "5.6.7.8")
    noise = attr(1, struct.pack("!HBx", 0x0800, 1)) + attr(4, struct.pack("!I", 2))
    data = packet_message("LINFW:INPUT:DROP: ", tcp, noise) + packet_message("LINFW:OUTPUT:ACCEPT: ", udp) + packet_message("x:", icmp)
    packets = list(nflog.iter_packets(data))
    assert [p.prefix for p in packets] == ["LINFW:INPUT:DROP: ", "LINFW:OUTPUT:ACCEPT: ", "x:"]
    assert nflog.parse_ipv4(packets[0].payload) == nflog.Hit("tcp", "203.0.113.9", "192.168.1.10", "22")
    assert nflog.parse_ipv4(packets[1].payload) == nflog.Hit("udp", "10.0.0.2", "10.0.0.1", "53")
    assert nflog.parse_ipv4(packets[2].payload) == nflog.Hit("icmp", "1.2.3.4", "5.6.7.8", "-")


def test_decoder_ignores_garbage_and_truncation():
    assert list(nflog.iter_packets(b"")) == []
    good = packet_message("LINFW:INPUT:DROP: ", ipv4(6, "1.1.1.1", "2.2.2.2", 1, 2))
    assert len(list(nflog.iter_packets(good[:-5]))) == 0  # cut off mid-message
    ack = struct.pack("=IHHIIi", 20, nflog.NLMSG_ERROR, 0, 1, 0, 0)  # an ack between packets is skipped
    assert len(list(nflog.iter_packets(ack + good))) == 1
    assert nflog.parse_ipv4(b"short") is None and nflog.parse_ipv4(b"\x60" + b"\0" * 39) is None  # IPv6


def test_entry_from_packet_uses_the_prefix():
    when = datetime(2026, 10, 27, 12, 0, 1)
    pkt = nflog.Packet("LINFW:FORWARD:REJECT: ", ipv4(6, "1.1.1.1", "2.2.2.2", 9, 8080))
    assert entry_from_packet(pkt, when) == LogEntry("2026-10-27 12:00:01", "FORWARD", "reject", "tcp", "1.1.1.1", "2.2.2.2", "8080")
    assert entry_from_packet(nflog.Packet("other: ", pkt.payload)) is None
    assert entry_from_packet(nflog.Packet("LINFW:INPUT:DROP: ", b"junk")) is None


def hit(day, hms, chain="INPUT", src="1.1.1.1"):
    return LogEntry(f"{day} {hms}", chain, "drop", "tcp", src, "2.2.2.2", "22")


def test_writer_uses_one_file_per_day_and_prunes_after_30_days(tmp_path):
    d = tmp_path / "hits"
    d.mkdir()
    for old in ("2026-09-01", "2026-09-26", "2026-09-27"):
        (d / f"hits-{old}.log").write_text(format_hit(hit(old, "10:00:00")) + "\n")
    (d / "hits.log").write_text("legacy\n")
    os.utime(d / "hits.log", (0, 0))  # ancient legacy file
    writer = HitWriter(str(d), keep_days=30)
    writer.prune(today=date(2026, 10, 27))
    assert sorted(p.name for p in d.iterdir()) == ["hits-2026-09-27.log"]  # exactly 30 days back survives
    writer.write(hit("2026-10-27", "12:00:00"))
    writer.write(hit("2026-10-27", "12:00:01", src="3.3.3.3"))
    writer.write(hit("2026-10-28", "00:00:05"))
    writer.close()
    assert len((d / "hits-2026-10-27.log").read_text().splitlines()) == 2
    assert len((d / "hits-2026-10-28.log").read_text().splitlines()) == 1


def test_reader_returns_newest_records_across_days_with_chain_filter(tmp_path):
    from linfw.journal import read_hits

    d = tmp_path / "hits"
    d.mkdir()
    for day in ("2026-10-25", "2026-10-26", "2026-10-27"):
        lines = [format_hit(hit(day, f"10:00:{i:02d}", chain=("INPUT" if i % 2 else "OUTPUT"), src=f"9.9.{day[-2:]}.{i}")) for i in range(10)]
        (d / f"hits-{day}.log").write_text("\n".join(lines) + "\n")
    everything = read_hits(str(d), limit=100)
    assert len(everything) == 30 and everything[0].time.startswith("2026-10-25") and everything[-1].time.startswith("2026-10-27")
    newest = read_hits(str(d), limit=12)
    assert len(newest) == 12 and newest[-1] == everything[-1] and newest[0] == everything[-12]
    only_in = read_hits(str(d), chain="INPUT", limit=100)
    assert len(only_in) == 15 and {e.chain for e in only_in} == {"INPUT"}
    assert read_hits(str(tmp_path / "missing")) is None
    assert read_hits(str(tmp_path)) == []  # a directory without record files


def test_reader_skips_a_cut_first_line(tmp_path, monkeypatch):
    import linfw.journal as journal

    d = tmp_path / "hits"
    d.mkdir()
    lines = [format_hit(hit("2026-10-27", f"10:{i // 60:02d}:{i % 60:02d}")) for i in range(200)]
    (d / "hits-2026-10-27.log").write_text("\n".join(lines) + "\n")
    real_tail = journal._tail
    monkeypatch.setattr(journal, "_tail", lambda path, nbytes=2_000_000, whole_lines=False: real_tail(path, 1000, whole_lines))
    got = journal.read_hits(str(d), limit=1000)
    assert got and all(len(format_hit(e).split("\t")) == 7 and e.time.startswith("2026-10-27 10:") for e in got)
    assert got[-1].time == "2026-10-27 10:03:19"


def test_journal_prefers_the_logd_files(tmp_path, monkeypatch):
    import linfw.journal as journal

    (tmp_path / "hits-2026-10-27.log").write_text(format_hit(hit("2026-10-27", "12:00:00")) + "\n")
    monkeypatch.setattr(journal, "HITS_DIR", str(tmp_path))
    monkeypatch.setattr(journal.persist, "find_binary", lambda name: None)
    source, entries = journal.read_entries()
    assert source == "linfw-logd" and entries[0].source == "1.1.1.1"
    assert journal.read_entries("OUTPUT") == ("linfw-logd", [])


def test_legacy_log_twins_are_upgraded_to_nflog_keeping_counters():
    runner = DemoRunner(sample=False, jitter=False)
    fw = Firewall(runner)
    fw.ensure_base()
    legacy = ["-p", "tcp", "--dport", "22", "-m", "comment", "--comment", "linfw:log", "-m", "limit", "--limit", "10/min",
              "--limit-burst", "10", "-j", "LOG", "--log-prefix", "LINFW:INPUT:DROP: ", "--log-level", "4"]
    runner.rules["INPUT"].append([9, 99, legacy])
    runner.rules["INPUT"].append([0, 0, ["-p", "tcp", "--dport", "22", "-j", "DROP"]])
    assert not fw.base_ok(fw.snapshot())
    assert fw.ensure_base()
    twin = fw.snapshot().rules["INPUT"][-2]
    assert twin.spec[-6:] == tuple(nflog_target("INPUT", "DROP")) and twin.pkts == 9 and twin.is_log
    assert fw.base_ok(fw.snapshot()) and not fw.ensure_base()
