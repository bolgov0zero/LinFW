import pytest

from linfw.demo import DemoRunner
from linfw.firewall import Firewall
from linfw.model import LOG_TAG, FirewallError, NewRule
from linfw.parser import parse_listing

LISTING = """\
table ip linfw {
\tset blocklist {
\t\ttype ipv4_addr
\t\tflags interval
\t\telements = { 198.51.100.7 }
\t}

\tchain input {
\t\ttype filter hook input priority filter; policy drop;
\t\tiifname "lo" counter packets 10 bytes 840 accept comment "linfw:base:lo"
\t\ttcp dport 22 counter packets 7 bytes 500 accept comment "linfw:rule"
\t\ttcp dport { 80, 443 } ip saddr 10.0.0.1 counter packets 0 bytes 0 continue comment "linfw:off:drop"
\t\tip saddr != 1.2.3.4 udp sport 53 counter packets 3 bytes 120 reject
\t\tmeta l4proto 17 ip daddr 1.1.1.1/32 counter packets 1 bytes 1 accept comment "linfw:rule"
\t\tip protocol 6 counter packets 2 bytes 2 drop comment "linfw:rule"
\t\tip saddr @blocklist counter packets 5 bytes 5 drop comment "linfw:rule"
\t\tudp dport 1000-2000 counter packets 0 bytes 0 accept comment "linfw:rule"
\t}

\tchain forward {
\t\ttype filter hook forward priority filter; policy accept;
\t\tcounter packets 1 bytes 1 jump docker-user
\t}
}
"""


def test_parse_columns():
    snap = parse_listing(LISTING)
    assert snap.exists and snap.chains == {"INPUT", "FORWARD"}
    assert snap.policies == {"INPUT": "DROP", "FORWARD": "ACCEPT"}
    lo, ssh, web, udp, dst, proto, lst, rng = snap.rules["INPUT"]
    assert (lo.index, lo.pkts, lo.base_id, lo.hidden) == (1, 10, "linfw:base:lo", True)
    assert (ssh.protocol, ssh.port, ssh.extra, ssh.spec, ssh.bytes) == ("tcp", "22", (), ("tcp", "dport", "22", "accept"), 500)
    assert (web.port, web.source, web.enabled, web.action) == ("80,443", "10.0.0.1", False, "drop")
    assert web.spec[-1] == "drop"  # the spec is the rule as if it were on
    assert (udp.source, udp.extra[:1], udp.port, udp.action) == ("", ("ip",), "sp:53", "reject")
    assert (dst.protocol, dst.destination) == ("udp", "1.1.1.1")  # meta l4proto 17, /32 dropped
    assert proto.protocol == "tcp" and proto.spec == ("ip", "protocol", "tcp", "drop")  # ip protocol 6
    assert (lst.source, lst.number) == ("@blocklist", 6)  # the first rule is hidden
    assert rng.port == "1000:2000"
    assert snap.rules["FORWARD"][0].action == "-" and snap.rules["FORWARD"][0].extra == ("jump", "docker-user")
    assert not parse_listing(None).exists


@pytest.mark.parametrize(
    "kwargs, spec",
    [
        (dict(), ["accept"]),
        (dict(protocol="tcp", port="22"), ["tcp", "dport", "22", "accept"]),
        (dict(protocol="icmp"), ["ip", "protocol", "icmp", "accept"]),
        (
            dict(protocol="udp", port="80, 443", source="10.0.0.0/8", destination="1.1.1.1", action="DROP"),
            ["udp", "dport", "{80,443}", "ip", "saddr", "10.0.0.0/8", "ip", "daddr", "1.1.1.1", "drop"],
        ),
        (dict(protocol="tcp", port="1000-2000"), ["tcp", "dport", "1000-2000", "accept"]),
        (dict(source="@office", action="REJECT"), ["ip", "saddr", "@office", "reject"]),
    ],
)
def test_new_rule_spec(kwargs, spec):
    assert NewRule(**kwargs).validated().to_spec() == spec


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(protocol="icmp", port="22"),
        dict(protocol="all", port="22"),
        dict(protocol="tcp", port="70000"),
        dict(protocol="tcp", port="abc"),
        dict(protocol="tcp", port="9:1"),
        dict(source="example.com"),
        dict(destination="10.0.0.0/33"),
    ],
)
def test_new_rule_invalid(kwargs):
    with pytest.raises(ValueError):
        NewRule(**kwargs).validated()


@pytest.fixture
def fw():
    fw = Firewall(DemoRunner(jitter=False))
    fw.ensure_base()  # what the app does on start
    return fw


def test_a_new_rule_reads_back_as_the_same_spec(fw):
    new = NewRule("INPUT", "udp", "DROP", source="10.0.0.0/8", destination="1.1.1.1", port="80,1000:2000").validated()
    fw.add(new)
    assert list(fw.snapshot().rules["INPUT"][-1].spec) == new.to_spec()


def test_add_always_appends_to_the_end(fw):
    before = [r.spec for r in fw.snapshot().rules["INPUT"]]
    assert fw.snapshot().rules["INPUT"][-1].action == "drop"  # trailing catch-all DROP
    fw.add(NewRule("INPUT", "tcp", "ACCEPT", port="8080"))
    after = fw.snapshot().rules["INPUT"]
    assert [r.spec for r in after[:-1]] == before
    assert after[-1].port == "8080"
    fw.add(NewRule("INPUT", "all", "REJECT"))
    assert fw.snapshot().rules["INPUT"][-1].action == "reject"


def test_delete_and_stale_rule(fw):
    snap = fw.snapshot()
    victim, other = snap.rules["INPUT"][3], snap.rules["INPUT"][2]  # other sits above: unaffected
    fw.delete(victim)
    assert len(fw.snapshot().rules["INPUT"]) == len(snap.rules["INPUT"]) - 1
    with pytest.raises(FirewallError):
        fw.delete(victim)  # the chain shifted, the old view is stale
    fw.delete(other)


def test_move_keeps_counters_and_edges(fw):
    rules = fw.snapshot().rules["INPUT"]
    web = rules[3]  # real index 4: two hidden base rules + ssh come first
    assert fw.move(web, -1)
    moved = fw.snapshot().rules["INPUT"]
    assert moved[2].spec == web.spec and moved[2].pkts == web.pkts
    assert len(moved) == len(rules)
    assert fw.move(moved[2], 1)
    assert [r.spec for r in fw.snapshot().rules["INPUT"]] == [r.spec for r in rules]
    # the first visible rule cannot go above the base rules, the last cannot go down
    assert not fw.move(fw.snapshot().rules["INPUT"][2], -1)
    assert not fw.move(fw.snapshot().rules["INPUT"][-1], 1)


def test_move_down_to_last_position(fw):
    rules = fw.snapshot().rules["FORWARD"]
    assert fw.move(rules[1], 1)  # rules[0] is the hidden base rule
    assert fw.snapshot().rules["FORWARD"][-1].spec == rules[1].spec


def test_toggle_roundtrip(fw):
    reject = next(r for r in fw.snapshot().rules["INPUT"] if r.action == "reject")
    assert fw.toggle(reject) is False
    off = fw.snapshot().rules["INPUT"][reject.index - 1]
    assert (off.enabled, off.action, off.spec, off.pkts) == (False, "reject", reject.spec, reject.pkts)
    assert off.tag == "linfw:off:reject"
    assert fw.toggle(off) is True
    on = fw.snapshot().rules["INPUT"][reject.index - 1]
    assert (on.enabled, on.action, on.tag) == (True, "reject", "linfw:rule")


def test_a_disabled_rule_lets_the_packet_go_on(fw):
    drop = fw.snapshot().rules["INPUT"][-1]
    fw.toggle(drop)
    assert 'continue comment "linfw:off:drop"' in fw.runner.list_table()


def test_disabled_rules_keep_their_position(fw):
    order = lambda: [(r.index, r.action) for r in fw.snapshot().rules["INPUT"]]  # noqa: E731
    before = order()
    for rule in fw.snapshot().rules["INPUT"]:
        if not rule.hidden and rule.action in ("accept", "drop", "reject"):
            fw.toggle(fw.snapshot().rules["INPUT"][rule.index - 1])
    after = [r for r in fw.snapshot().rules["INPUT"] if not r.hidden]
    assert order() == before
    assert len(after) == 6 and not any(r.enabled for r in after)


def test_toggle_unsupported_verdict():
    runner = DemoRunner(sample=False)
    runner.nft(["table ip linfw", "add chain ip linfw forward { type filter hook forward priority filter; policy accept; }",
                "add rule ip linfw forward jump docker-user"])
    fw = Firewall(runner)
    with pytest.raises(FirewallError):
        fw.toggle(fw.snapshot().rules["FORWARD"][0])


def test_a_failed_transaction_changes_nothing(fw):
    before = fw.runner.list_table()
    with pytest.raises(FirewallError):
        fw.runner.nft(["flush chain ip linfw input", "add rule ip linfw input ip saddr @nolist drop"])
    assert fw.runner.list_table() == before


# -- base rules ------------------------------------------------------------


def test_base_rules_are_hidden_numbered_and_on_top(fw):
    snap = fw.snapshot()
    inp = snap.rules["INPUT"]
    assert [r.base_id for r in inp[:2]] == ["linfw:base:lo", "linfw:base:est"]
    assert [r.hidden for r in inp[:3]] == [True, True, False]
    assert [r.number for r in inp if not r.hidden][:2] == [1, 2]  # numbering skips them
    assert snap.rules["OUTPUT"][0].hidden and snap.rules["FORWARD"][0].hidden
    assert "ct" in snap.rules["FORWARD"][0].spec and "established,related" in snap.rules["FORWARD"][0].spec


def test_ensure_base_is_idempotent(fw):
    before = [r.spec for r in fw.snapshot().rules["INPUT"]]
    assert fw.base_ok(fw.snapshot()) and not fw.ensure_base()
    assert [r.spec for r in fw.snapshot().rules["INPUT"]] == before


def test_ensure_base_creates_the_table_from_nothing():
    runner = DemoRunner(sample=False, jitter=False)
    fw = Firewall(runner)
    assert not fw.snapshot().exists and not fw.base_ok(fw.snapshot())
    assert fw.ensure_base()
    snap = fw.snapshot()
    assert snap.exists and snap.chains == {"INPUT", "OUTPUT", "FORWARD"} and fw.base_ok(snap)
    assert snap.policies == {"INPUT": "ACCEPT", "OUTPUT": "ACCEPT", "FORWARD": "ACCEPT"}


def test_ensure_base_restores_missing_and_misplaced():
    runner = DemoRunner(jitter=False)
    fw = Firewall(runner)
    assert not fw.base_ok(fw.snapshot()) and fw.ensure_base()
    user_rules = [r.spec for r in fw.snapshot().rules["INPUT"] if not r.hidden]

    # someone flushed one base rule and put a foreign rule on top of another
    del runner.rules["INPUT"][1]
    runner.rules["INPUT"].insert(0, [0, 0, ["ip", "saddr", "9.9.9.9", "drop"], ""])
    assert not fw.base_ok(fw.snapshot()) and fw.ensure_base()
    inp = fw.snapshot().rules["INPUT"]
    assert [r.base_id for r in inp[:2]] == ["linfw:base:lo", "linfw:base:est"]
    assert sum(r.hidden for r in inp) == 2  # no duplicates left behind
    assert [r.spec for r in inp if not r.hidden][0] == ("ip", "saddr", "9.9.9.9", "drop")
    assert [r.spec for r in inp if not r.hidden][1:] == user_rules


def test_base_rules_cannot_be_changed(fw):
    base = fw.snapshot().rules["INPUT"][0]
    for op in (fw.delete, fw.toggle, lambda r: fw.move(r, 1)):
        with pytest.raises(FirewallError):
            op(base)


def test_remove_base(fw):
    assert fw.remove_base()
    snap = fw.snapshot()
    assert not any(r.hidden for rules in snap.rules.values() for r in rules)
    assert not fw.remove_base()


def test_edit_in_place_keeps_position_and_state(fw):
    ssh = fw.snapshot().rules["INPUT"][2]
    assert ssh.editable
    fw.edit(ssh, NewRule("INPUT", "tcp", "DROP", source="10.0.0.0/8", port="2222"))
    after = fw.snapshot().rules["INPUT"]
    edited = after[2]
    assert (edited.action, edited.port, edited.source, edited.enabled) == ("drop", "2222", "10.0.0.0/8", True)
    # a disabled rule stays disabled
    fw.toggle(edited)
    off = fw.snapshot().rules["INPUT"][2]
    fw.edit(off, NewRule("INPUT", "udp", "REJECT", port="53"))
    again = fw.snapshot().rules["INPUT"][2]
    assert (again.enabled, again.action, again.protocol, again.port) == (False, "reject", "udp", "53")


def test_edit_refuses_chain_change_base_and_stale(fw):
    rules = fw.snapshot().rules["INPUT"]
    with pytest.raises(FirewallError):
        fw.edit(rules[2], NewRule("OUTPUT", "tcp", "ACCEPT"))
    with pytest.raises(FirewallError):
        fw.edit(rules[0], NewRule("INPUT"))
    fw.delete(rules[2])
    with pytest.raises(FirewallError):
        fw.edit(rules[3], NewRule("INPUT"))  # shifted: stale view


def test_editable_flags():
    snap = parse_listing(LISTING)
    lo, ssh, web, udp, *_ = snap.rules["INPUT"]
    assert not lo.editable  # hidden base rule
    assert ssh.editable
    assert web.editable and not web.enabled
    assert not udp.editable  # negated source, source port


# -- logging (hidden twin above the rule) -----------------------------------


def visible(fw, chain="INPUT"):
    return [r for r in fw.snapshot().rules[chain] if not r.hidden]


def logged_specs(fw, chain="INPUT"):
    """Real chain layout as (kind, port) pairs: 'log' twin or 'rule'."""
    return [("log" if r.is_log else "rule", r.port) for r in fw.snapshot().rules[chain] if not r.base_id]


def test_add_with_log_creates_hidden_twin(fw):
    before = len(visible(fw))
    fw.add(NewRule("INPUT", "tcp", "DROP", port="2222", log=True))
    rules = fw.snapshot().rules["INPUT"]
    main, twin = rules[-1], rules[-2]
    assert twin.is_log and twin.hidden and not main.hidden
    assert main.log and main.port == "2222" and main.number == before + 1
    assert twin.spec[-4:] == ("prefix", '"LINFW:INPUT:DROP: "', "group", "40")
    assert "limit" in twin.spec  # rate-limited
    assert len(visible(fw)) == before + 1  # the twin is not listed
    assert not visible(fw)[0].log  # default: off


def test_edit_turns_logging_on_and_off_in_place(fw):
    ssh = visible(fw)[0]
    total = len(fw.snapshot().rules["INPUT"])
    fw.edit(ssh, NewRule("INPUT", "tcp", "ACCEPT", port="22", log=True))
    rules = fw.snapshot().rules["INPUT"]
    assert len(rules) == total + 1 and rules[2].is_log and rules[3].port == "22" and rules[3].log
    fw.edit(rules[3], NewRule("INPUT", "tcp", "DROP", port="2200", log=True))  # twin follows the edit
    rules = fw.snapshot().rules["INPUT"]
    assert rules[2].is_log and '"LINFW:INPUT:DROP: "' in rules[2].spec and "2200" in rules[2].spec
    assert rules[3].action == "drop"
    fw.edit(rules[3], NewRule("INPUT", "tcp", "DROP", port="2200", log=False))
    rules = fw.snapshot().rules["INPUT"]
    assert len(rules) == total and not any(r.is_log for r in rules) and not rules[2].log


def test_delete_removes_the_twin(fw):
    fw.add(NewRule("INPUT", "udp", "DROP", port="5353", log=True))
    total = len(fw.snapshot().rules["INPUT"])
    fw.delete(visible(fw)[-1])
    rules = fw.snapshot().rules["INPUT"]
    assert len(rules) == total - 2 and not any(r.is_log for r in rules)


def test_move_keeps_blocks_together(fw):
    fw.add(NewRule("INPUT", "tcp", "ACCEPT", port="7001", log=True))
    fw.add(NewRule("INPUT", "tcp", "ACCEPT", port="7002", log=True))
    tail = lambda: logged_specs(fw)[-4:]  # noqa: E731
    assert tail() == [("log", "7001"), ("rule", "7001"), ("log", "7002"), ("rule", "7002")]

    assert fw.move(visible(fw)[-1], -1)  # 7002 goes above 7001, twin included
    assert tail() == [("log", "7002"), ("rule", "7002"), ("log", "7001"), ("rule", "7001")]
    assert fw.move(visible(fw)[-2], 1)  # and back down
    assert tail() == [("log", "7001"), ("rule", "7001"), ("log", "7002"), ("rule", "7002")]

    # an unlogged neighbour hops over a whole block as well
    last_plain = visible(fw)[-3]  # the catch-all DROP, the rule just above the 7001 block
    assert not last_plain.log and fw.move(last_plain, 1)
    assert [k for k, _ in logged_specs(fw)][-5:] == ["log", "rule", "rule", "log", "rule"]
    assert fw.move(visible(fw)[-2], -1)
    assert not fw.move(visible(fw)[-1], 1)  # already last
    assert not fw.move(visible(fw)[0], -1)  # already first visible


def test_move_carries_counters_of_both_rules():
    runner = DemoRunner(sample=False, jitter=False)
    fw = Firewall(runner)
    fw.ensure_base()
    fw.add(NewRule("INPUT", "tcp", "ACCEPT", port="1", log=True))
    fw.add(NewRule("INPUT", "tcp", "ACCEPT", port="2", log=True))
    entries = [e for e in runner.rules["INPUT"] if not e[3].startswith("linfw:base")]
    # entries: log1, rule1, log2, rule2 -> give the second pair distinctive counters
    entries[2][0], entries[3][0] = 7, 55
    assert fw.move(visible(fw)[-1], -1)
    tail = [e[0] for e in runner.rules["INPUT"][-4:]]
    assert tail == [7, 55, 0, 0]  # second pair now first, counters intact, pair order kept


def test_toggle_removes_the_twin_and_brings_it_back(fw):
    fw.add(NewRule("INPUT", "tcp", "DROP", port="2222", log=True))
    total = len(fw.snapshot().rules["INPUT"])
    rule = visible(fw)[-1]
    assert fw.toggle(rule) is False
    rules = fw.snapshot().rules["INPUT"]
    off = rules[-1]
    assert len(rules) == total - 1 and not any(r.is_log for r in rules)
    assert not off.enabled and off.log and off.tag == "linfw:off:drop:log"  # the comment remembers the logging
    assert fw.toggle(off) is True
    rules = fw.snapshot().rules["INPUT"]
    assert rules[-1].enabled and rules[-1].log and rules[-2].is_log and len(rules) == total


def test_twins_cannot_be_touched_directly(fw):
    fw.add(NewRule("INPUT", "tcp", "DROP", port="2222", log=True))
    twin = fw.snapshot().rules["INPUT"][-2]
    for op in (fw.delete, fw.toggle, lambda r: fw.move(r, 1)):
        with pytest.raises(FirewallError):
            op(twin)


def test_base_rules_check_ignores_log_twins(fw):
    fw.add(NewRule("INPUT", "tcp", "DROP", port="2222", log=True))
    assert fw.base_ok(fw.snapshot()) and not fw.ensure_base()


def test_persist_writes_the_whole_table_without_counters(fw):
    fw.create_list("staff")
    fw.add_to_list("staff", ["10.0.0.5"])
    fw.add(NewRule("INPUT", "tcp", "DROP", source="@staff", port="2222", log=True))
    fw.toggle(visible(fw)[0])
    assert fw.persist().startswith("demo")
    text = fw.runner.persisted
    assert text.startswith("table ip linfw\ndelete table ip linfw\ntable ip linfw {\n")
    assert "elements = { 10.0.0.5 }" in text and "set staff {" in text
    assert 'comment "linfw:base:lo"' in text and 'comment "linfw:off:accept"' in text
    assert "packets" not in text.replace("burst 10 packets", "")  # counters are not saved
    assert text.count("chain ") == 3


# -- journal parsing -----------------------------------------------------------

from linfw.journal import parse_line, parse_text  # noqa: E402
import linfw.journal as journal_mod  # noqa: E402


def test_parse_journal_line_variants():
    e = parse_line("2026-10-27T12:00:01+0300 srv kernel: LINFW:INPUT:DROP: IN=eth0 OUT= SRC=1.2.3.4 DST=5.6.7.8 LEN=60 PROTO=TCP SPT=5555 DPT=22")
    assert (e.time, e.chain, e.action, e.protocol, e.source, e.destination, e.port) == (
        "2026-10-27 12:00:01", "INPUT", "drop", "tcp", "1.2.3.4", "5.6.7.8", "22")
    icmp = parse_line("Oct 27 12:00:01 srv kernel: [ 9.1] LINFW:OUTPUT:ACCEPT: IN= OUT=eth0 SRC=10.0.0.1 DST=8.8.8.8 PROTO=ICMP TYPE=8")
    assert (icmp.protocol, icmp.port, icmp.time, icmp.chain) == ("icmp", "-", "Oct 27 12:00:01", "OUTPUT")
    assert parse_line("[Tue Oct 27 12:00:01 2026] LINFW:FORWARD:REJECT: SRC=1.1.1.1 DST=2.2.2.2 PROTO=UDP SPT=1 DPT=53").time == "Oct 27 12:00:01 2026"
    assert parse_line("kernel: something else entirely") is None
    assert parse_line("kernel: LINFW:INPUT:DROP: garbage") is None


def test_parse_text_keeps_order_and_limit():
    n = journal_mod.MAX_ENTRIES + 500
    lines = [f"2026-10-27T12:00:{i % 60:02d}+0000 h kernel: LINFW:INPUT:DROP: SRC=1.1.1.{i % 250} DST=2.2.2.2 PROTO=TCP DPT=22" for i in range(n)]
    lines.insert(3, "unrelated line")
    entries = parse_text("\n".join(lines))
    assert len(entries) == journal_mod.MAX_ENTRIES and entries[-1].source == "1.1.1.%d" % ((n - 1) % 250)


# -- journal sources and diagnosis -----------------------------------------------


_HIT_LINE = "2026-10-27T12:00:01+0300 srv kernel: LINFW:INPUT:DROP: IN=eth0 OUT= SRC=1.2.3.4 DST=5.6.7.8 PROTO=TCP SPT=1 DPT=22"


def test_empty_journalctl_falls_back_to_a_file_that_has_records(monkeypatch):
    monkeypatch.setattr(journal_mod.persist, "find_binary", lambda name: "/bin/" + name if name == "journalctl" else None)
    monkeypatch.setattr(journal_mod, "_run", lambda argv: "2026-10-27T12:00:00+0300 srv kernel: unrelated\n")
    monkeypatch.setattr(journal_mod, "HITS_DIR", "/nonexistent-linfw-dir")
    monkeypatch.setattr(journal_mod, "_tail", lambda path, *a, **k: _HIT_LINE if path == "/var/log/messages" else None)
    source, entries = journal_mod.read_entries()
    assert source == "/var/log/messages" and entries[0].port == "22"


def test_no_records_anywhere_reports_the_first_readable_source(monkeypatch):
    monkeypatch.setattr(journal_mod.persist, "find_binary", lambda name: "/bin/" + name if name == "journalctl" else None)
    monkeypatch.setattr(journal_mod, "_run", lambda argv: "")
    monkeypatch.setattr(journal_mod, "HITS_DIR", "/nonexistent-linfw-dir")
    monkeypatch.setattr(journal_mod, "_tail", lambda path, *a, **k: None)
    assert journal_mod.read_entries() == ("journalctl -k", [])


def test_nothing_readable_is_an_error(monkeypatch):
    monkeypatch.setattr(journal_mod.persist, "find_binary", lambda name: None)
    monkeypatch.setattr(journal_mod, "HITS_DIR", "/nonexistent-linfw-dir")
    monkeypatch.setattr(journal_mod, "_tail", lambda path, *a, **k: None)
    with pytest.raises(FirewallError):
        journal_mod.read_entries()


def test_log_diagnosis_counts_twins_and_their_packets():
    runner = DemoRunner(sample=False, jitter=False)
    fw = Firewall(runner)
    assert fw.log_diagnosis() == (0, 0, "active")
    fw.add(NewRule("INPUT", "tcp", "DROP", port="22", log=True))
    fw.add(NewRule("OUTPUT", "tcp", "DROP", port="25", log=True))
    assert fw.log_diagnosis()[:2] == (2, 0)
    for chain in runner.rules.values():
        for entry in chain:
            if entry[3] == LOG_TAG:
                entry[0] = 4
    assert fw.log_diagnosis()[:2] == (2, 8)
