import json

import pytest

from linfw.counters import CounterStore, signature
from linfw.demo import DemoRunner
from linfw.firewall import Firewall
from linfw.model import FirewallError, NewRule
from linfw.parser import parse_listing

BOOT = ["boot-1"]


def save(*rules, policy="ACCEPT"):
    """`nft list table` text with (pkts, bytes, 'rule words') per INPUT rule; a rule may carry its comment."""
    lines = ["table ip linfw {", "\tchain input {", f"\t\ttype filter hook input priority filter; policy {policy.lower()};"]
    for p, b, spec in rules:
        head, _, tail = spec.rpartition(" ")
        tag = ""
        if tail.startswith("off:"):
            head, tail, tag = head, "continue", ' comment "linfw:' + spec.rsplit(" ", 1)[1] + '"'
        lines.append(f"\t\t{head} counter packets {p} bytes {b} {tail}{tag}")
    return "\n".join(lines + ["\t}", "}"]) + "\n"


def totals(store, *rules):
    return store.update(parse_listing(save(*rules)))


@pytest.fixture
def store(tmp_path):
    BOOT[0] = "boot-1"
    return CounterStore(str(tmp_path / "counters.json"), epoch=lambda: BOOT[0])


SSH = "tcp dport 22 accept"
WEB = "tcp dport 80 accept"


def test_totals_follow_the_kernel_counters(store):
    assert totals(store, (5, 500, SSH)) == {"INPUT:1": (5, 500)}
    assert totals(store, (9, 900, SSH)) == {"INPUT:1": (9, 900)}
    assert totals(store, (9, 900, SSH)) == {"INPUT:1": (9, 900)}  # idle: unchanged


def test_counter_reset_never_lowers_the_total(store):
    totals(store, (100, 10_000, SSH))
    assert totals(store, (0, 0, SSH)) == {"INPUT:1": (100, 10_000)}  # kernel counters zeroed (a reload of the table)
    assert totals(store, (7, 700, SSH)) == {"INPUT:1": (107, 10_700)}
    assert totals(store, (3, 300, SSH)) == {"INPUT:1": (110, 11_000)}  # reset again


def test_reboot_is_detected_even_when_the_counter_climbs_back_above_the_old_value(store):
    totals(store, (100, 10_000, SSH))
    BOOT[0] = "boot-2"
    # after the reboot the rule already counted 150 > 100 before the first sample: all 150 are new
    assert totals(store, (150, 15_000, SSH)) == {"INPUT:1": (250, 25_000)}
    assert totals(store, (160, 16_000, SSH)) == {"INPUT:1": (260, 26_000)}


def test_total_survives_moving_and_switching_off(store):
    totals(store, (50, 5000, SSH), (20, 2000, WEB))
    moved = totals(store, (20, 2000, WEB), (50, 5000, SSH))  # same rules, other order
    assert moved == {"INPUT:1": (20, 2000), "INPUT:2": (50, 5000)}
    off = totals(store, (20, 2000, WEB), (55, 5500, "tcp dport 22 off:accept"))
    assert off["INPUT:2"] == (55, 5500)  # a disabled rule keeps its identity


def test_identical_rules_are_counted_separately(store):
    assert totals(store, (3, 30, SSH), (8, 80, SSH)) == {"INPUT:1": (3, 30), "INPUT:2": (8, 80)}
    assert totals(store, (4, 40, SSH), (9, 90, SSH)) == {"INPUT:1": (4, 40), "INPUT:2": (9, 90)}


def test_totals_persist_in_the_file_and_forgotten_rules_expire(store, tmp_path):
    totals(store, (40, 400, SSH))
    other = CounterStore(store.path, epoch=lambda: BOOT[0])  # another process (the service)
    assert other.update(parse_listing(save((0, 0, SSH)))) == {"INPUT:1": (40, 400)}
    data = json.load(open(store.path))
    assert list(data["rules"]) == ["INPUT|tcp dport 22 accept|0"]
    store.update(parse_listing(save()), now=10**10)  # the rule is gone for more than 30 days
    assert json.load(open(store.path))["rules"] == {}


def test_a_disabled_rule_has_the_signature_of_the_enabled_one():
    on = parse_listing(save((1, 1, "tcp dport 22 accept"))).rules["INPUT"][0]
    off = parse_listing(save((1, 1, "tcp dport 22 off:accept"))).rules["INPUT"][0]
    assert not off.enabled and signature(on.spec) == signature(off.spec) == "tcp dport 22 accept"


# -- through the Firewall: edit keeps the total, delete forgets it ------------------


@pytest.fixture
def fw():
    runner = DemoRunner(sample=False, jitter=False)
    firewall = Firewall(runner, CounterStore(None))
    firewall.ensure_base()
    firewall.add(NewRule("INPUT", "tcp", "ACCEPT", port="22"))
    firewall.add(NewRule("INPUT", "tcp", "ACCEPT", port="80"))
    return firewall, runner


def shown(firewall):
    return firewall.counter_totals(firewall.snapshot())


def set_kernel(runner, port, pkts):
    for entry in runner.rules["INPUT"]:
        if ["dport", port] == entry[2][entry[2].index("dport"):][:2] if "dport" in entry[2] else False:
            entry[0], entry[1] = pkts, pkts * 100


def test_edit_keeps_the_total_although_the_kernel_counter_restarts(fw):
    firewall, runner = fw
    set_kernel(runner, "22", 40)
    assert shown(firewall)["INPUT:3"] == (40, 4000)
    rule = firewall.snapshot().rules["INPUT"][2]
    firewall.edit(rule, NewRule("INPUT", "tcp", "DROP", source="10.0.0.0/8", port="2222"))
    edited = firewall.snapshot().rules["INPUT"][2]
    assert edited.pkts == 0 and edited.port == "2222"  # the kernel counter did restart
    assert shown(firewall)["INPUT:3"] == (40, 4000)  # the total did not
    set_kernel(runner, "2222", 6)
    assert shown(firewall)["INPUT:3"] == (46, 4600)


def test_failed_edit_leaves_the_total_alone(fw):
    firewall, runner = fw
    set_kernel(runner, "22", 40)
    shown(firewall)
    rule = firewall.snapshot().rules["INPUT"][2]
    original = runner.nft

    def broken(lines):
        if any(line.startswith("flush chain") for line in lines):
            raise FirewallError("boom")
        original(lines)

    runner.nft = broken
    with pytest.raises(FirewallError):
        firewall.edit(rule, NewRule("INPUT", "tcp", "DROP", port="2222"))
    runner.nft = original
    set_kernel(runner, "22", 43)  # the kernel counter kept counting: no double counting
    assert shown(firewall)["INPUT:3"] == (43, 4300)


def test_deleted_rule_does_not_leave_its_total_behind(fw):
    firewall, runner = fw
    set_kernel(runner, "22", 40)
    shown(firewall)
    firewall.delete(firewall.snapshot().rules["INPUT"][2])
    firewall.add(NewRule("INPUT", "tcp", "ACCEPT", port="22"))  # the same definition again starts from zero
    assert shown(firewall)["INPUT:4"] == (0, 0)


def test_no_store_means_no_totals():
    assert Firewall(DemoRunner(jitter=False)).counter_totals(Firewall(DemoRunner(jitter=False)).snapshot()) == {}
