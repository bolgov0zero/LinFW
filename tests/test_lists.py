import pytest
from textual.widgets import Button, DataTable, Input, Static, TextArea

from linfw import lists as lst
from linfw.app import LinFWApp
from linfw.demo import DemoRunner
from linfw.firewall import Firewall
from linfw.lists_ui import AddAddressesScreen, ListsScreen, NewListScreen
from linfw.model import FirewallError, NewRule
from linfw.parser import parse_save
from linfw.screens import AddRuleScreen, ConfirmScreen, PickListScreen


# -- pure helpers --------------------------------------------------------------


@pytest.mark.parametrize("text, expected", [
    ("10.0.0.5", "10.0.0.5"), ("10.0.0.5/32", "10.0.0.5"), ("10.0.0.7/24", "10.0.0.0/24"), (" 192.168.1.0/24 ", "192.168.1.0/24"),
])
def test_normalize_entry(text, expected):
    assert lst.normalize_entry(text) == expected


@pytest.mark.parametrize("text", ["", "abc", "999.1.1.1", "10.0.0.0/33", "0.0.0.0/0", "::1", "example.com"])
def test_normalize_entry_rejects(text):
    with pytest.raises(ValueError):
        lst.normalize_entry(text)


def test_parse_entries_accepts_any_separator_and_dedupes():
    good, errors = lst.parse_entries("10.0.0.1, 10.0.0.2;10.0.0.1\n192.168.0.0/16  bad 300.1.1.1")
    assert good == ["10.0.0.1", "10.0.0.2", "192.168.0.0/16"] and len(errors) == 2


def test_names_and_references():
    assert lst.check_name(" office ") == "office"
    for bad in ("", "1abc", "a b", "a" * 40, "тест"):
        with pytest.raises(ValueError):
            lst.check_name(bad)
    assert lst.list_ref("@office") == "office" and lst.list_ref("10.0.0.1") is None and lst.list_ref("@") is None


def test_parse_save_keeps_only_our_sets_sorted():
    text = (
        "create lf_office hash:net family inet hashsize 1024 maxelem 65536\nadd lf_office 192.168.1.0/24\nadd lf_office 10.0.0.5\n"
        "create f2b-sshd hash:ip timeout 600\nadd f2b-sshd 1.2.3.4 timeout 100\ncreate lf_empty hash:net family inet\n"
    )
    assert lst.parse_save(text) == {"empty": [], "office": ["10.0.0.5", "192.168.1.0/24"]}


# -- rules that use lists ---------------------------------------------------------


def test_new_rule_spec_uses_the_set_match():
    rule = NewRule("INPUT", "tcp", "DROP", source="@blocklist", destination="@office", port="22").validated()
    assert rule.to_spec() == [
        "-p", "tcp", "-m", "set", "--match-set", "lf_blocklist", "src", "-m", "set", "--match-set", "lf_office", "dst",
        "--dport", "22", "-j", "DROP",
    ]
    assert rule.used_lists() == ["blocklist", "office"]
    with pytest.raises(ValueError):
        NewRule(source="@bad name").validated()


def test_parser_turns_our_set_match_into_a_column_value_and_leaves_foreign_ones():
    snap = parse_save(
        "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n"
        "[5:300] -A INPUT -m set --match-set lf_blocklist src -p tcp -m tcp --dport 22 -j DROP\n"
        "[0:0] -A INPUT -m set --match-set lf_a src -m set --match-set lf_b dst -j ACCEPT\n"
        "[0:0] -A INPUT -m set --match-set f2b-sshd src -j DROP\n"
        "[0:0] -A INPUT -m set ! --match-set lf_x src -j DROP\nCOMMIT\n"
    )
    ours, both, foreign, negated = snap.rules["INPUT"]
    assert (ours.source, ours.port, ours.protocol, ours.extra, ours.editable) == ("@blocklist", "22", "tcp", (), True)
    assert (both.source, both.destination, both.editable) == ("@a", "@b", True)
    assert foreign.source == "" and foreign.extra and not foreign.editable  # somebody else's set: shown as extra
    assert negated.source == "" and not negated.editable


@pytest.fixture
def fw():
    return Firewall(DemoRunner(jitter=False))


def test_lists_roundtrip_in_the_firewall(fw):
    assert set(fw.lists()) == {"office", "blocklist"}
    fw.create_list("vpn")
    assert fw.lists()["vpn"] == []
    with pytest.raises(FirewallError):
        fw.create_list("vpn")  # already there
    assert fw.add_to_list("vpn", ["10.8.0.0/24", "10.8.0.5", "10.8.0.5"]) == 2
    assert fw.add_to_list("vpn", ["10.8.0.5", "10.9.0.1"]) == 1  # only the new one counts
    assert fw.lists()["vpn"] == ["10.8.0.0/24", "10.8.0.5", "10.9.0.1"]
    fw.remove_from_list("vpn", ["10.8.0.5"])
    fw.remove_from_list("vpn", ["10.8.0.5"])  # removing a missing address is not an error
    assert fw.lists()["vpn"] == ["10.8.0.0/24", "10.9.0.1"]
    fw.delete_list("vpn")
    assert "vpn" not in fw.lists()
    assert fw.lists_overview()[0] == {"blocklist": 2, "office": 2} and fw.lists_overview()[1] is None


def test_a_list_in_use_cannot_be_deleted_and_its_users_are_named(fw):
    fw.ensure_base()
    usage = fw.list_usage()
    assert usage["blocklist"] == ["INPUT #4"] and "office" not in usage
    with pytest.raises(FirewallError, match="INPUT #4"):
        fw.delete_list("blocklist")
    fw.delete_list("office")  # unused: fine


def test_rule_with_a_list_is_added_edited_and_checked(fw):
    fw.add(NewRule("INPUT", "tcp", "ACCEPT", source="@office", port="22"))
    rule = fw.snapshot().rules["INPUT"][-1]
    assert (rule.source, rule.port, rule.editable) == ("@office", "22", True)
    with pytest.raises(FirewallError, match="не найден"):
        fw.add(NewRule("INPUT", "tcp", "ACCEPT", source="@ghost"))
    with pytest.raises(FirewallError, match="не найден"):
        fw.edit(rule, NewRule("INPUT", "tcp", "ACCEPT", destination="@ghost", port="22"))
    fw.edit(rule, NewRule("INPUT", "tcp", "DROP", source="@blocklist", port="22"))
    assert fw.snapshot().rules["INPUT"][-1].source == "@blocklist"
    assert fw.list_usage()["blocklist"] and "office" not in fw.list_usage()
    fw.toggle(fw.snapshot().rules["INPUT"][-1])  # a rule with a list can be switched off and on
    assert fw.snapshot().rules["INPUT"][-1].source == "@blocklist"


def test_editing_a_list_never_touches_the_rules_that_use_it(fw):
    fw.ensure_base()
    before = [r.spec for r in fw.snapshot().rules["INPUT"]]
    fw.add_to_list("blocklist", ["192.0.2.9"])
    fw.remove_from_list("blocklist", ["198.51.100.7"])
    assert [r.spec for r in fw.snapshot().rules["INPUT"]] == before


# -- the windows ---------------------------------------------------------------------


def make_app(**kw):
    runner = DemoRunner(jitter=False, **kw)
    return LinFWApp(Firewall(runner)), runner


async def settle(app, pilot, delay=0.3):
    await pilot.pause(delay)
    await app.workers.wait_for_complete()
    await pilot.pause()


async def test_lists_window_create_fill_and_delete():
    app, runner = make_app()
    async with app.run_test(size=(130, 36)) as pilot:
        await pilot.pause(0.4)
        await pilot.press("f8")
        await settle(app, pilot)
        screen = app.screen
        assert isinstance(screen, ListsScreen)
        lists = screen.query_one("#lists", DataTable)
        entries = screen.query_one("#entries", DataTable)
        assert lists.row_count == 2 and "@blocklist" in str(lists.get_row_at(0)[0])
        assert str(lists.get_row_at(0)[2]) == "1 прав." and entries.row_count == 2  # blocklist is used by one rule

        await pilot.press("n")
        await pilot.pause()
        assert isinstance(app.screen, NewListScreen)
        app.screen.query_one("#name", Input).value = "1bad"
        await pilot.click("#ok")
        await pilot.pause(0.4)
        assert isinstance(app.screen, NewListScreen) and "Название списка" in str(app.screen.query_one("#error").render())
        app.screen.query_one("#name", Input).value = "vpn"
        await pilot.press("enter")
        await settle(app, pilot, 0.5)
        assert "lf_vpn" in runner.sets and screen.query_one("#lists", DataTable).row_count == 3
        assert screen._current == "vpn"  # the new list is selected

        await pilot.press("a")
        await pilot.pause()
        assert isinstance(app.screen, AddAddressesScreen)
        app.screen.query_one(TextArea).text = "10.8.0.1, 10.8.0.0/24\n10.8.0.9 nonsense"
        await pilot.click("#ok")
        await pilot.pause(0.4)
        assert isinstance(app.screen, AddAddressesScreen) and "nonsense" in str(app.screen.query_one("#error").render())
        app.screen.query_one(TextArea).text = "10.8.0.1, 10.8.0.0/24\n10.8.0.9"
        await pilot.click("#ok")
        await settle(app, pilot, 0.5)
        assert sorted(runner.sets["lf_vpn"]) == ["10.8.0.0/24", "10.8.0.1", "10.8.0.9"]
        assert screen.query_one("#entries", DataTable).row_count == 3
        assert runner.persist_calls >= 2  # every change is saved

        screen.query_one("#entries", DataTable).focus()
        await pilot.press("delete")
        await settle(app, pilot, 0.5)
        assert len(runner.sets["lf_vpn"]) == 2

        await pilot.press("x")  # delete the list: confirm first
        await pilot.pause()
        assert isinstance(app.screen, ConfirmScreen)
        await pilot.click("#yes")
        await settle(app, pilot, 0.5)
        assert "lf_vpn" not in runner.sets

        screen.query_one("#lists", DataTable).focus()
        await pilot.press("home", "x")  # blocklist: used by a rule, so it refuses without asking
        await settle(app, pilot, 0.4)
        assert isinstance(app.screen, ListsScreen) and "lf_blocklist" in runner.sets
        await pilot.press("escape")
        await pilot.pause(0.4)
        assert not isinstance(app.screen, ListsScreen)


async def test_pick_a_list_in_the_rule_dialog_and_save():
    app, runner = make_app()
    async with app.run_test(size=(130, 36)) as pilot:
        await pilot.pause(0.5)
        await pilot.press("f1")
        await pilot.pause()
        assert isinstance(app.screen, AddRuleScreen)
        await pilot.click("#pick-source")
        await pilot.pause(0.4)
        assert isinstance(app.screen, PickListScreen)
        await pilot.press("down", "enter")  # office comes after blocklist
        await pilot.pause(0.4)
        assert isinstance(app.screen, AddRuleScreen)
        assert app.screen.query_one("#source", Input).value == "@office"
        await pilot.click("#pick-destination")
        await pilot.pause(0.4)
        await pilot.click("#apply")  # the highlighted first entry: blocklist
        await pilot.pause(0.4)
        assert app.screen.query_one("#destination", Input).value == "@blocklist"
        await pilot.click("#save")
        await settle(app, pilot, 0.5)
        added = runner.rules["INPUT"][-1][2]
        assert added == ["-m", "set", "--match-set", "lf_office", "src", "-m", "set", "--match-set", "lf_blocklist", "dst", "-j", "ACCEPT"]
        table = app.query_one(DataTable)
        last = [str(c) for c in table.get_row_at(table.row_count - 1)]
        assert last[4] == "@office" and last[5] == "@blocklist"  # lists show as @name in the table
        detail = str(app.query_one("#detail", Static).render())
        assert "списка «office»" in detail or "списка «blocklist»" in detail or "Разрешает" in detail


async def test_rule_dialog_without_ipset_explains_instead_of_failing():
    app, runner = make_app()
    runner.ipset = lambda args, stdin=None: (_ for _ in ()).throw(FirewallError("Не установлен пакет ipset"))
    async with app.run_test(size=(130, 36)) as pilot:
        await pilot.pause(0.5)
        await pilot.press("f1")
        await pilot.pause()
        await pilot.click("#pick-source")
        await pilot.pause(0.3)
        assert isinstance(app.screen, AddRuleScreen)
        assert "Списки недоступны" in str(app.screen.query_one("#error").render())
        app.screen.query_one("#source", Input).value = "@office"
        await pilot.click("#save")  # a typed @list is rejected by the firewall layer with the reason
        await settle(app, pilot, 0.5)
        assert any("ipset" in str(n.message) for n in app._notifications)

        await pilot.press("f8")  # the dialog is already closed (the add failed afterwards)
        await settle(app, pilot)
        assert "Списки недоступны" in str(app.screen.query_one("#lstatus", Static).render())


async def test_picker_with_no_lists_and_move_buttons_are_arrows():
    app, _ = make_app(sample=False)
    async with app.run_test(size=(130, 36)) as pilot:
        await pilot.pause(0.5)
        assert str(app.query_one("#btn-up", Button).label) == "F4 ▲" and str(app.query_one("#btn-down", Button).label) == "F5 ▼"
        await pilot.press("f1")
        await pilot.pause()
        await pilot.click("#pick-destination")
        await pilot.pause(0.4)
        assert isinstance(app.screen, PickListScreen) and "Списков пока нет" in str(app.screen.query_one(".hint").render())
        await pilot.press("escape")
        await pilot.pause(0.3)
        assert isinstance(app.screen, AddRuleScreen)
