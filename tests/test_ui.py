from textual.widgets import DataTable, Input, RadioSet, Tabs

from linfw.app import LinFWApp
from linfw.demo import DemoRunner
from linfw.firewall import Firewall
from linfw.screens import AddRuleScreen, ConfirmScreen, TemplateScreen


def make_app():
    runner = DemoRunner(jitter=False)
    return LinFWApp(Firewall(runner)), runner


async def test_table_columns_and_chain_tabs():
    app, _ = make_app()
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        table = app.query_one(DataTable)
        assert [str(c.label) for c in table.columns.values()] == [
            "#", "Pkts", "chain", "protocol", "source", "destination", "port", "action",
        ]
        tabs = app.query_one(Tabs)
        assert [t.id for t in tabs.query("Tab")] == ["tab-INPUT", "tab-OUTPUT", "tab-FORWARD"]  # no ALL
        assert tabs.active == "tab-INPUT"
        assert table.row_count == 6  # hidden base rules are not listed
        assert {str(table.get_row_at(i)[2]) for i in range(table.row_count)} == {"input"}
        await pilot.press("right")
        await pilot.pause()
        assert tabs.active == "tab-OUTPUT" and table.row_count == 2
        assert {str(table.get_row_at(i)[2]) for i in range(table.row_count)} == {"output"}
        await pilot.press("right")
        await pilot.pause()
        assert tabs.active == "tab-FORWARD" and table.row_count == 2
        await pilot.press("right")  # no wrap-around surprises: stays a valid chain tab
        await pilot.pause()
        assert tabs.active in ("tab-INPUT", "tab-FORWARD")


async def test_toolbar_keys_add_delete_toggle_move():
    app, runner = make_app()
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        table = app.query_one(DataTable)
        saved = runner.persist_calls
        last = lambda i: runner.rules["INPUT"][i][2][-1]  # noqa: E731

        # real positions: 0-1 hidden base rules, 2 ssh, 3 web (visible #1, #2)
        await pilot.press("down", "f6")  # disable visible #2
        await pilot.pause(0.3)
        assert last(3) == "LINFW_OFF_ACCEPT"
        assert runner.persist_calls == saved + 1

        await pilot.press("f4")  # up: it must stay selected
        await pilot.pause(0.3)
        assert table.cursor_row == 0
        assert last(2) == "LINFW_OFF_ACCEPT"
        await pilot.press("f4")  # already first: it may not climb over the base rules
        await pilot.pause(0.3)
        assert last(2) == "LINFW_OFF_ACCEPT" and "linfw:base:est" in runner.rules["INPUT"][1][2]
        await pilot.press("f5")
        await pilot.pause(0.3)
        assert table.cursor_row == 1

        await pilot.press("f2")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmScreen)
        await pilot.press("y")
        await pilot.pause(0.3)
        assert len(runner.rules["INPUT"]) == 7
        assert table.row_count == 5  # INPUT tab: one fewer visible rule


async def test_add_dialog_and_validation():
    app, runner = make_app()
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        await pilot.press("f1")
        await pilot.pause()
        assert isinstance(app.screen, AddRuleScreen)
        await pilot.press("f1")  # shortcuts are inert while a dialog is open
        await pilot.pause()
        assert isinstance(app.screen, AddRuleScreen)

        port = app.screen.query_one("#port", Input)
        assert port.disabled
        app.screen.query_one("#protocol", RadioSet).query("RadioButton").last().toggle()  # icmp
        app.screen.query_one("#protocol", RadioSet).query("RadioButton")[1].toggle()  # tcp
        await pilot.pause()
        assert not port.disabled
        port.value = "99999"
        await pilot.click("#save")
        await pilot.pause(0.4)  # a Button ignores presses while its press effect plays
        assert isinstance(app.screen, AddRuleScreen)
        assert "1–65535" in str(app.screen.query_one("#error").render())

        port.value = "8080"
        await pilot.click("#save")
        await pilot.pause(0.3)
        assert not isinstance(app.screen, AddRuleScreen)
        added = [t for _, _, t in runner.rules["INPUT"] if "8080" in t]
        assert added and added[0][-1] == "ACCEPT"


async def test_template_modal_applies_ssh():
    app, runner = make_app()
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        saved = runner.persist_calls
        await pilot.press("f3")
        await pilot.pause()
        assert isinstance(app.screen, TemplateScreen)
        await pilot.press("down", "down", "enter")  # HTTP/HTTPS
        await pilot.pause(0.3)
        assert any("--dports" in t for _, _, t in runner.rules["INPUT"])
        assert runner.persist_calls == saved + 1


async def test_mouse_click_button_and_cancel():
    app, runner = make_app()
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        saved = runner.persist_calls
        await pilot.click("#btn-add")
        await pilot.pause()
        assert isinstance(app.screen, AddRuleScreen)
        await pilot.click("#cancel")
        await pilot.pause()
        assert not isinstance(app.screen, AddRuleScreen)
        assert runner.persist_calls == saved


async def test_switching_to_an_empty_chain_clears_the_table():
    runner = DemoRunner(sample=False, jitter=False)
    runner.rules["INPUT"].append([0, 0, ["-p", "tcp", "--dport", "22", "-j", "ACCEPT"]])
    app = LinFWApp(Firewall(runner))
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        table = app.query_one(DataTable)
        assert table.row_count == 1  # INPUT
        await pilot.press("right")  # OUTPUT: no visible rules (only the hidden base ones)
        await pilot.pause()
        assert table.row_count == 0
        await pilot.press("left")  # INPUT
        await pilot.pause()
        assert table.row_count == 1


async def test_double_click_and_enter_open_the_editor():
    app, runner = make_app()
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        table = app.query_one(DataTable)  # INPUT: visible #1 ssh, #2 web
        # header is line 0, so rows start at y=1: double click the second row
        await pilot.click(DataTable, offset=(10, 2), times=2)
        await pilot.pause()
        assert isinstance(app.screen, AddRuleScreen)
        assert table.cursor_row == 1
        assert app.screen.query_one("#port", Input).value == "80,443"
        assert app.screen.query_one("#chain", RadioSet).disabled
        app.screen.query_one("#port", Input).value = "8443"
        await pilot.click("#save")
        await pilot.pause(0.4)
        assert not isinstance(app.screen, AddRuleScreen)
        assert runner.rules["INPUT"][3][2] == ["-p", "tcp", "--dport", "8443", "-j", "ACCEPT"]
        assert table.cursor_row == 1

        await pilot.press("up", "enter")  # Enter edits the highlighted rule too
        await pilot.pause()
        assert isinstance(app.screen, AddRuleScreen)
        await pilot.press("escape")
        await pilot.pause()

        await pilot.click(DataTable, offset=(10, 0), times=2)  # header: nothing opens
        await pilot.pause()
        assert not isinstance(app.screen, AddRuleScreen)


async def test_complex_rule_is_not_editable_in_dialog():
    runner = DemoRunner(sample=False, jitter=False)
    runner.rules["INPUT"].append([0, 0, ["-i", "eth0", "-j", "DROP"]])
    app = LinFWApp(Firewall(runner))
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert not isinstance(app.screen, AddRuleScreen)


from linfw.screens import JournalScreen  # noqa: E402
from textual.widgets import Checkbox  # noqa: E402


async def test_log_checkbox_creates_a_logged_rule_and_marks_the_row():
    app, runner = make_app()
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        await pilot.press("f1")
        await pilot.pause()
        assert app.screen.query_one("#log", Checkbox).value is False  # off by default
        app.screen.query_one("#protocol", RadioSet).query("RadioButton")[1].toggle()  # tcp
        await pilot.pause()
        app.screen.query_one("#port", Input).value = "9999"
        app.screen.query_one("#log", Checkbox).value = True
        await pilot.click("#save")
        await pilot.pause(0.5)
        assert any("LOG" in t for _, _, t in runner.rules["INPUT"])
        table = app.query_one(DataTable)
        last = [str(c) for c in table.get_row_at(table.row_count - 1)]
        assert last[-1] == "accept ●" and last[6] == "9999"
        assert table.row_count == 7  # the twin is not a row

        await pilot.press("e")  # editing shows the stored flag
        await pilot.pause()
        assert app.screen.query_one("#log", Checkbox).value is True
        await pilot.press("escape")


async def test_journal_screen_filters_and_returns():
    app, runner = make_app()
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        await pilot.click("#btn-journal")
        await pilot.pause(0.5)
        assert isinstance(app.screen, JournalScreen)
        table = app.screen.query_one("#jtable", DataTable)
        total = len(runner.read_journal()[1])
        assert table.row_count == total > 0
        assert [str(c.label) for c in table.columns.values()] == [
            "time", "chain", "protocol", "source", "destination", "port", "action"]

        await pilot.press("f1")  # main-screen shortcuts are inert here
        await pilot.pause()
        assert isinstance(app.screen, JournalScreen)

        await pilot.click("#jf-OUTPUT")
        await pilot.pause(0.4)
        wanted = sum(e.chain == "OUTPUT" for e in runner.read_journal()[1])
        assert table.row_count == wanted
        assert {str(table.get_row_at(i)[1]) for i in range(table.row_count)} == {"output"}
        await pilot.press("right")  # -> FORWARD
        await pilot.pause()
        assert {str(table.get_row_at(i)[1]) for i in range(table.row_count)} <= {"forward"}
        await pilot.press("left", "left", "left")  # back to "Все"
        await pilot.pause()
        assert table.row_count >= total

        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, JournalScreen)
        await pilot.click("#btn-journal")
        await pilot.pause(0.4)
        await pilot.click("#jback")
        await pilot.pause(0.4)
        assert not isinstance(app.screen, JournalScreen)
        await pilot.press("f7")
        await pilot.pause(0.4)
        assert isinstance(app.screen, JournalScreen)
        await pilot.press("f7")  # F7 toggles back
        await pilot.pause(0.4)
        assert not isinstance(app.screen, JournalScreen)


async def test_journal_error_and_empty_states():
    runner = DemoRunner(sample=False, jitter=False)
    app = LinFWApp(Firewall(runner))
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        await pilot.press("f7")
        await pilot.pause(0.4)
        status = str(app.screen.query_one("#jstatus").render())
        assert "Записей нет" in status

        def broken():
            from linfw.model import FirewallError
            raise FirewallError("Журнал ядра недоступен: тест")
        runner.read_journal = broken
        await app.screen._poll()
        assert "недоступен" in str(app.screen.query_one("#jstatus").render())
