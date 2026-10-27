from textual.widgets import DataTable, Input, RadioSet, Tabs

from linfw.app import LinFWApp
from linfw.demo import DemoRunner
from linfw.firewall import Firewall
from linfw.screens import AddRuleScreen, ConfirmScreen, TemplateScreen


def make_app():
    runner = DemoRunner(jitter=False)
    return LinFWApp(Firewall(runner)), runner


async def test_table_columns_and_tabs():
    app, _ = make_app()
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        table = app.query_one(DataTable)
        assert [str(c.label) for c in table.columns.values()] == [
            "#", "Pkts", "chain", "protocol", "source", "destination", "port", "action",
        ]
        assert table.row_count == 13
        await pilot.press("right")  # ALL -> INPUT
        await pilot.pause()
        assert app.query_one(Tabs).active == "tab-INPUT"
        assert table.row_count == 8
        await pilot.press("right", "right")
        await pilot.pause()
        assert table.row_count == 2  # FORWARD


async def test_toolbar_keys_add_delete_toggle_move():
    app, runner = make_app()
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        await pilot.press("right")  # INPUT tab
        await pilot.pause()
        table = app.query_one(DataTable)

        await pilot.press("down", "down", "f6")  # disable rule #3 (ssh)
        await pilot.pause(0.3)
        assert runner.rules["INPUT"][2][2][-1] == "LINFW_OFF_ACCEPT"
        assert runner.persist_calls == 1

        await pilot.press("f4")  # up: it must stay selected
        await pilot.pause(0.3)
        assert table.cursor_row == 1
        assert runner.rules["INPUT"][1][2][-1] == "LINFW_OFF_ACCEPT"
        await pilot.press("f5")
        await pilot.pause(0.3)
        assert table.cursor_row == 2

        await pilot.press("f2")
        await pilot.pause()
        assert isinstance(app.screen, ConfirmScreen)
        await pilot.press("y")
        await pilot.pause(0.3)
        assert len(runner.rules["INPUT"]) == 7


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
        await pilot.press("f3")
        await pilot.pause()
        assert isinstance(app.screen, TemplateScreen)
        await pilot.press("down", "down", "enter")  # HTTP/HTTPS
        await pilot.pause(0.3)
        assert any("--dports" in t for _, _, t in runner.rules["INPUT"])
        assert runner.persist_calls == 1


async def test_mouse_click_button_and_cancel():
    app, runner = make_app()
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        await pilot.click("#btn-add")
        await pilot.pause()
        assert isinstance(app.screen, AddRuleScreen)
        await pilot.click("#cancel")
        await pilot.pause()
        assert not isinstance(app.screen, AddRuleScreen)
        assert runner.persist_calls == 0


async def test_switching_to_an_empty_chain_clears_the_table():
    runner = DemoRunner(sample=False, jitter=False)
    runner.rules["INPUT"].append([0, 0, ["-p", "tcp", "--dport", "22", "-j", "ACCEPT"]])
    app = LinFWApp(Firewall(runner))
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.pause()
        table = app.query_one(DataTable)
        assert table.row_count == 1  # ALL
        await pilot.press("right", "right")  # OUTPUT: no rules
        await pilot.pause()
        assert table.row_count == 0
        await pilot.press("left")  # INPUT
        await pilot.pause()
        assert table.row_count == 1
