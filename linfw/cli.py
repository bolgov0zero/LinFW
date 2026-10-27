from __future__ import annotations

import argparse
import os
import shutil
import sys

from . import __version__
from .model import FirewallError


def main() -> None:
    parser = argparse.ArgumentParser(prog="linfw", description="TUI для управления правилами iptables")
    parser.add_argument("--demo", action="store_true", help="работать с тестовыми правилами в памяти (без root и iptables)")
    parser.add_argument("--apply-base", action="store_true", help="поставить базовые правила (loopback, established/related) и сохранить")
    parser.add_argument("--remove-base", action="store_true", help="удалить базовые правила и сохранить")
    parser.add_argument("--logd", action="store_true", help="служба журнала: принимает пакеты правил с журналом (запускается через systemd)")
    parser.add_argument("--version", action="version", version=f"linfw {__version__}")
    args = parser.parse_args()

    from .counters import COUNTERS_FILE, CounterStore
    from .firewall import Firewall, SystemRunner

    if args.demo:
        from .demo import DemoRunner

        runner = DemoRunner()
        counters = CounterStore(None)
    else:
        if not sys.platform.startswith("linux"):
            sys.exit("LinFW работает только в Linux. Для знакомства с интерфейсом: linfw --demo")
        if os.geteuid() != 0:
            # managing iptables needs root: re-run ourselves through sudo if there is one
            if shutil.which("sudo"):
                os.execvp("sudo", ["sudo", sys.executable, "-m", "linfw", *sys.argv[1:]])
            sys.exit("Нужны права root, а sudo не установлен. Станьте root (su -) и запустите linfw снова.")
        try:
            runner = SystemRunner()
        except FirewallError as exc:
            sys.exit(str(exc))
        counters = CounterStore(COUNTERS_FILE)

    if args.logd:
        from . import logd

        logd.run()
        return

    fw = Firewall(runner, counters)
    if args.apply_base or args.remove_base:
        try:
            if args.apply_base:
                changed, done = fw.ensure_base(), "Базовые правила применены"
            else:
                changed, done = fw.remove_base(), "Базовые правила удалены"
            if changed:
                fw.persist()
        except FirewallError as exc:
            sys.exit(str(exc))
        print(done if changed else "Изменений не требуется")
        return

    from .app import LinFWApp

    LinFWApp(fw).run()


if __name__ == "__main__":
    main()
