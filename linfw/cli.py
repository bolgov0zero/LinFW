from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .model import FirewallError


def main() -> None:
    parser = argparse.ArgumentParser(prog="linfw", description="TUI для управления правилами iptables")
    parser.add_argument("--demo", action="store_true", help="работать с тестовыми правилами в памяти (без root и iptables)")
    parser.add_argument("--version", action="version", version=f"linfw {__version__}")
    args = parser.parse_args()

    from .firewall import Firewall, SystemRunner

    if args.demo:
        from .demo import DemoRunner

        runner = DemoRunner()
    else:
        if not sys.platform.startswith("linux"):
            sys.exit("LinFW работает только в Linux. Для знакомства с интерфейсом: linfw --demo")
        if os.geteuid() != 0:
            # managing iptables needs root: re-run ourselves through sudo
            os.execvp("sudo", ["sudo", sys.executable, "-m", "linfw", *sys.argv[1:]])
        try:
            runner = SystemRunner()
        except FirewallError as exc:
            sys.exit(str(exc))

    from .app import LinFWApp

    LinFWApp(Firewall(runner)).run()


if __name__ == "__main__":
    main()
