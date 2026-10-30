import os
import subprocess
import sys

import pytest

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "install.sh")


def release(tmp_path, **fields):
    path = tmp_path / "os-release"
    path.write_text("".join(f'{k}="{v}"\n' for k, v in fields.items()))
    return str(path)


def supported(path):
    r = subprocess.run(["bash", "-c", f'source "{SCRIPT}"; supported_os "{path}"'], capture_output=True, text=True)
    return r.returncode == 0, r.stdout


@pytest.mark.skipif(sys.platform == "win32", reason="needs bash")
@pytest.mark.parametrize(
    "fields, ok",
    [
        (dict(ID="debian", PRETTY_NAME="Debian GNU/Linux 12"), True),
        (dict(ID="ubuntu", ID_LIKE="debian", PRETTY_NAME="Ubuntu 24.04"), True),
        (dict(ID="linuxmint", ID_LIKE="ubuntu debian", PRETTY_NAME="Linux Mint"), True),  # derivatives are fine
        (dict(ID="raspbian", ID_LIKE="debian", PRETTY_NAME="Raspbian"), True),
        (dict(ID="fedora", PRETTY_NAME="Fedora Linux 40"), False),
        (dict(ID="arch", PRETTY_NAME="Arch Linux"), False),
        (dict(ID="alpine", PRETTY_NAME="Alpine Linux"), False),
        (dict(ID="rocky", ID_LIKE="rhel centos fedora", PRETTY_NAME="Rocky Linux 9"), False),
        (dict(ID="debianlike", PRETTY_NAME="Not Debian"), False),  # a name that merely contains «debian»
    ],
)
def test_only_debian_family_is_supported(tmp_path, fields, ok):
    good, name = supported(release(tmp_path, **fields))
    assert good is ok and name == fields["PRETTY_NAME"]


def test_unsupported_system_stops_the_step_with_a_message(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    script = f'''
source "{SCRIPT}"
STATE="{state}"; NOTE_FILE="$STATE/note"; FATAL_FILE="$STATE/fatal"; : > "$NOTE_FILE"; : > "$FATAL_FILE"
OS_RELEASE="{release(tmp_path, ID="fedora", PRETTY_NAME="Fedora Linux 40")}"
( set -e; step_system )
echo "rc=$?"
'''
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert "rc=1" in r.stdout
    message = (state / "fatal").read_text()
    assert "только Debian и Ubuntu" in message and "Fedora Linux 40" in message
