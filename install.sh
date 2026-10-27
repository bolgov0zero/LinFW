#!/usr/bin/env bash
# LinFW installer.
#   curl -fsSL https://raw.githubusercontent.com/bolgov0zero/LinFW/main/install.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/bolgov0zero/LinFW/main/install.sh | bash   # as root, no sudo needed
#   ./install.sh              # from a cloned repository (uses sudo if present and you are not root)
#   ./install.sh --uninstall
#
# Installs LinFW into a private virtualenv (/opt/linfw), links /usr/local/bin/linfw
# and sets up the distro's mechanism for restoring iptables rules after a reboot.
set -euo pipefail

REPO="${LINFW_REPO:-bolgov0zero/LinFW}"
REF="${LINFW_REF:-main}"
PREFIX="${LINFW_PREFIX:-/opt/linfw}"
LINK="/usr/local/bin/linfw"

say() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARN:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = "Linux" ] || die "LinFW работает только в Linux."

if [ "$(id -u)" -ne 0 ]; then
  # sudo is optional: as root (e.g. after `su -`) just run the script without it
  SELF="${BASH_SOURCE[0]:-}"
  if command -v sudo >/dev/null && [ -n "$SELF" ] && [ -f "$SELF" ]; then
    exec sudo bash "$SELF" "$@"
  fi
  URL="https://raw.githubusercontent.com/${REPO}/${REF}/install.sh"
  if command -v sudo >/dev/null; then
    die "Нужны права root. Запустите: curl -fsSL $URL | sudo bash"
  fi
  die "Нужны права root, а sudo не установлен. Станьте root (su -) и запустите: curl -fsSL $URL | bash"
fi

if [ "${1:-}" = "--uninstall" ]; then
  [ -x "$PREFIX/bin/linfw" ] && { "$PREFIX/bin/linfw" --remove-base || warn "не удалось удалить базовые правила"; }
  if command -v systemctl >/dev/null && [ -f /etc/systemd/system/linfw-logd.service ]; then
    systemctl disable --now linfw-logd >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/linfw-logd.service
    systemctl daemon-reload || true
  fi
  rm -rf "$PREFIX"
  [ -L "$LINK" ] && rm -f "$LINK"
  say "LinFW удалён. Сохранённые правила iptables и пакеты автозагрузки не тронуты."
  exit 0
fi

# --- 1. packages -----------------------------------------------------------
# python3 + venv, iptables, and whatever restores the rules at boot.
install_packages() {
  if command -v apt-get >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    # answer iptables-persistent's "save current rules?" questions
    if command -v debconf-set-selections >/dev/null; then
      echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
      echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
    fi
    apt-get update -qq
    apt-get install -y python3 python3-venv iptables iptables-persistent netfilter-persistent
    PERSIST="netfilter-persistent"
  elif command -v dnf >/dev/null || command -v yum >/dev/null; then
    local pm; pm="$(command -v dnf || command -v yum)"
    "$pm" install -y python3 iptables iptables-services
    # keep the rules that are active right now, then enable restore at boot
    # (do not start the service: that would replace the live rules with the file)
    iptables-save > /etc/sysconfig/iptables
    chmod 600 /etc/sysconfig/iptables
    systemctl enable iptables >/dev/null 2>&1 || warn "не удалось включить сервис iptables"
    if systemctl is-active --quiet firewalld 2>/dev/null; then
      warn "firewalld активен и управляет правилами сам. Отключите его: systemctl disable --now firewalld"
    fi
    PERSIST="/etc/sysconfig/iptables"
  elif command -v pacman >/dev/null; then
    pacman -S --noconfirm --needed python iptables
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/iptables.rules
    systemctl enable iptables >/dev/null 2>&1 || warn "не удалось включить сервис iptables"
    PERSIST="/etc/iptables/iptables.rules"
  elif command -v apk >/dev/null; then
    apk add --no-cache python3 py3-pip iptables
    rc-update add iptables >/dev/null 2>&1 || true
    /etc/init.d/iptables save >/dev/null 2>&1 || true
    PERSIST="/etc/init.d/iptables"
  else
    warn "Неизвестный дистрибутив: поставьте вручную python3 (>=3.9, с venv), iptables и пакет сохранения правил."
    PERSIST=""
  fi
}

PERSIST=""
say "Устанавливаю зависимости"
install_packages

command -v python3 >/dev/null || die "python3 не найден"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' || die "Нужен Python 3.9 или новее"

# --- 2. LinFW itself -------------------------------------------------------
say "Устанавливаю LinFW в $PREFIX"
python3 -m venv "$PREFIX" || die "не удалось создать virtualenv (нужен пакет python3-venv)"
"$PREFIX/bin/pip" install --quiet --upgrade pip

SRC=""
SELF="${BASH_SOURCE[0]:-}"
if [ -n "$SELF" ] && [ -f "$SELF" ]; then
  HERE="$(cd "$(dirname "$SELF")" && pwd)"
  [ -f "$HERE/pyproject.toml" ] && SRC="$HERE"
fi
[ -n "$SRC" ] || SRC="https://github.com/${REPO}/archive/refs/heads/${REF}.tar.gz"
"$PREFIX/bin/pip" install --quiet --upgrade --no-cache-dir "$SRC"
# the package version does not change between commits, so pip would skip an
# update above: force-reinstall LinFW itself (dependencies are already in place)
"$PREFIX/bin/pip" install --quiet --force-reinstall --no-deps --no-cache-dir "$SRC"

ln -sf "$PREFIX/bin/linfw" "$LINK"

# --- 3. base rules ---------------------------------------------------------
# loopback + established/related on top of every chain, hidden in the UI
say "Применяю базовые правила (loopback, established/related)"
"$PREFIX/bin/linfw" --apply-base || warn "не удалось применить базовые правила; LinFW повторит попытку при запуске"

# --- 4. journal service ----------------------------------------------------
# linfw-logd records packets from rules that have logging on (iptables NFLOG target)
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null; then
  say "Устанавливаю службу журнала linfw-logd"
  cat > /etc/systemd/system/linfw-logd.service <<UNIT
[Unit]
Description=LinFW background service: rule hit journal and persistent counters
# started after the firewall is restored, stopped before it is torn down, so the last counters are saved
After=network.target netfilter-persistent.service iptables.service

[Service]
ExecStart=$PREFIX/bin/linfw --logd
Restart=on-failure
RestartSec=10
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable linfw-logd >/dev/null 2>&1 || warn "не удалось включить linfw-logd"
  systemctl restart linfw-logd || warn "linfw-logd не запустился: journalctl -u linfw-logd"
else
  warn "systemd не найден: журнал срабатываний и сохранение счётчиков не будут работать. Службу запускают командой: linfw --logd"
fi

# --- 5. done ---------------------------------------------------------------
say "Готово. Запуск: linfw"
if [ -n "$PERSIST" ]; then
  say "Правила сохраняются автоматически (${PERSIST})."
else
  warn "Автосохранение правил не настроено — после перезагрузки они пропадут."
fi
