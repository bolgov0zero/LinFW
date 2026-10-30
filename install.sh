#!/usr/bin/env bash
# LinFW installer.
#   curl -fsSL https://raw.githubusercontent.com/bolgov0zero/LinFW/main/install.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/bolgov0zero/LinFW/main/install.sh | bash   # as root, no sudo needed
#   ./install.sh              # from a cloned repository (uses sudo if present and you are not root)
#   ./install.sh --uninstall
#
# Installs LinFW into a private virtualenv (/opt/linfw), links /usr/local/bin/linfw,
# sets up the distro's way of restoring iptables rules after a reboot, applies the
# base rules and installs the linfw-logd service (journal and persistent counters).
#
# The screen is cleared and only the steps are shown, each with a spinner and then a
# check mark. Everything the tools print goes to a log file, which is shown (its tail)
# only if a step fails. Set NO_COLOR=1 for plain output.
set -uo pipefail

REPO="${LINFW_REPO:-bolgov0zero/LinFW}"
REF="${LINFW_REF:-main}"
PREFIX="${LINFW_PREFIX:-/opt/linfw}"
LINK="/usr/local/bin/linfw"
UNIT="/etc/systemd/system/linfw-logd.service"

# --- screen -------------------------------------------------------------------

setup_ui() {
  TTY=0
  [ -t 1 ] && TTY=1
  if [ "$TTY" = 1 ] && [ -z "${NO_COLOR:-}" ]; then
    C_OK=$'\033[32m' C_ERR=$'\033[31m' C_WARN=$'\033[33m' C_DIM=$'\033[2m'
    C_BOLD=$'\033[1m' C_ACC=$'\033[36m' C_OFF=$'\033[0m'
  else
    C_OK="" C_ERR="" C_WARN="" C_DIM="" C_BOLD="" C_ACC="" C_OFF=""
  fi
  case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
    *[Uu][Tt][Ff]-8* | *[Uu][Tt][Ff]8*)
      FRAMES=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
      M_OK="✔" M_ERR="✘" M_WARN="!" RULE="──────────────────────────────────────────────" ;;
    *)
      FRAMES=('-' '\' '|' '/')
      M_OK="+" M_ERR="x" M_WARN="!" RULE="----------------------------------------------" ;;
  esac
}

ui_start() {
  if [ "$TTY" = 1 ]; then
    printf '\033[2J\033[H\033[?25l'   # clear the screen, hide the cursor
  fi
  printf '\n  %sLinFW%s  %s·  управление iptables в терминале%s\n' "$C_BOLD$C_ACC" "$C_OFF" "$C_DIM" "$C_OFF"
  printf '  %s%s%s\n\n' "$C_DIM" "$RULE" "$C_OFF"
}

cleanup() {
  [ "$TTY" = 1 ] && printf '\033[?25h'   # show the cursor again
  local running
  running="$(jobs -p 2> /dev/null)"
  [ -n "$running" ] && kill $running 2> /dev/null   # a step still running after Ctrl+C
  [ "${KEEP_LOG:-0}" = 1 ] || rm -rf "${STATE:-/nonexistent}"
}

# Called by the steps (they run in a subshell, so they talk to the screen through files):
note() { printf '%s\n' "$*" >> "$NOTE_FILE"; }        # grey detail after the step's name
warn_note() { printf '%s\n' "$*" >> "$WARN_FILE"; }   # yellow line under the step
abort() { printf '%s\n' "$@" > "$FATAL_FILE"; exit 1; }  # stop the installation with an explanation

# run_step "Title" function: spinner while it runs, then a check mark (or a cross and the log).
run_step() {
  local title="$1" fn="$2" rc i=0 label detail line
  STEP=$((STEP + 1))
  label="[$STEP/$TOTAL] $title"
  : > "$NOTE_FILE"
  : > "$WARN_FILE"
  : > "$FATAL_FILE"
  if [ "$TTY" = 1 ]; then
    ( set -e; "$fn" ) < /dev/null >> "$LOG" 2>&1 &
    local pid=$!
    while kill -0 "$pid" 2> /dev/null; do
      printf '\r  %s%s%s %s' "$C_ACC" "${FRAMES[i % ${#FRAMES[@]}]}" "$C_OFF" "$label"
      i=$((i + 1))
      sleep 0.1
    done
    wait "$pid"
    rc=$?
    printf '\r\033[K'
  else
    printf '  ... %s\n' "$label"
    ( set -e; "$fn" ) < /dev/null >> "$LOG" 2>&1
    rc=$?
  fi
  if [ "$rc" -ne 0 ]; then
    printf '  %s%s%s %s\n\n' "$C_ERR" "$M_ERR" "$C_OFF" "$label"
    if [ -s "$FATAL_FILE" ]; then
      # a deliberate refusal (unsupported system): say why, no log needed
      sed 's/^/    /' "$FATAL_FILE"
      printf '\n'
    else
      printf '  %sПоследние строки журнала:%s\n' "$C_DIM" "$C_OFF"
      tail -n 12 "$LOG" | sed 's/^/    /'
      printf '\n  Полный журнал: %s\n\n' "$LOG"
      KEEP_LOG=1
    fi
    exit 1
  fi
  detail=""
  [ -s "$NOTE_FILE" ] && detail="  ${C_DIM}$(head -n 1 "$NOTE_FILE")${C_OFF}"
  printf '  %s%s%s %s%s\n' "$C_OK" "$M_OK" "$C_OFF" "$label" "$detail"
  while IFS= read -r line; do
    printf '      %s%s %s%s\n' "$C_WARN" "$M_WARN" "$line" "$C_OFF"
  done < "$WARN_FILE"
}

fail_early() {
  printf '\n  %s%s%s %s\n\n' "$C_ERR" "$M_ERR" "$C_OFF" "$*" >&2
  exit 1
}

# --- steps --------------------------------------------------------------------

# 0 if the os-release file describes Debian, Ubuntu or a derivative (Mint, Raspberry Pi OS ...);
# prints the pretty name either way
supported_os() {
  local file="${1:-${OS_RELEASE:-/etc/os-release}}" id="" like="" name="Linux"
  if [ -r "$file" ]; then
    id="$(. "$file"; printf '%s' "${ID:-}")"
    like="$(. "$file"; printf '%s' "${ID_LIKE:-}")"
    name="$(. "$file"; printf '%s' "${PRETTY_NAME:-Linux}")"
  fi
  printf '%s' "$name"
  case " $id $like " in
    *" debian "* | *" ubuntu "*) return 0 ;;
  esac
  return 1
}

step_system() {
  local name
  if ! name="$(supported_os)"; then
    abort "LinFW поддерживает только Debian и Ubuntu (и их производные)." \
          "Ваша система: $name." \
          "Нужны пакеты iptables-persistent и ipset-persistent: на других дистрибутивах" \
          "правила и адресные списки не переживут перезагрузку."
  fi
  command -v apt-get > /dev/null || abort "Не найден apt-get: установка возможна только на системах с apt."
  note "$name"
}

# python3 + venv, iptables, and what restores rules and address lists at boot
step_packages() {
  export DEBIAN_FRONTEND=noninteractive
  # answer iptables-persistent's "save current rules?" questions
  if command -v debconf-set-selections > /dev/null; then
    echo "iptables-persistent iptables-persistent/autosave_v4 boolean true" | debconf-set-selections
    echo "iptables-persistent iptables-persistent/autosave_v6 boolean true" | debconf-set-selections
  fi
  apt-get update -qq
  apt-get install -y -qq python3 python3-venv iptables iptables-persistent netfilter-persistent
  python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' || { echo "Нужен Python 3.9 или новее" >&2; exit 1; }
  # address lists are ipset sets; ipset-persistent restores them before the rules at boot
  if apt-get install -y -qq ipset ipset-persistent; then
    if ipset create -exist linfw_probe hash:net && ipset destroy linfw_probe; then
      note "iptables-persistent, ipset-persistent"
    else
      warn_note "ipset недоступен в ядре: адресные списки не будут работать (в контейнере: modprobe ip_set ip_set_hash_net на хосте)"
    fi
  else
    warn_note "не удалось поставить ipset-persistent: адресные списки не переживут перезагрузку"
  fi
  printf '%s' "netfilter-persistent" > "$STATE/persist"
  return 0
}

step_linfw() {
  python3 -m venv "$PREFIX" || { echo "не удалось создать virtualenv (нужен пакет python3-venv)" >&2; exit 1; }
  "$PREFIX/bin/pip" install --quiet --disable-pip-version-check --upgrade pip
  "$PREFIX/bin/pip" install --quiet --disable-pip-version-check --upgrade --no-cache-dir "$SRC"
  # the package version does not change between commits, so pip would skip an
  # update above: force-reinstall LinFW itself (dependencies are already in place)
  "$PREFIX/bin/pip" install --quiet --disable-pip-version-check --force-reinstall --no-deps --no-cache-dir "$SRC"
  ln -sf "$PREFIX/bin/linfw" "$LINK"
  note "$("$PREFIX/bin/linfw" --version)"
}

# loopback + established/related on top of every chain, hidden in the UI
step_base_rules() {
  if "$PREFIX/bin/linfw" --apply-base; then
    note "loopback, established/related"
  else
    warn_note "не удалось применить; LinFW повторит попытку при запуске"
  fi
}

# linfw-logd records packets of rules with logging on (iptables NFLOG) and samples the counters
step_service() {
  if [ -d /run/systemd/system ] && command -v systemctl > /dev/null; then
    cat > "$UNIT" << UNITFILE
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
UNITFILE
    systemctl daemon-reload
    systemctl enable linfw-logd || warn_note "не удалось включить linfw-logd"
    if systemctl restart linfw-logd; then
      note "linfw-logd запущен"
    else
      warn_note "linfw-logd не запустился: journalctl -u linfw-logd"
    fi
  else
    warn_note "нет systemd: журнал и сохранение счётчиков не работают. Запуск вручную: linfw --logd"
  fi
}

step_remove_rules() {
  if [ -x "$PREFIX/bin/linfw" ]; then
    "$PREFIX/bin/linfw" --remove-base || warn_note "не удалось удалить базовые правила"
  fi
}

step_remove_service() {
  if command -v systemctl > /dev/null && [ -f "$UNIT" ]; then
    systemctl disable --now linfw-logd || true
    rm -f "$UNIT"
    systemctl daemon-reload || true
  fi
}

step_remove_files() {
  rm -rf "$PREFIX"
  [ -L "$LINK" ] && rm -f "$LINK"
  return 0
}

# --- main ---------------------------------------------------------------------

main() {
  setup_ui
  TOTAL=0 STEP=0 KEEP_LOG=0
  [ "$(uname -s)" = "Linux" ] || fail_early "LinFW работает только в Linux."

  if [ "$(id -u)" -ne 0 ]; then
    # sudo is optional: as root (e.g. after `su -`) just run the script without it
    local self="${BASH_SOURCE[0]:-}" url="https://raw.githubusercontent.com/${REPO}/${REF}/install.sh"
    if command -v sudo > /dev/null && [ -n "$self" ] && [ -f "$self" ]; then
      exec sudo bash "$self" "$@"
    fi
    if command -v sudo > /dev/null; then
      fail_early "Нужны права root. Запустите: curl -fsSL $url | sudo bash"
    fi
    fail_early "Нужны права root, а sudo не установлен. Станьте root (su -) и запустите: curl -fsSL $url | bash"
  fi

  # where LinFW comes from: this checkout if the script lives in one, otherwise GitHub
  SRC=""
  local self="${BASH_SOURCE[0]:-}" here
  if [ -n "$self" ] && [ -f "$self" ]; then
    here="$(cd "$(dirname "$self")" && pwd)"
    [ -f "$here/pyproject.toml" ] && SRC="$here"
  fi
  [ -n "$SRC" ] || SRC="https://github.com/${REPO}/archive/refs/heads/${REF}.tar.gz"

  STATE="$(mktemp -d "${TMPDIR:-/tmp}/linfw-install.XXXXXX")"
  LOG="$STATE/install.log"
  NOTE_FILE="$STATE/note"
  WARN_FILE="$STATE/warn"
  FATAL_FILE="$STATE/fatal"
  : > "$LOG"
  trap cleanup EXIT
  trap 'exit 130' INT TERM

  ui_start
  if [ "${1:-}" = "--uninstall" ]; then
    TOTAL=3
    run_step "Удаление базовых правил" step_remove_rules
    run_step "Остановка службы журнала" step_remove_service
    run_step "Удаление файлов" step_remove_files
    printf '\n  %s%s%s %sLinFW удалён.%s Сохранённые правила iptables и пакеты автозагрузки не тронуты.\n\n' \
      "$C_OK" "$M_OK" "$C_OFF" "$C_BOLD" "$C_OFF"
    return 0
  fi

  TOTAL=5
  run_step "Проверка системы" step_system
  run_step "Установка зависимостей" step_packages
  run_step "Установка LinFW" step_linfw
  run_step "Базовые правила" step_base_rules
  run_step "Служба журнала" step_service

  local persist=""
  [ -s "$STATE/persist" ] && persist="$(cat "$STATE/persist")"
  printf '\n  %s%s%s %sГотово.%s Запуск:  %slinfw%s\n' "$C_OK" "$M_OK" "$C_OFF" "$C_BOLD" "$C_OFF" "$C_ACC" "$C_OFF"
  if [ -n "$persist" ]; then
    printf '    %sПравила сохраняются автоматически (%s).%s\n\n' "$C_DIM" "$persist" "$C_OFF"
  else
    printf '    %s%s Автосохранение правил не настроено: после перезагрузки они пропадут.%s\n\n' "$C_WARN" "$M_WARN" "$C_OFF"
  fi
}

# run main when executed (also when piped into bash), but not when the file is only sourced
if [ "${BASH_SOURCE[0]:-$0}" = "$0" ]; then
  main "$@"
fi
