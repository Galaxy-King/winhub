#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

action=""
hosts_file=""
package_path=""
runtime_config="$script_dir/winhub_agent.conf"
bootstrap_config="$script_dir/winhub_agent.bootstrap.conf"
ssh_user="${WINHUB_DEPLOY_SSH_USER:-root}"
ssh_port="${WINHUB_DEPLOY_SSH_PORT:-22}"
ssh_key="${WINHUB_DEPLOY_SSH_KEY:-}"
force_install=0
sync_config=1
purge=0
assume_yes=0

usage() {
  cat <<'EOF'
Масове керування WinHUB Linux Agent через SSH.

Використання:
  ./deploy-linux-agents.sh [--action install|uninstall|reinstall] [--hosts FILE] [параметри]

Якщо --action не задано, скрипт інтерактивно запитає режим роботи.
Якщо --hosts не задано, скрипт запропонує файл linux_hosts.txt.

Режими:
  install       Встановити відсутній агент або оновити старішу версію.
  uninstall     Зупинити службу та видалити службу і файли агента.
  reinstall     Примусово замінити службу і файли агента пакетом.

Параметри:
  --action MODE          install, uninstall або reinstall.
  --hosts FILE           IP/hostname по одному на рядок; можна user@host.
  --package FILE         Архів агента. Типово береться найновіший
                         WinHUBLinuxAgent-v*-linux-{x64,arm64}.tar.gz.
  --config FILE          Runtime-конфіг. Типово: ./winhub_agent.conf.
  --bootstrap FILE       Bootstrap-конфіг. Типово: ./winhub_agent.bootstrap.conf.
  --user USER            SSH-користувач для рядків без user@host. Типово: root.
  --port PORT            SSH-порт. Типово: 22.
  --identity FILE        Приватний SSH-ключ.
  --force                У режимі install замінити також поточну/новішу версію.
  --no-config-sync       Не копіювати конфіги на сервери.
  --purge                Разом із uninstall/reinstall видалити /etc/winhub-agent
                         і /var/lib/winhub-agent. Це видаляє токен та ідентичність.
  --yes                  Не запитувати фінальне підтвердження.
  -h, --help             Показати довідку.

SSH-користувач повинен бути root або мати passwordless sudo (sudo -n).

Приклади:
  ./deploy-linux-agents.sh
  ./deploy-linux-agents.sh --action install --hosts linux_hosts.txt --identity ~/.ssh/id_ed25519
  ./deploy-linux-agents.sh --action uninstall --hosts linux_hosts.txt
  ./deploy-linux-agents.sh --action reinstall --hosts linux_hosts.txt --yes
EOF
}

die() {
  echo "ПОМИЛКА: $*" >&2
  exit 1
}

need_value() {
  local option="$1"
  local value="${2:-}"
  [[ -n "$value" ]] || die "Параметр $option потребує значення."
}

normalize_action() {
  case "${1,,}" in
    1|install|i) printf '%s' "install" ;;
    2|uninstall|remove|delete|u) printf '%s' "uninstall" ;;
    3|reinstall|r) printf '%s' "reinstall" ;;
    *) return 1 ;;
  esac
}

prompt_for_action() {
  local answer normalized
  echo "Оберіть режим роботи:" >&2
  echo "  1) Встановлення / оновлення" >&2
  echo "  2) Видалення" >&2
  echo "  3) Перевстановлення" >&2
  while true; do
    read -r -p "Режим [1-3]: " answer || return 1
    if normalized="$(normalize_action "$answer")"; then
      printf '%s' "$normalized"
      return 0
    fi
    echo "Введіть 1, 2 або 3." >&2
  done
}

find_latest_package() {
  local candidate latest=""
  shopt -s nullglob
  local candidates=(
    "$script_dir"/WinHUBLinuxAgent-v*-linux-x64.tar.gz
    "$script_dir"/dist-agent/WinHUBLinuxAgent-v*-linux-x64.tar.gz
  )
  shopt -u nullglob

  for candidate in "${candidates[@]}"; do
    if [[ -z "$latest" || "$candidate" -nt "$latest" ]]; then
      latest="$candidate"
    fi
  done

  # x64 is the default rollout architecture. Fall back to ARM only when no
  # x64 package exists; an explicit --package is clearer for mixed fleets.
  if [[ -z "$latest" ]]; then
    shopt -s nullglob
    candidates=(
      "$script_dir"/WinHUBLinuxAgent-v*-linux-arm64.tar.gz
      "$script_dir"/dist-agent/WinHUBLinuxAgent-v*-linux-arm64.tar.gz
    )
    shopt -u nullglob
    for candidate in "${candidates[@]}"; do
      if [[ -z "$latest" || "$candidate" -nt "$latest" ]]; then
        latest="$candidate"
      fi
    done
  fi
  printf '%s' "$latest"
}

validate_package_archive() {
  local archive="$1"
  local listing entry normalized required found
  local required_files=(
    "WinHUBLinuxAgent"
    "install-linux-agent.sh"
    "update-linux-agent.sh"
    "winhub-linux-agent.service"
  )

  if ! listing="$(tar -tzf "$archive")"; then
    return 1
  fi

  while IFS= read -r entry; do
    normalized="${entry#./}"
    if [[ "$normalized" == /* || "$normalized" == ".." || "$normalized" == ../* || "$normalized" == */../* || "$normalized" == */.. ]]; then
      echo "Небезпечний шлях в архіві: $entry" >&2
      return 1
    fi
  done <<< "$listing"

  for required in "${required_files[@]}"; do
    found=0
    while IFS= read -r entry; do
      if [[ "${entry#./}" == "$required" ]]; then
        found=1
        break
      fi
    done <<< "$listing"
    if [[ "$found" -ne 1 ]]; then
      echo "В архіві відсутній обов'язковий файл: $required" >&2
      return 1
    fi
  done
}

version_is_older() {
  local current="$1"
  local target="$2"
  [[ "$current" != "$target" ]] &&
    [[ "$(printf '%s\n%s\n' "$current" "$target" | sort -V | head -n1)" == "$current" ]]
}

remote_for_host() {
  local item="$1"
  if [[ "$item" == *@* ]]; then
    printf '%s' "$item"
  else
    printf '%s@%s' "$ssh_user" "$item"
  fi
}

validate_host_entry() {
  local entry="$1"
  local entry_user="" entry_target="$entry"

  if [[ "$entry" == *@* ]]; then
    entry_user="${entry%%@*}"
    entry_target="${entry#*@}"
    [[ "$entry_target" != *@* ]] || return 1
    [[ "$entry_user" =~ ^[A-Za-z_][A-Za-z0-9._-]*$ ]] || return 1
  fi

  if [[ "$entry_target" == *:* ]]; then
    # Brackets keep IPv6 destinations unambiguous for both ssh and scp.
    [[ "$entry_target" =~ ^\[[A-Za-z0-9:.%_-]+\]$ ]] || return 1
  else
    [[ "$entry_target" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || return 1
  fi
}

cleanup_remote_tmp() {
  local remote="$1"
  local remote_tmp="$2"
  local root_runner="$3"
  local remote_command
  [[ "$remote_tmp" =~ ^/tmp/winhub-agent-deploy\.[A-Za-z0-9]+$ ]] || return 0
  remote_command="$root_runner -- $remote_tmp"
  ssh "${ssh_opts[@]}" "$remote" "$remote_command" >/dev/null 2>&1 <<'REMOTE_SCRIPT' || true
set -eu
deploy_tmp="$1"
case "$deploy_tmp" in
  /tmp/winhub-agent-deploy.*) rm -rf -- "$deploy_tmp" ;;
  *) exit 2 ;;
esac
REMOTE_SCRIPT
}

preflight_host() {
  local remote="$1"
  local output marker uid os_id os_like machine_arch normalized_os

  if ! output="$(ssh "${ssh_opts[@]}" "$remote" 'set -eu
    test -r /etc/os-release
    command -v bash >/dev/null
    command -v systemctl >/dev/null
    . /etc/os-release
    printf "__WINHUB_PREFLIGHT__%s|%s|%s|%s\n" "$(id -u)" "${ID:-}" "${ID_LIKE:-}" "$(uname -m)"
  ' 2>&1)"; then
    echo "    SSH/preflight не виконано: $output" >&2
    return 1
  fi

  marker="$(printf '%s\n' "$output" | sed -n 's/^__WINHUB_PREFLIGHT__//p' | tail -n1)"
  if [[ -z "$marker" ]]; then
    echo "    Не вдалося прочитати /etc/os-release або UID на сервері." >&2
    return 1
  fi

  IFS='|' read -r uid os_id os_like machine_arch <<< "$marker"
  normalized_os="${os_id,,} ${os_like,,}"
  if [[ "$normalized_os" != *debian* && "$normalized_os" != *ubuntu* ]]; then
    echo "    Непідтримувана ОС: ID=${os_id:-unknown}, ID_LIKE=${os_like:-unknown}." >&2
    return 1
  fi

  if [[ "$uid" == "0" ]]; then
    host_root_runner="bash -s"
  else
    if ! output="$(ssh "${ssh_opts[@]}" "$remote" 'sudo -n true' 2>&1)"; then
      echo "    Користувач не root і passwordless sudo недоступний: $output" >&2
      return 1
    fi
    host_root_runner="sudo -n bash -s"
  fi

  host_os_id="${os_id:-debian}"
  case "${machine_arch,,}" in
    x86_64|amd64) host_rid="linux-x64" ;;
    aarch64|arm64) host_rid="linux-arm64" ;;
    *) host_rid="unsupported:${machine_arch:-unknown}" ;;
  esac
}

read_remote_state() {
  local remote="$1"
  local output marker

  if ! output="$(ssh "${ssh_opts[@]}" "$remote" 'set -u
    version="absent"
    binary="absent"
    unit="absent"
    if [ -x /opt/winhub-linux-agent/WinHUBLinuxAgent ]; then
      binary="present"
      version="$(/opt/winhub-linux-agent/WinHUBLinuxAgent --version 2>/dev/null | tail -n1 || true)"
      [ -n "$version" ] || version="unknown"
    fi
    [ -f /etc/systemd/system/winhub-linux-agent.service ] && unit="present"
    printf "__WINHUB_STATE__%s|%s|%s\n" "$version" "$binary" "$unit"
  ' 2>&1)"; then
    echo "    Не вдалося визначити стан агента: $output" >&2
    return 1
  fi

  marker="$(printf '%s\n' "$output" | sed -n 's/^__WINHUB_STATE__//p' | tail -n1)"
  [[ -n "$marker" ]] || {
    echo "    Сервер не повернув стан агента." >&2
    return 1
  }

  IFS='|' read -r remote_version remote_binary remote_unit <<< "$marker"
}

create_remote_tmp() {
  local remote="$1"
  local output
  if ! output="$(ssh "${ssh_opts[@]}" "$remote" 'umask 077; mktemp -d /tmp/winhub-agent-deploy.XXXXXX' 2>&1)"; then
    echo "    Не вдалося створити тимчасовий каталог: $output" >&2
    return 1
  fi
  host_remote_tmp="$(printf '%s\n' "$output" | tail -n1 | tr -d '\r')"
  if [[ ! "$host_remote_tmp" =~ ^/tmp/winhub-agent-deploy\.[A-Za-z0-9]+$ ]]; then
    echo "    Отримано некоректний тимчасовий шлях: $host_remote_tmp" >&2
    return 1
  fi
}

upload_install_files() {
  local remote="$1"
  local remote_tmp="$2"
  local upload_package="$3"

  if [[ "$upload_package" -eq 1 ]]; then
    if ! scp "${scp_opts[@]}" "$package_path" "$remote:$remote_tmp/$package_name" >/dev/null; then
      echo "    Не вдалося скопіювати пакет агента." >&2
      return 1
    fi
  fi

  if [[ "$sync_config" -eq 1 ]]; then
    if ! scp "${scp_opts[@]}" "$runtime_config" "$remote:$remote_tmp/winhub_agent.conf" >/dev/null; then
      echo "    Не вдалося скопіювати runtime-конфіг." >&2
      return 1
    fi
    if ! scp "${scp_opts[@]}" "$bootstrap_config" "$remote:$remote_tmp/winhub_agent.bootstrap.conf" >/dev/null; then
      echo "    Не вдалося скопіювати bootstrap-конфіг." >&2
      return 1
    fi
  fi
}

run_remote_install() {
  local remote="$1"
  local root_runner="$2"
  local remote_tmp="$3"
  local operation="$4"
  local remote_command

  remote_command="$root_runner -- $remote_tmp $package_name $operation $purge $sync_config"
  ssh "${ssh_opts[@]}" "$remote" "$remote_command" <<'REMOTE_SCRIPT'
set -euo pipefail

deploy_tmp="$1"
package_name="$2"
operation="$3"
purge="$4"
sync_config="$5"
archive="$deploy_tmp/$package_name"
extract_dir="$deploy_tmp/extract"
service_name="winhub-linux-agent.service"

command -v tar >/dev/null
rm -rf "$extract_dir"
mkdir -p "$extract_dir"
tar -xzf "$archive" -C "$extract_dir"
test -x "$extract_dir/WinHUBLinuxAgent"
test -f "$extract_dir/install-linux-agent.sh"
test -f "$extract_dir/update-linux-agent.sh"
test -f "$extract_dir/winhub-linux-agent.service"

stage_configs() {
  if [[ "$sync_config" == "1" ]]; then
    install -d -o root -g root -m 0700 /etc/winhub-agent /var/lib/winhub-agent
    if [[ -s /etc/winhub-agent/winhub_agent.conf ]]; then
      "$extract_dir/WinHUBLinuxAgent" \
        --migrate-task-signing-state \
        /etc/winhub-agent/winhub_agent.conf \
        /var/lib/winhub-agent
    fi
    install -o root -g root -m 0600 "$deploy_tmp/winhub_agent.conf" /etc/winhub-agent/winhub_agent.conf
    if [[ ! -s /var/lib/winhub-agent/agent.token ]]; then
      install -o root -g root -m 0600 "$deploy_tmp/winhub_agent.bootstrap.conf" /etc/winhub-agent/winhub_agent.bootstrap.conf
    fi
  fi
}

case "$operation" in
  fresh)
    stage_configs
    cd "$extract_dir"
    bash ./install-linux-agent.sh
    ;;
  update)
    stage_configs
    bash "$extract_dir/update-linux-agent.sh" --package "$archive"
    ;;
  reinstall)
    systemctl disable --now "$service_name" 2>/dev/null || true
    rm -f "/etc/systemd/system/$service_name"
    systemctl daemon-reload
    rm -rf /opt/winhub-linux-agent
    if [[ "$purge" == "1" ]]; then
      rm -rf /etc/winhub-agent /var/lib/winhub-agent
    fi
    stage_configs
    cd "$extract_dir"
    bash ./install-linux-agent.sh
    ;;
  *)
    echo "Unknown remote install operation: $operation" >&2
    exit 2
    ;;
esac
REMOTE_SCRIPT
}

sync_remote_configs() {
  local remote="$1"
  local root_runner="$2"
  local remote_tmp="$3"
  local remote_command

  remote_command="$root_runner -- $remote_tmp"
  ssh "${ssh_opts[@]}" "$remote" "$remote_command" <<'REMOTE_SCRIPT'
set -euo pipefail

deploy_tmp="$1"
install -d -o root -g root -m 0700 /etc/winhub-agent /var/lib/winhub-agent
if [[ -s /etc/winhub-agent/winhub_agent.conf \
      && ! -s /var/lib/winhub-agent/task-signing-state.json ]] \
   && grep -Eq '"TaskSigningPublicKeyPem"[[:space:]]*:[[:space:]]*"[^"[:space:]]+' /etc/winhub-agent/winhub_agent.conf; then
  echo "Pinned task signing state exists only in the current config. Re-run with --force or reinstall so the new package can migrate it safely." >&2
  exit 42
fi
install -o root -g root -m 0600 "$deploy_tmp/winhub_agent.conf" /etc/winhub-agent/winhub_agent.conf
if [[ ! -s /var/lib/winhub-agent/agent.token ]]; then
  install -o root -g root -m 0600 "$deploy_tmp/winhub_agent.bootstrap.conf" /etc/winhub-agent/winhub_agent.bootstrap.conf
fi
systemctl restart winhub-linux-agent.service
REMOTE_SCRIPT
}

verify_remote_install() {
  local remote="$1"
  local output marker

  if ! output="$(ssh "${ssh_opts[@]}" "$remote" 'set -eu
    systemctl is-active --quiet winhub-linux-agent.service
    test -x /opt/winhub-linux-agent/WinHUBLinuxAgent
    version="$(/opt/winhub-linux-agent/WinHUBLinuxAgent --version)"
    printf "__WINHUB_VERIFIED__%s\n" "$version"
  ' 2>&1)"; then
    echo "    Перевірка служби не пройдена: $output" >&2
    return 1
  fi

  marker="$(printf '%s\n' "$output" | sed -n 's/^__WINHUB_VERIFIED__//p' | tail -n1)"
  [[ -n "$marker" ]] || {
    echo "    Не вдалося прочитати встановлену версію." >&2
    return 1
  }
  verified_version="$marker"
}

uninstall_remote_agent() {
  local remote="$1"
  local root_runner="$2"
  local remote_command

  remote_command="$root_runner -- $purge"
  ssh "${ssh_opts[@]}" "$remote" "$remote_command" <<'REMOTE_SCRIPT'
set -euo pipefail

purge="$1"
service_name="winhub-linux-agent.service"

systemctl disable --now "$service_name" 2>/dev/null || true
rm -f "/etc/systemd/system/$service_name"
systemctl daemon-reload
systemctl reset-failed "$service_name" 2>/dev/null || true
rm -rf /opt/winhub-linux-agent

if [[ "$purge" == "1" ]]; then
  rm -rf /etc/winhub-agent /var/lib/winhub-agent
fi

if systemctl is-active --quiet "$service_name"; then
  echo "Служба все ще активна." >&2
  exit 1
fi
test ! -e /opt/winhub-linux-agent/WinHUBLinuxAgent
REMOTE_SCRIPT
}

process_host() {
  local host_line="$1"
  local remote root_runner remote_tmp=""
  local install_needed=0 install_operation="update"

  remote="$(remote_for_host "$host_line")"
  echo "==> $remote"

  if ! preflight_host "$remote"; then
    return 1
  fi
  root_runner="$host_root_runner"
  echo "    ОС: $host_os_id; архітектура: $host_rid; привілеї: $([[ "$root_runner" == "bash -s" ]] && echo root || echo sudo)"

  if [[ "$action" == "uninstall" ]]; then
    if ! uninstall_remote_agent "$remote" "$root_runner"; then
      echo "    Видалення не завершено." >&2
      return 1
    fi
    if [[ "$purge" -eq 1 ]]; then
      echo "    Агент, конфіг і runtime-дані видалені."
    else
      echo "    Агент видалений; конфіг і runtime-дані збережені."
    fi
    return 0
  fi

  if [[ "$host_rid" != "$target_rid" ]]; then
    echo "    Пакет $target_rid не підходить для архітектури сервера $host_rid." >&2
    return 1
  fi

  if ! read_remote_state "$remote"; then
    return 1
  fi
  echo "    Поточна версія: $remote_version; цільова: $target_version; unit: $remote_unit"

  if [[ "$action" == "reinstall" ]]; then
    install_needed=1
    install_operation="reinstall"
  elif [[ "$force_install" -eq 1 || "$remote_binary" == "absent" || "$remote_unit" == "absent" ]]; then
    install_needed=1
    if [[ "$remote_binary" == "absent" ]]; then
      install_operation="fresh"
    fi
  elif [[ "$remote_version" == "unknown" ]] || version_is_older "$remote_version" "$target_version"; then
    install_needed=1
  fi

  if ! create_remote_tmp "$remote"; then
    return 1
  fi
  remote_tmp="$host_remote_tmp"

  if ! upload_install_files "$remote" "$remote_tmp" "$install_needed"; then
    cleanup_remote_tmp "$remote" "$remote_tmp" "$root_runner"
    return 1
  fi

  if [[ "$install_needed" -eq 1 ]]; then
    if ! run_remote_install "$remote" "$root_runner" "$remote_tmp" "$install_operation"; then
      echo "    Встановлення не завершено." >&2
      cleanup_remote_tmp "$remote" "$remote_tmp" "$root_runner"
      return 1
    fi
    echo "    Файли агента встановлені ($install_operation)."
  else
    echo "    Заміна файлів не потрібна: версія поточна або новіша."
  fi

  if [[ "$sync_config" -eq 1 ]]; then
    if ! sync_remote_configs "$remote" "$root_runner" "$remote_tmp"; then
      echo "    Не вдалося синхронізувати конфіг або перезапустити службу." >&2
      cleanup_remote_tmp "$remote" "$remote_tmp" "$root_runner"
      return 1
    fi
    echo "    Конфіг синхронізовано."
  fi

  if ! verify_remote_install "$remote"; then
    cleanup_remote_tmp "$remote" "$remote_tmp" "$root_runner"
    return 1
  fi
  cleanup_remote_tmp "$remote" "$remote_tmp" "$root_runner"
  echo "    Готово: служба active, версія $verified_version."
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --action)
      need_value "$1" "${2:-}"
      action="$2"
      shift 2
      ;;
    --hosts)
      need_value "$1" "${2:-}"
      hosts_file="$2"
      shift 2
      ;;
    --package)
      need_value "$1" "${2:-}"
      package_path="$2"
      shift 2
      ;;
    --config)
      need_value "$1" "${2:-}"
      runtime_config="$2"
      shift 2
      ;;
    --bootstrap)
      need_value "$1" "${2:-}"
      bootstrap_config="$2"
      shift 2
      ;;
    --user)
      need_value "$1" "${2:-}"
      ssh_user="$2"
      shift 2
      ;;
    --port)
      need_value "$1" "${2:-}"
      ssh_port="$2"
      shift 2
      ;;
    --identity|-i)
      need_value "$1" "${2:-}"
      ssh_key="$2"
      shift 2
      ;;
    --force)
      force_install=1
      shift
      ;;
    --no-config-sync)
      sync_config=0
      shift
      ;;
    --purge)
      purge=1
      shift
      ;;
    --yes|-y)
      assume_yes=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Невідомий параметр: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$action" ]]; then
  [[ -t 0 ]] || die "У неінтерактивному режимі задайте --action."
  action="$(prompt_for_action)" || die "Не вдалося прочитати режим роботи."
else
  action="$(normalize_action "$action")" || die "Невідомий режим. Використайте install, uninstall або reinstall."
fi

if [[ -z "$hosts_file" ]]; then
  [[ -t 0 ]] || die "У неінтерактивному режимі задайте --hosts."
  default_hosts_file="$script_dir/linux_hosts.txt"
  read -r -p "Файл зі списком IP/хостів [$default_hosts_file]: " hosts_file
  hosts_file="${hosts_file:-$default_hosts_file}"
fi

[[ -f "$hosts_file" ]] || die "Файл хостів не знайдено: $hosts_file"
[[ "$ssh_port" =~ ^[0-9]+$ ]] || die "SSH-порт має бути числом."
port_number=$((10#$ssh_port))
(( port_number >= 1 && port_number <= 65535 )) || die "SSH-порт поза діапазоном 1-65535."
[[ -z "$ssh_key" || -f "$ssh_key" ]] || die "SSH-ключ не знайдено: $ssh_key"
[[ "$ssh_user" =~ ^[A-Za-z_][A-Za-z0-9._-]*$ ]] || die "Некоректний SSH-користувач: $ssh_user"
command -v ssh >/dev/null || die "Команду ssh не знайдено."

if [[ "$purge" -eq 1 && "$action" == "install" ]]; then
  die "--purge можна використовувати лише з uninstall або reinstall."
fi
if [[ "$purge" -eq 1 && "$action" == "reinstall" && "$sync_config" -eq 0 ]]; then
  die "reinstall --purge потребує конфігів; приберіть --no-config-sync."
fi

if [[ "$action" != "uninstall" ]]; then
  command -v scp >/dev/null || die "Команду scp не знайдено."
  command -v tar >/dev/null || die "Команду tar не знайдено."
  if [[ -z "$package_path" ]]; then
    package_path="$(find_latest_package)"
  fi
  [[ -n "$package_path" && -f "$package_path" ]] ||
    die "Пакет агента не знайдено. Створіть release або задайте --package."

  package_name="$(basename "$package_path")"
  if [[ "$package_name" =~ ^WinHUBLinuxAgent-v([0-9A-Za-z][0-9A-Za-z._+~-]*)-(linux-(x64|arm64))\.tar\.gz$ ]]; then
    target_version="${BASH_REMATCH[1]}"
    target_rid="${BASH_REMATCH[2]}"
  else
    die "Назва пакета має формат WinHUBLinuxAgent-vVERSION-linux-{x64,arm64}.tar.gz: $package_name"
  fi
  validate_package_archive "$package_path" || die "Пакет пошкоджений або має неправильну структуру: $package_path"

  if [[ "$sync_config" -eq 1 ]]; then
    [[ -f "$runtime_config" ]] || die "Runtime-конфіг не знайдено: $runtime_config"
    [[ -f "$bootstrap_config" ]] || die "Bootstrap-конфіг не знайдено: $bootstrap_config"
  fi
fi

mapfile -t raw_hosts < <(sed 's/[[:space:]]*#.*$//' "$hosts_file" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | awk 'NF')
[[ "${#raw_hosts[@]}" -gt 0 ]] || die "Файл хостів порожній."

declare -A seen_hosts=()
hosts=()
for host in "${raw_hosts[@]}"; do
  validate_host_entry "$host" || die "Некоректний IP/hostname у файлі хостів: $host"
  if [[ -z "${seen_hosts[$host]:-}" ]]; then
    hosts+=("$host")
    seen_hosts[$host]=1
  fi
done

ssh_opts=(-p "$ssh_port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=2)
scp_opts=(-P "$ssh_port" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10)
if [[ -n "$ssh_key" ]]; then
  ssh_opts+=(-i "$ssh_key")
  scp_opts+=(-i "$ssh_key")
fi

echo
echo "Режим: $action"
echo "Файл хостів: $hosts_file"
echo "Кількість унікальних хостів: ${#hosts[@]}"
if [[ "$action" != "uninstall" ]]; then
  echo "Пакет: $package_path"
  echo "Цільова версія/архітектура: $target_version / $target_rid"
fi
if [[ "$purge" -eq 1 ]]; then
  echo "УВАГА: --purge видалить конфіг, токен та локальну ідентичність агента."
fi
echo

if [[ "$assume_yes" -eq 0 && -t 0 ]]; then
  read -r -p "Продовжити для всіх указаних хостів? [y/N]: " confirmation
  case "${confirmation,,}" in
    y|yes|т|так) ;;
    *) echo "Скасовано."; exit 0 ;;
  esac
fi

failures=0
successes=0
failed_hosts=()
for host in "${hosts[@]}"; do
  if process_host "$host"; then
    successes=$((successes + 1))
  else
    failures=$((failures + 1))
    failed_hosts+=("$host")
    echo "    НЕВДАЧА: $host" >&2
  fi
  echo
done

echo "Підсумок: успішно=$successes, помилок=$failures, всього=${#hosts[@]}."
if [[ "$failures" -gt 0 ]]; then
  echo "Проблемні хости: ${failed_hosts[*]}" >&2
  exit 1
fi

echo "Операцію завершено успішно."
