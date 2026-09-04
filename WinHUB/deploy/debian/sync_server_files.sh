#!/usr/bin/env bash
# Shared by installation and updates. Source this file; it has no side effects.

winhub_server_source() {
  local candidate="$1"
  if [[ -f "${candidate}/WinHUB/server_debian.py" ]]; then
    candidate="${candidate}/WinHUB"
  fi
  [[ -f "${candidate}/server_debian.py" && -f "${candidate}/requirements.txt" &&
     -f "${candidate}/deploy/server-files.txt" && -f "${candidate}/deploy/server-excludes.txt" ]] || {
    printf '[WinHUB] Not a complete server source: %s\n' "${candidate}" >&2
    return 1
  }
  (cd "${candidate}" && pwd -P)
}

winhub_sync_server_files() {
  local source_dir target_dir
  source_dir="$(winhub_server_source "$1")" || return 1
  target_dir="$2"
  mkdir -p "${target_dir}"
  if [[ "${source_dir}" == "$(cd "${target_dir}" && pwd -P)" ]]; then
    return 0
  fi
  # --files-from limits the copy to server components. Excluded runtime data
  # and existing virtual environments are protected from --delete.
  rsync -a --recursive --delete \
    --files-from="${source_dir}/deploy/server-files.txt" \
    --exclude-from="${source_dir}/deploy/server-excludes.txt" \
    "${source_dir}/" "${target_dir}/"
}
