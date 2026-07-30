#!/bin/bash
set -euo pipefail

readonly source_dir="$(cd "$(dirname "$0")" && pwd -P)"
runtime_config="${source_dir}/winhub_agent.conf"
bootstrap_config="${source_dir}/winhub_agent.bootstrap.conf"
generated_config=0

cleanup() {
  if [[ ${generated_config} -eq 1 ]]; then
    /bin/rm -f "${runtime_config}" "${bootstrap_config}"
  fi
}
trap cleanup EXIT HUP INT TERM

if [[ -f "${runtime_config}" && -f "${bootstrap_config}" ]]; then
  echo "Using winhub_agent.conf and winhub_agent.bootstrap.conf next to the installer."
  if [[ ${WINHUB_ALLOW_UNSIGNED:-0} == "1" ]]; then
    /usr/bin/sudo /usr/bin/env WINHUB_ALLOW_UNSIGNED=1 "${source_dir}/install-macos-agent.sh"
  else
    /usr/bin/sudo "${source_dir}/install-macos-agent.sh"
  fi
  exit 0
fi

if [[ -f "${runtime_config}" || -f "${bootstrap_config}" ]]; then
  echo "Both winhub_agent.conf and winhub_agent.bootstrap.conf must be present next to the installer." >&2
  exit 1
fi

generated_config=1
printf 'WinHUB HTTPS server URL: '
IFS= read -r server_url
case "${server_url}" in
  https://*) ;;
  *) echo "The server URL must start with https://." >&2; exit 1 ;;
esac

printf 'Enrollment key: '
IFS= read -r -s enrollment_key
printf '\nTask HMAC secret: '
IFS= read -r -s task_secret
printf '\n'
[[ -n "${enrollment_key}" && -n "${task_secret}" ]] || { echo "Both secrets are required." >&2; exit 1; }

/usr/bin/plutil -create xml1 "${runtime_config}"
/usr/bin/plutil -insert ServerUrl -string "${server_url%/}" "${runtime_config}"
/usr/bin/plutil -insert PollIntervalSeconds -integer 30 "${runtime_config}"
/usr/bin/plutil -insert PollJitterSeconds -integer 30 "${runtime_config}"
/usr/bin/plutil -insert StartupSpreadSeconds -integer 120 "${runtime_config}"
/usr/bin/plutil -insert DefaultTaskTimeoutSeconds -integer 1800 "${runtime_config}"
/usr/bin/plutil -insert MaxResultLogBytes -integer 262144 "${runtime_config}"
/usr/bin/plutil -insert IgnoreTlsCertificateErrors -bool false "${runtime_config}"
/usr/bin/plutil -insert ServerCertificateSha256 -string "" "${runtime_config}"
/usr/bin/plutil -insert RequireTaskSignature -bool true "${runtime_config}"
/usr/bin/plutil -insert ExecutionMode -string "allowlist" "${runtime_config}"
/usr/bin/plutil -insert AllowedActions -json '["agent_update"]' "${runtime_config}"
/usr/bin/plutil -insert AllowCrossHostUpdateDownloads -bool false "${runtime_config}"
/usr/bin/plutil -convert json "${runtime_config}"

/usr/bin/plutil -create xml1 "${bootstrap_config}"
/usr/bin/plutil -insert GlobalApiKey -string "${enrollment_key}" "${bootstrap_config}"
/usr/bin/plutil -insert TaskHmacSecret -string "${task_secret}" "${bootstrap_config}"
/usr/bin/plutil -convert json "${bootstrap_config}"
/bin/chmod 0600 "${runtime_config}" "${bootstrap_config}"

unset enrollment_key task_secret
if [[ ${WINHUB_ALLOW_UNSIGNED:-0} == "1" ]]; then
  /usr/bin/sudo /usr/bin/env WINHUB_ALLOW_UNSIGNED=1 "${source_dir}/install-macos-agent.sh"
else
  /usr/bin/sudo "${source_dir}/install-macos-agent.sh"
fi
