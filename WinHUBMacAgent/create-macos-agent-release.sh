#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

readonly script_dir="$(cd "$(dirname "$0")" && pwd -P)"
readonly project_file="${script_dir}/WinHUBMacAgent.csproj"
readonly version_file="${script_dir}/../VERSION"
readonly runtime_id="osx-arm64"
version="${1:-$(tr -d '[:space:]' < "${version_file}")}"
identity="${WINHUB_CODESIGN_IDENTITY:-}"
readonly publish_dir="${script_dir}/bin/Release/net8.0/${runtime_id}/publish"
readonly dist_dir="${script_dir}/dist-agent"
readonly package_dir="${dist_dir}/package-${version}-macos-arm64"
readonly archive_name="WinHUBMacAgent-v${version}-macos-arm64.tar.gz"
readonly archive="${dist_dir}/${archive_name}"

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
require_command() { command -v "$1" >/dev/null 2>&1 || die "Required command is missing: $1"; }

[[ $(uname -s) == "Darwin" ]] || die "Native macOS release builds must run on a Mac."
[[ $(uname -m) == "arm64" ]] || die "This release target requires an Apple Silicon Mac (arm64)."
macos_major="$(/usr/bin/sw_vers -productVersion | /usr/bin/cut -d. -f1)"
[[ "${macos_major}" =~ ^[0-9]+$ && "${macos_major}" -ge 14 ]] \
  || die "A .NET 8-supported macOS release (14 or newer) is required."
[[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]] || die "Invalid release version: ${version}"
[[ -f "${project_file}" && -f "${script_dir}/../WinHUBLinuxAgent/Worker.cs" ]] \
  || die "Sparse checkout must include WinHUBMacAgent, WinHUBLinuxAgent/Worker.cs and VERSION."

require_command dotnet
require_command git
require_command xcode-select
require_command xcrun
require_command codesign
require_command security
require_command file
require_command tar
require_command shasum

dotnet --list-sdks | /usr/bin/grep -Eq '^8\.' || die ".NET 8 SDK (Arm64) is required."
selected_sdk="$(cd "${script_dir}" && dotnet --version)"
[[ "${selected_sdk}" == 8.* ]] || die "global.json must select the .NET 8 SDK; selected ${selected_sdk}."
xcode-select -p >/dev/null 2>&1 || die "Xcode Command Line Tools are not selected."
xcrun --find clang >/dev/null 2>&1 || die "The Xcode clang toolchain is unavailable."

if [[ -z "${identity}" && ${WINHUB_ALLOW_UNSIGNED_BUILD:-0} != "1" ]]; then
  die "Set WINHUB_CODESIGN_IDENTITY to a Developer ID Application identity. For a local-only build, explicitly set WINHUB_ALLOW_UNSIGNED_BUILD=1."
fi

/bin/rm -rf "${publish_dir}" "${package_dir}"
/bin/mkdir -p "${publish_dir}" "${package_dir}"

dotnet publish "${project_file}" -c Release -r "${runtime_id}" \
  -p:PublishAot=true -p:Version="${version}" -p:InformationalVersion="${version}" \
  --self-contained true -o "${publish_dir}"

[[ -f "${publish_dir}/WinHUBMacAgent" ]] || die "Publish did not produce WinHUBMacAgent."
/usr/bin/file "${publish_dir}/WinHUBMacAgent" | /usr/bin/grep -q 'arm64' \
  || die "Published executable does not contain the arm64 architecture."

sign_macho_files() {
  local signing_identity="$1"
  local item
  while IFS= read -r -d '' item; do
    [[ "${item}" == "${publish_dir}/WinHUBMacAgent" ]] && continue
    if /usr/bin/file "${item}" | /usr/bin/grep -q 'Mach-O'; then
      /usr/bin/codesign --force --options runtime --timestamp --sign "${signing_identity}" "${item}"
    fi
  done < <(/usr/bin/find "${publish_dir}" -maxdepth 1 -type f -print0)
  /usr/bin/codesign --force --options runtime --timestamp --sign "${signing_identity}" "${publish_dir}/WinHUBMacAgent"
}

adhoc_sign_macho_files() {
  local item
  while IFS= read -r -d '' item; do
    if /usr/bin/file "${item}" | /usr/bin/grep -q 'Mach-O'; then
      /usr/bin/codesign --force --sign - "${item}"
    fi
  done < <(/usr/bin/find "${publish_dir}" -maxdepth 1 -type f -print0)
}

team_id=""
if [[ -n "${identity}" ]]; then
  /usr/bin/security find-identity -v -p codesigning | /usr/bin/grep -F "${identity}" >/dev/null \
    || die "Code-signing identity was not found in the unlocked keychain: ${identity}"
  sign_macho_files "${identity}"
  signature_details="$(/usr/bin/codesign -dvvv "${publish_dir}/WinHUBMacAgent" 2>&1)"
  printf '%s\n' "${signature_details}" | /usr/bin/grep -q '^Authority=Developer ID Application:' \
    || die "Production releases must use a Developer ID Application certificate."
  team_id="$(printf '%s\n' "${signature_details}" | /usr/bin/awk -F= '/^TeamIdentifier=/{print $2; exit}')"
  [[ -n "${team_id}" && "${team_id}" != "not set" ]] || die "Signed executable has no Apple TeamIdentifier."
else
  printf 'WARNING: creating an ad-hoc signed development build; do not upload it to production WinHUB.\n' >&2
  adhoc_sign_macho_files
fi

while IFS= read -r -d '' item; do
  if /usr/bin/file "${item}" | /usr/bin/grep -q 'Mach-O'; then
    /usr/bin/codesign --verify --strict --verbose=2 "${item}"
  fi
done < <(/usr/bin/find "${publish_dir}" -maxdepth 1 -type f -print0)

actual_version="$("${publish_dir}/WinHUBMacAgent" --version)"
[[ "${actual_version}" == "${version}" ]] || die "Embedded version is ${actual_version}, expected ${version}."
"${publish_dir}/WinHUBMacAgent" --self-test

while IFS= read -r -d '' item; do
  name="${item##*/}"
  case "${name}" in
    WinHUBMacAgent|*.dylib|*.sh|*.json|*.plist|*.conf.example|*.md)
      /bin/cp -p "${item}" "${package_dir}/${name}"
      ;;
  esac
done < <(/usr/bin/find "${publish_dir}" -maxdepth 1 -type f -print0)

[[ -f "${package_dir}/WinHUBMacAgent" ]] || die "Package staging failed."
[[ -f "${package_dir}/com.winhub.agent.plist" ]] || die "LaunchDaemon plist is missing from the package."
/usr/bin/plutil -lint "${package_dir}/com.winhub.agent.plist" >/dev/null

/bin/mkdir -p "${dist_dir}"
COPYFILE_DISABLE=1 /usr/bin/tar -C "${package_dir}" -czf "${archive}" .
(
  cd "${dist_dir}"
  /usr/bin/shasum -a 256 "${archive_name}" > "${archive_name}.sha256"
)
/bin/rm -rf "${package_dir}"

printf '%s\n' \
  "Release archive: ${archive}" \
  "SHA-256 file: ${archive}.sha256" \
  "Version: ${version}" \
  "Apple Team ID: ${team_id:-development-ad-hoc}"
