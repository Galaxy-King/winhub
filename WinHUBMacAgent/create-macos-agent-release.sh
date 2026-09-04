#!/bin/bash
set -euo pipefail
IFS=$'\n\t'

readonly script_dir="$(cd "$(dirname "$0")" && pwd -P)"
readonly repository_dir="$(cd "${script_dir}/.." && pwd -P)"
readonly project_file="${script_dir}/WinHUBMacAgent.csproj"
readonly version_file="${repository_dir}/WinHUB/VERSION"
readonly runtime_id="osx-arm64"
readonly label="com.winhub.agent"
version="${1:-$(tr -d '[:space:]' < "${version_file}")}"
application_identity="${WINHUB_CODESIGN_IDENTITY:-}"
installer_identity="${WINHUB_INSTALLER_IDENTITY:-}"
notary_profile="${WINHUB_NOTARY_PROFILE:-}"
allow_unsigned="${WINHUB_ALLOW_UNSIGNED_BUILD:-0}"
update_only="${WINHUB_UPDATE_ONLY:-0}"
skip_notarization="${WINHUB_SKIP_NOTARIZATION:-0}"

readonly publish_dir="${script_dir}/bin/Release/net10.0/${runtime_id}/publish"
readonly dist_dir="${script_dir}/dist-agent"
readonly update_stage="${dist_dir}/package-${version}-macos-arm64"
readonly archive_name="WinHUBMacAgent-v${version}-macos-arm64.tar.gz"
readonly archive="${dist_dir}/${archive_name}"
readonly pkg_root="${dist_dir}/pkg-root-${version}"
readonly pkg_scripts="${script_dir}/pkg-scripts"
readonly pkg_name="WinHUBMacAgent-v${version}-macos-arm64.pkg"
readonly installer_pkg="${dist_dir}/${pkg_name}"
readonly installer_bundle_name="WinHUBMacAgent-v${version}-macos-arm64-installer"
readonly installer_bundle_dir="${dist_dir}/${installer_bundle_name}"
readonly installer_zip="${dist_dir}/${installer_bundle_name}.zip"

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }
require_command() { command -v "$1" >/dev/null 2>&1 || die "Required command is missing: $1"; }

[[ "$(uname -s)" == "Darwin" ]] || die "Native macOS release builds must run on a Mac."
[[ "$(uname -m)" == "arm64" ]] || die "This release target requires an Apple Silicon Mac (arm64)."
macos_major="$(/usr/bin/sw_vers -productVersion | /usr/bin/cut -d. -f1)"
[[ "${macos_major}" =~ ^[0-9]+$ && "${macos_major}" -ge 14 ]] \
  || die "macOS 14 or newer is required."
[[ "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]] || die "Invalid release version: ${version}"
[[ -f "${project_file}" && -f "${repository_dir}/WinHUBLinuxAgent/Worker.cs" ]] \
  || die "Sparse checkout must include WinHUBMacAgent, WinHUBLinuxAgent/Worker.cs and WinHUB/VERSION."
[[ -f "${pkg_scripts}/preinstall" && -f "${pkg_scripts}/postinstall" ]] \
  || die "macOS package scripts are missing."

for command in dotnet git xcode-select xcrun codesign security file tar shasum plutil; do
  require_command "${command}"
done
dotnet --list-sdks | /usr/bin/grep -Eq '^10\.' || die ".NET 10 SDK (Arm64) is required."
selected_sdk="$(cd "${script_dir}" && dotnet --version)"
[[ "${selected_sdk}" == 10.* ]] || die "WinHUBMacAgent/global.json must select .NET 10; selected ${selected_sdk}."
xcode-select -p >/dev/null 2>&1 || die "Xcode Command Line Tools are not selected."
xcrun --find clang >/dev/null 2>&1 || die "The Xcode clang toolchain is unavailable."

if [[ ${WINHUB_ALLOW_DIRTY_BUILD:-0} != "1" ]]; then
  dirty_files="$(git -C "${repository_dir}" status --porcelain)"
  [[ -z "${dirty_files}" ]] || die "Production builds require a clean Git worktree. Commit the changes or explicitly use WINHUB_ALLOW_DIRTY_BUILD=1 for a non-release test."
fi

for source_script in "${script_dir}"/*.sh "${pkg_scripts}"/*; do
  /bin/bash -n "${source_script}" || die "Shell syntax check failed: ${source_script}"
done

if [[ "${allow_unsigned}" != "1" ]]; then
  [[ -n "${application_identity}" ]] \
    || die "Set WINHUB_CODESIGN_IDENTITY to Developer ID Application."
  /usr/bin/security find-identity -v | /usr/bin/grep -F "${application_identity}" >/dev/null \
    || die "Application signing identity was not found in the unlocked keychain: ${application_identity}"
  if [[ "${update_only}" != "1" ]]; then
    require_command pkgbuild
    require_command ditto
    [[ -n "${installer_identity}" ]] \
      || die "Set WINHUB_INSTALLER_IDENTITY to Developer ID Installer."
    /usr/bin/security find-identity -v | /usr/bin/grep -F "${installer_identity}" >/dev/null \
      || die "Installer signing identity was not found in the unlocked keychain: ${installer_identity}"
    if [[ "${skip_notarization}" != "1" ]]; then
      [[ -n "${notary_profile}" ]] \
        || die "Set WINHUB_NOTARY_PROFILE to a notarytool Keychain profile."
      xcrun notarytool history --keychain-profile "${notary_profile}" >/dev/null \
        || die "notarytool could not use Keychain profile ${notary_profile}."
    fi
  fi
fi

/bin/rm -rf "${publish_dir}" "${update_stage}" "${pkg_root}" "${installer_bundle_dir}"
/bin/rm -f "${archive}" "${archive}.sha256" "${installer_pkg}" "${installer_pkg}.sha256" "${installer_zip}" "${installer_zip}.sha256"
/bin/mkdir -p "${publish_dir}" "${update_stage}" "${dist_dir}"

(
  cd "${script_dir}"
  dotnet publish "${project_file}" -c Release -r "${runtime_id}" \
    -p:PublishAot=true -p:Version="${version}" -p:InformationalVersion="${version}" \
    --self-contained true -o "${publish_dir}"
)

[[ -f "${publish_dir}/WinHUBMacAgent" ]] || die "Publish did not produce WinHUBMacAgent."
/usr/bin/file "${publish_dir}/WinHUBMacAgent" | /usr/bin/grep -q 'arm64' \
  || die "Published executable does not contain arm64 code."

sign_macho_files() {
  local item
  local name
  local safe_name
  while IFS= read -r -d '' item; do
    [[ "${item}" == "${publish_dir}/WinHUBMacAgent" ]] && continue
    if /usr/bin/file "${item}" | /usr/bin/grep -q 'Mach-O'; then
      name="${item##*/}"
      safe_name="$(printf '%s' "${name}" | /usr/bin/tr -cs 'A-Za-z0-9.-' '-')"
      /usr/bin/codesign --force --options runtime --timestamp \
        --identifier "${label}.${safe_name}" --sign "${application_identity}" "${item}"
    fi
  done < <(/usr/bin/find "${publish_dir}" -maxdepth 1 -type f -print0)
  /usr/bin/codesign --force --options runtime --timestamp \
    --identifier "${label}" --sign "${application_identity}" "${publish_dir}/WinHUBMacAgent"
}

adhoc_sign_macho_files() {
  local item
  while IFS= read -r -d '' item; do
    if /usr/bin/file "${item}" | /usr/bin/grep -q 'Mach-O'; then
      /usr/bin/codesign --force --options runtime --identifier "${label}.development" --sign - "${item}"
    fi
  done < <(/usr/bin/find "${publish_dir}" -maxdepth 1 -type f -print0)
  /usr/bin/codesign --force --options runtime --identifier "${label}" --sign - "${publish_dir}/WinHUBMacAgent"
}

team_id=""
if [[ "${allow_unsigned}" != "1" ]]; then
  sign_macho_files
  signature_details="$(/usr/bin/codesign -dvvv "${publish_dir}/WinHUBMacAgent" 2>&1)"
  printf '%s\n' "${signature_details}" | /usr/bin/grep -q '^Authority=Developer ID Application:' \
    || die "Production binaries must use Developer ID Application."
  printf '%s\n' "${signature_details}" | /usr/bin/grep -Eq '^CodeDirectory .*flags=.*\(.*runtime.*\)' \
    || die "Hardened Runtime was not enabled."
  [[ "$(printf '%s\n' "${signature_details}" | /usr/bin/awk -F= '/^Identifier=/{print $2; exit}')" == "${label}" ]] \
    || die "The main code-signing identifier must be ${label}."
  team_id="$(printf '%s\n' "${signature_details}" | /usr/bin/awk -F= '/^TeamIdentifier=/{print $2; exit}')"
  [[ -n "${team_id}" && "${team_id}" != "not set" ]] || die "Signed executable has no Apple TeamIdentifier."
else
  printf 'WARNING: creating an ad-hoc development build; do not upload it to production WinHUB.\n' >&2
  adhoc_sign_macho_files
fi

while IFS= read -r -d '' item; do
  if /usr/bin/file "${item}" | /usr/bin/grep -q 'Mach-O'; then
    /usr/bin/codesign --verify --strict --all-architectures --verbose=2 "${item}"
  fi
done < <(/usr/bin/find "${publish_dir}" -maxdepth 1 -type f -print0)

actual_version="$("${publish_dir}/WinHUBMacAgent" --version)"
[[ "${actual_version}" == "${version}" ]] || die "Embedded version is ${actual_version}, expected ${version}."
"${publish_dir}/WinHUBMacAgent" --self-test

while IFS= read -r -d '' item; do
  name="${item##*/}"
  case "${name}" in
    WinHUBMacAgent|*.dylib|*.sh|*.json|*.plist|*.conf.example|*.newsyslog.conf|*.md)
      /bin/cp -p "${item}" "${update_stage}/${name}"
      ;;
  esac
done < <(/usr/bin/find "${publish_dir}" -maxdepth 1 -type f -print0)

[[ -f "${update_stage}/WinHUBMacAgent" ]] || die "Update package staging failed."
/bin/mkdir -p "${update_stage}/docs"
/bin/cp -p "${script_dir}/docs/BUILD_MAC_M4_UA.md" "${update_stage}/docs/BUILD_MAC_M4_UA.md"
[[ -f "${update_stage}/${label}.plist" ]] || die "LaunchDaemon plist is missing from the update package."
[[ -f "${update_stage}/${label}.newsyslog.conf" ]] || die "newsyslog policy is missing from the update package."
/usr/bin/plutil -lint "${update_stage}/${label}.plist" >/dev/null
/bin/chmod 0755 "${update_stage}/WinHUBMacAgent" "${update_stage}"/*.sh

COPYFILE_DISABLE=1 /usr/bin/tar -C "${update_stage}" -czf "${archive}" .
(
  cd "${dist_dir}"
  /usr/bin/shasum -a 256 "${archive_name}" > "${archive_name}.sha256"
)

if [[ "${allow_unsigned}" != "1" && "${update_only}" != "1" ]]; then
  install_payload="${pkg_root}${install_dir}"
  /bin/mkdir -p "${install_payload}" "${pkg_root}/Library/LaunchDaemons" "${pkg_root}/etc/newsyslog.d"
  while IFS= read -r -d '' item; do
    name="${item##*/}"
    case "${name}" in
      "${label}.plist"|"${label}.newsyslog.conf") ;;
      *) /bin/cp -p "${item}" "${install_payload}/${name}" ;;
    esac
  done < <(/usr/bin/find "${update_stage}" -maxdepth 1 -type f -print0)
  /bin/cp -p "${update_stage}/${label}.plist" "${pkg_root}/Library/LaunchDaemons/${label}.plist"
  /bin/cp -p "${update_stage}/${label}.newsyslog.conf" "${pkg_root}/etc/newsyslog.d/${label}.conf"
  /usr/bin/touch "${install_payload}/release-files.manifest"
  /usr/bin/find "${install_payload}" -maxdepth 1 -type f -exec /usr/bin/basename {} \; \
    | LC_ALL=C /usr/bin/sort > "${install_payload}/release-files.manifest"
  /bin/chmod 0755 "${install_payload}/WinHUBMacAgent" "${install_payload}"/*.sh
  /bin/chmod 0644 "${pkg_root}/Library/LaunchDaemons/${label}.plist" "${pkg_root}/etc/newsyslog.d/${label}.conf"
  /bin/chmod 0755 "${pkg_scripts}/preinstall" "${pkg_scripts}/postinstall"

  /usr/bin/pkgbuild --root "${pkg_root}" --scripts "${pkg_scripts}" \
    --identifier "${label}" --version "${version}" --install-location / \
    --ownership recommended --sign "${installer_identity}" "${installer_pkg}"

  package_signature="$(/usr/sbin/pkgutil --check-signature "${installer_pkg}" 2>&1)"
  printf '%s\n' "${package_signature}" | /usr/bin/grep -q 'Developer ID Installer:' \
    || die "The installer package does not have a Developer ID Installer signature."
  printf '%s\n' "${package_signature}" | /usr/bin/grep -F "(${team_id})" >/dev/null \
    || die "Application and installer certificates belong to different Apple teams."

  if [[ "${skip_notarization}" != "1" ]]; then
    notarization_output="$(xcrun notarytool submit "${installer_pkg}" --keychain-profile "${notary_profile}" --wait)"
    printf '%s\n' "${notarization_output}"
    printf '%s\n' "${notarization_output}" | /usr/bin/grep -Eq 'status:[[:space:]]*Accepted' \
      || die "Apple notarization did not return Accepted."
    xcrun stapler staple "${installer_pkg}"
    xcrun stapler validate "${installer_pkg}"
    /usr/sbin/spctl --assess --type install --verbose=2 "${installer_pkg}"
  else
    printf 'WARNING: installer notarization was explicitly skipped. This package is not a production distribution artifact.\n' >&2
  fi

  (
    cd "${dist_dir}"
    /usr/bin/shasum -a 256 "${pkg_name}" > "${pkg_name}.sha256"
  )

  /bin/mkdir -p "${installer_bundle_dir}"
  /bin/cp -p "${installer_pkg}" "${installer_bundle_dir}/${pkg_name}"
  /bin/cp -p "${script_dir}/setup-macos-agent.sh" "${installer_bundle_dir}/setup-macos-agent.sh"
  /bin/cp -p "${script_dir}/winhub_agent.conf.example" "${installer_bundle_dir}/winhub_agent.conf.example"
  /bin/cp -p "${script_dir}/winhub_agent.bootstrap.conf.example" "${installer_bundle_dir}/winhub_agent.bootstrap.conf.example"
  /bin/cp -p "${script_dir}/README.md" "${installer_bundle_dir}/README.md"
  /bin/mkdir -p "${installer_bundle_dir}/docs"
  /bin/cp -p "${script_dir}/docs/BUILD_MAC_M4_UA.md" "${installer_bundle_dir}/docs/BUILD_MAC_M4_UA.md"
  /bin/chmod 0755 "${installer_bundle_dir}/setup-macos-agent.sh"
  /usr/bin/ditto -c -k --sequesterRsrc --keepParent "${installer_bundle_dir}" "${installer_zip}"
  (
    cd "${dist_dir}"
    /usr/bin/shasum -a 256 "${installer_bundle_name}.zip" > "${installer_bundle_name}.zip.sha256"
  )
fi

/bin/rm -rf "${update_stage}" "${pkg_root}" "${installer_bundle_dir}"

printf '%s\n' \
  "Managed-update archive: ${archive}" \
  "Managed-update SHA-256: ${archive}.sha256" \
  "Version: ${version}" \
  "Apple Team ID: ${team_id:-development-ad-hoc}"
if [[ -f "${installer_pkg}" ]]; then
  printf '%s\n' \
    "Installer package: ${installer_pkg}" \
    "Installer SHA-256: ${installer_pkg}.sha256" \
    "Installer bundle: ${installer_zip}" \
    "Installer bundle SHA-256: ${installer_zip}.sha256"
fi
