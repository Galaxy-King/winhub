#!/bin/bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd -P)"
version="${1:-$(tr -d '[:space:]' < "${script_dir}/../VERSION")}"
identity="${WINHUB_CODESIGN_IDENTITY:-}"
publish_dir="${script_dir}/bin/Release/net8.0/osx-arm64/publish"
archive="${script_dir}/WinHUBMacAgent-v${version}-macos-arm64.tar.gz"

dotnet publish "${script_dir}/WinHUBMacAgent.csproj" -c Release -r osx-arm64 \
  -p:Version="${version}" -p:InformationalVersion="${version}" --self-contained true

if [[ -n "${identity}" ]]; then
  /usr/bin/codesign --force --options runtime --timestamp --sign "${identity}" "${publish_dir}/WinHUBMacAgent"
  /usr/bin/codesign --verify --deep --strict --verbose=2 "${publish_dir}/WinHUBMacAgent"
else
  echo "WARNING: WINHUB_CODESIGN_IDENTITY is empty; output is for development only." >&2
fi

/usr/bin/tar -C "${publish_dir}" -czf "${archive}" .
/usr/bin/shasum -a 256 "${archive}" > "${archive}.sha256"
echo "${archive}"
