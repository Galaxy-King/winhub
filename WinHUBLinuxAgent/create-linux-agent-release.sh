#!/usr/bin/env bash
set -euo pipefail

version="${1:-}"
rid="${2:-linux-x64}"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ || ! "$rid" =~ ^linux-(x64|arm64)$ ]]; then
  echo "Usage: ./create-linux-agent-release.sh VERSION [linux-x64|linux-arm64]" >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dist_dir="$script_dir/dist-agent"
package_name="WinHUBLinuxAgent-v${version}-${rid}.tar.gz"

mkdir -p "$dist_dir"
[[ ! -e "$dist_dir/$package_name" && ! -e "$dist_dir/${package_name}.manifest.json" ]] || { echo 'Release already exists.' >&2; exit 1; }
publish_dir="$(mktemp -d "$dist_dir/publish-XXXXXXXX")"

dotnet publish "$script_dir/WinHUBLinuxAgent.csproj" \
  -c Release \
  -r "$rid" \
  --self-contained true \
  -p:PublishAot=true \
  -p:Version="$version" \
  -o "$publish_dir"

rm -f "$publish_dir"/*.dbg "$publish_dir"/*.pdb
chmod 0755 "$publish_dir/WinHUBLinuxAgent" "$publish_dir"/*.sh

[[ ! -e "$dist_dir/$package_name" ]] || { echo 'Another build created this release; nothing was overwritten.' >&2; exit 1; }
tar -C "$publish_dir" -czf "$dist_dir/$package_name" .
sha256="$(sha256sum "$dist_dir/$package_name" | awk '{print toupper($1)}')"
cat > "$dist_dir/${package_name}.manifest.json" <<EOF
{
  "name": "WinHUBLinuxAgent",
  "version": "$version",
  "rid": "$rid",
  "package": "$package_name",
  "sha256": "$sha256",
  "release_signature": "NOT_SIGNED_USE_OFFLINE_PUBLISHER",
  "publish_directory": "$publish_dir"
}
EOF

echo "$dist_dir/$package_name"
echo "$sha256"
echo "Publish directory for offline signing: $publish_dir"
echo 'Build archive is unsigned. Strict agents require a package made by tools/sign-release.py.'
