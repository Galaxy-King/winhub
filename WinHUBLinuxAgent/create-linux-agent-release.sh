#!/usr/bin/env bash
set -euo pipefail

version="${1:-}"
rid="${2:-linux-x64}"

if [[ -z "$version" ]]; then
  echo "Usage: ./create-linux-agent-release.sh VERSION [linux-x64|linux-arm64]" >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
publish_dir="$script_dir/dist-agent/publish"
dist_dir="$script_dir/dist-agent"
package_name="WinHUBLinuxAgent-v${version}-${rid}.tar.gz"

rm -rf "$publish_dir"
mkdir -p "$publish_dir" "$dist_dir"

dotnet publish "$script_dir/WinHUBLinuxAgent.csproj" \
  -c Release \
  -r "$rid" \
  --self-contained true \
  -p:PublishAot=true \
  -p:Version="$version" \
  -o "$publish_dir"

rm -f "$publish_dir"/*.dbg "$publish_dir"/*.pdb
chmod 0755 "$publish_dir/WinHUBLinuxAgent" "$publish_dir"/*.sh

tar -C "$publish_dir" -czf "$dist_dir/$package_name" .
sha256="$(sha256sum "$dist_dir/$package_name" | awk '{print toupper($1)}')"
cat > "$dist_dir/${package_name}.manifest.json" <<EOF
{
  "name": "WinHUBLinuxAgent",
  "version": "$version",
  "rid": "$rid",
  "package": "$package_name",
  "sha256": "$sha256"
}
EOF

echo "$dist_dir/$package_name"
echo "$sha256"
