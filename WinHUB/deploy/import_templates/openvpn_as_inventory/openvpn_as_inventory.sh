#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C.UTF-8
umask 077

scripts_dir="/usr/local/openvpn_as/scripts"
sacli="$scripts_dir/sacli"
logdba="$scripts_dir/logdba"

fail_json() {
  python3 -c 'import json,sys; print(json.dumps({"winhub_report_type":"openvpn_as_inventory","error":sys.argv[1]}, separators=(",", ":")))' "$1"
  exit 1
}

[[ -x "$sacli" ]] || fail_json "OpenVPN Access Server sacli was not found"
command -v python3 >/dev/null 2>&1 || fail_json "python3 is required"

work_dir="$(mktemp -d /tmp/winhub-openvpnas-inventory.XXXXXX)"
trap 'rm -rf "$work_dir"' EXIT

systemctl is-active openvpnas >"$work_dir/service_state.txt" 2>/dev/null || true
systemctl show openvpnas -p ActiveEnterTimestamp --value >"$work_dir/service_started.txt" 2>/dev/null || true
"$sacli" status >"$work_dir/status.json" 2>/dev/null || printf '{}\n' >"$work_dir/status.json"
"$sacli" ConfigQuery >"$work_dir/config.json" 2>/dev/null || printf '{}\n' >"$work_dir/config.json"
"$sacli" UserPropGet >"$work_dir/users.json" 2>/dev/null || printf '{}\n' >"$work_dir/users.json"
"$sacli" VPNSummary >"$work_dir/vpn_summary.json" 2>/dev/null || printf '{}\n' >"$work_dir/vpn_summary.json"

if [[ -x "$logdba" ]]; then
  timeout 45 "$logdba" --json --service_filt=VPN --start_time_ge=-365d \
    --start_time_outfmt=unix --columns="username,start_time,error,service" \
    >"$work_dir/logs.json" 2>"$work_dir/logs_error.txt" || printf '[]\n' >"$work_dir/logs.json"
else
  printf '[]\n' >"$work_dir/logs.json"
fi

ip -j address show >"$work_dir/network.json" 2>/dev/null || printf '[]\n' >"$work_dir/network.json"
ip -j route show default >"$work_dir/routes.json" 2>/dev/null || printf '[]\n' >"$work_dir/routes.json"
ss -H -lntup >"$work_dir/listeners.txt" 2>/dev/null || true
df -B1 --output=size,used,avail,pcent / | tail -n 1 >"$work_dir/disk.txt" 2>/dev/null || true
cat /proc/meminfo >"$work_dir/meminfo.txt" 2>/dev/null || true

version="$(/usr/local/openvpn_as/scripts/sacli version 2>/dev/null || true)"
if [[ -z "$version" && -x /usr/local/openvpn_as/bin/openvpnas ]]; then
  version="$(/usr/local/openvpn_as/bin/openvpnas --version 2>/dev/null || true)"
fi
printf '%s\n' "$version" >"$work_dir/version.txt"

python3 - "$work_dir" <<'PY'
import datetime, ipaddress, json, os, re, socket, sys
from pathlib import Path

base = Path(sys.argv[1])
now = datetime.datetime.now(datetime.timezone.utc)

def text(name):
    try: return (base / name).read_text(encoding="utf-8", errors="replace").strip()
    except OSError: return ""

def load(name, default):
    try: return json.loads(text(name) or json.dumps(default))
    except (ValueError, TypeError): return default

def scalar(config, *keys, default=""):
    for key in keys:
        value = config.get(key)
        if value not in (None, ""):
            return value
    return default

def truth(value):
    return str(value).strip().lower() in {"1", "true", "yes", "on"}

def bytes_gib(value):
    try: return round(float(value) / 1073741824, 2)
    except (TypeError, ValueError): return 0

def parse_timestamp(value):
    if value in (None, ""): return None
    if isinstance(value, (int, float)):
        try:
            if value > 100000000000: value /= 1000
            return datetime.datetime.fromtimestamp(value, datetime.timezone.utc)
        except (ValueError, OSError, OverflowError): return None
    raw = str(value).strip().replace("Z", "+00:00")
    for candidate in (raw, raw.replace(" ", "T", 1)):
        try:
            parsed = datetime.datetime.fromisoformat(candidate)
            return parsed.replace(tzinfo=parsed.tzinfo or datetime.timezone.utc).astimezone(datetime.timezone.utc)
        except ValueError: pass
    return None

config = load("config.json", {})
if not isinstance(config, dict): config = {}
user_props = load("users.json", {})
if not isinstance(user_props, dict): user_props = {}
status_raw = load("status.json", {})
summary_raw = load("vpn_summary.json", {})
logs_raw = load("logs.json", [])

hostname = socket.gethostname()
fqdn = socket.getfqdn()
public_name = str(scalar(config, "host.name", "cs.hostname", default=fqdn or hostname)).strip()
client_port = int(scalar(config, "cs.https.port", "client_ui.https.port", default=943) or 943)
admin_port = int(scalar(config, "admin_ui.https.port", default=943) or 943)
client_url = f"https://{public_name}" + ("/" if client_port == 443 else f":{client_port}/")
admin_url = f"https://{public_name}" + ("/admin" if admin_port == 443 else f":{admin_port}/admin")

interfaces = []
for iface in load("network.json", []):
    name = str(iface.get("ifname") or "")
    if re.match(r"^(lo|as\d|tun|tap|veth|docker|br-|virbr)", name): continue
    for address in iface.get("addr_info") or []:
        if address.get("family") != "inet": continue
        raw = str(address.get("local") or "")
        try:
            ip = ipaddress.ip_address(raw)
            if ip.is_loopback or ip.is_link_local: continue
            scope = "private" if ip.is_private else "public"
        except ValueError: continue
        interfaces.append({"name": name, "address": f"{raw}/{address.get('prefixlen', '')}", "scope": scope})

routes = load("routes.json", [])
default_gateway = ""
if routes:
    default_gateway = str(routes[0].get("gateway") or routes[0].get("via") or "")

dns = []
try:
    for line in Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("nameserver "): dns.append(line.split()[1])
except OSError: pass

def find_log_records(value):
    found = []
    if isinstance(value, list):
        for item in value: found.extend(find_log_records(item))
    elif isinstance(value, dict):
        lowered = {str(key).lower() for key in value}
        if lowered & {"username", "user_name", "common_name", "user"} and lowered & {"start_time", "timestamp", "start", "time"}:
            found.append(value)
        else:
            for item in value.values(): found.extend(find_log_records(item))
    return found

last_by_user = {}
records = find_log_records(logs_raw)
for row in records if isinstance(records, list) else []:
    if not isinstance(row, dict): continue
    username = str(row.get("username") or row.get("user_name") or row.get("common_name") or row.get("user") or "").strip()
    service = str(row.get("service") or "VPN").upper()
    error = row.get("error")
    if not username or "VPN" not in service or error not in (None, "", False, 0): continue
    stamp = parse_timestamp(row.get("timestamp") or row.get("start_time") or row.get("start") or row.get("time"))
    if stamp and (username not in last_by_user or stamp > last_by_user[username]): last_by_user[username] = stamp

users = []
group_names = {str(props.get("conn_group") or "") for props in user_props.values() if isinstance(props, dict) and props.get("conn_group")}
group_names.update(name for name, props in user_props.items() if isinstance(props, dict) and (truth(props.get("group_declare")) or "group" in str(props.get("type") or "")))
for name, props in user_props.items():
    if not isinstance(props, dict) or name.startswith("__"): continue
    item_type = str(props.get("type") or "")
    if name in group_names:
        continue
    if item_type and "user" not in item_type: continue
    last = last_by_user.get(name)
    if last:
        days = max(0, (now - last).days)
        usage = "recent" if days <= 30 else "aging" if days <= 90 else "inactive"
        last_text = last.strftime("%Y-%m-%d %H:%M UTC")
    else:
        days, usage, last_text = None, "unknown", "History unavailable / never connected"
    users.append({
        "login": name,
        "group": str(props.get("conn_group") or props.get("group") or props.get("prop_group") or ""),
        "access": "Blocked" if truth(props.get("prop_deny")) else "Allowed",
        "auth_method": str(props.get("user_auth_type") or props.get("auth_method") or "Inherited"),
        "admin": truth(props.get("prop_superuser")),
        "autologin": truth(props.get("prop_autologin")),
        "last_connection": last_text,
        "days_since_connection": days,
        "usage": usage,
    })

groups = []
for name in sorted(group_names, key=str.lower):
    props = user_props.get(name) or {}
    access_rules = [str(value) for key, value in sorted(props.items()) if re.match(r"^access_to\.\d+$", str(key)) and value]
    bypass_routes = [str(value) for key, value in sorted(props.items()) if re.match(r"^bypass_route\.\d+$", str(key)) and value]
    groups.append({
        "name": name,
        "access": "Blocked" if truth(props.get("prop_deny")) else "Allowed",
        "auth_method": str(props.get("user_auth_type") or "Inherited"),
        "admin": truth(props.get("prop_superuser")),
        "autologin": truth(props.get("prop_autologin")),
        "allow_profiles": str(props.get("prop_autogenerate") or "Inherited"),
        "reroute_gateway": str(props.get("prop_reroute_gw_override") or props.get("prop_reroute_gw") or "Inherited"),
        "block_local_network": truth(props.get("prop_block_local")),
        "static_ipv4": str(props.get("prop_static") or props.get("static_ip") or ""),
        "access_rules": access_rules,
        "bypass_routes": bypass_routes,
        "members": sum(user.get("group") == name for user in users),
    })

service_state = text("service_state.txt") or "unknown"
components = []
if isinstance(status_raw, dict):
    for key, value in status_raw.items():
        if isinstance(value, dict): state = value.get("status") or value.get("state") or value.get("active")
        else: state = value
        components.append({"name": str(key), "state": str(state)})

mem_total_kib = 0
for line in text("meminfo.txt").splitlines():
    if line.startswith("MemTotal:"):
        try: mem_total_kib = int(line.split()[1])
        except (ValueError, IndexError): pass
disk_parts = text("disk.txt").split()
disk = {"total_gib": 0, "used_gib": 0, "available_gib": 0, "used_pct": ""}
if len(disk_parts) >= 4:
    disk = {"total_gib": bytes_gib(disk_parts[0]), "used_gib": bytes_gib(disk_parts[1]), "available_gib": bytes_gib(disk_parts[2]), "used_pct": disk_parts[3]}

cpu_threads = os.cpu_count() or 0
try:
    load_1m = round(os.getloadavg()[0], 2)
except OSError: load_1m = 0

listeners = []
for line in text("listeners.txt").splitlines():
    match = re.search(r"^(udp|tcp)\S*\s+\S+\s+\S+\s+([^\s]+):(\d+)\s", line)
    if match and int(match.group(3)) in {443, 943, 945, 946, 1194}:
        listeners.append({"protocol": match.group(1).upper(), "address": match.group(2), "port": int(match.group(3))})

certificate = {"subject": "", "issuer": "", "expires": "unknown", "days_remaining": None, "status": "unknown"}
try:
    import ssl
    pem = ssl.get_server_certificate(("127.0.0.1", client_port), timeout=5)
    pem_path = base / "webcert.pem"
    pem_path.write_text(pem, encoding="ascii")
    import subprocess
    cert_text = subprocess.check_output(["openssl", "x509", "-in", str(pem_path), "-noout", "-subject", "-issuer", "-enddate"], text=True, timeout=5)
    values = dict(line.split("=", 1) for line in cert_text.splitlines() if "=" in line)
    expires = datetime.datetime.strptime(values.get("notAfter", ""), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
    remaining = (expires - now).days
    certificate = {"subject": values.get("subject", ""), "issuer": values.get("issuer", ""), "expires": expires.strftime("%Y-%m-%d %H:%M UTC"), "days_remaining": remaining, "status": "expired" if remaining < 0 else "warning" if remaining < 30 else "valid"}
except Exception: pass

auth_method = str(scalar(config, "auth.module.type", "auth.module.type.local", default="unknown"))
vpn_networks = [str(v) for k, v in sorted(config.items()) if re.match(r"vpn\.server\.network\.|vpn\.client\.routing\.private_network\.", k) and v]
warnings = []
if service_state != "active": warnings.append(f"openvpnas.service is {service_state}")
if certificate["status"] == "expired": warnings.append("Client Web Portal TLS certificate has expired")
elif certificate["status"] == "warning": warnings.append(f"TLS certificate expires in {certificate['days_remaining']} days")
if not interfaces: warnings.append("No primary IPv4 interfaces were detected")
if not records:
    detail = text("logs_error.txt")
    warnings.append("VPN connection history query returned no records" + (f": {detail[:240]}" if detail else "; inactivity status may be unknown"))

result = {
    "winhub_report_type": "openvpn_as_inventory",
    "generated_at": now.strftime("%Y-%m-%d %H:%M UTC"),
    "server": {
        "hostname": hostname, "fqdn": fqdn, "os": " ".join(os.uname()),
        "version": text("version.txt") or "unknown", "service_state": service_state,
        "service_started": text("service_started.txt") or "unknown", "cpu_threads": cpu_threads,
        "load_1m": load_1m, "ram_total_gib": round(mem_total_kib / 1048576, 2), "disk": disk,
        "interfaces": interfaces, "default_gateway": default_gateway, "dns": dns,
        "client_url": client_url, "admin_url": admin_url, "client_port": client_port,
        "admin_port": admin_port, "auth_method": auth_method, "vpn_networks": vpn_networks,
        "listeners": listeners, "certificate": certificate, "components": components,
    },
    "summary": {
        "users": len(users), "allowed": sum(x["access"] == "Allowed" for x in users),
        "blocked": sum(x["access"] == "Blocked" for x in users),
        "inactive_over_90_days": sum(x["usage"] == "inactive" for x in users),
        "unknown_history": sum(x["usage"] == "unknown" for x in users),
        "admins": sum(x["admin"] for x in users), "autologin": sum(x["autologin"] for x in users),
        "groups": len(groups),
    },
    "users": sorted(users, key=lambda x: x["login"].lower()),
    "groups": groups,
    "history": {"records_read": len(records), "users_with_history": len(last_by_user), "window_days": 365},
    "warnings": warnings,
    "vpn_summary_available": bool(summary_raw),
}
print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
PY
