#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C.UTF-8

if ! command -v pvesh >/dev/null 2>&1; then
  printf '{"winhub_report_type":"proxmox_inventory","error":"pvesh not found; this task must run on a Proxmox VE node"}\n'
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  printf '{"winhub_report_type":"proxmox_inventory","error":"python3 is required"}\n'
  exit 1
fi

work_dir="$(mktemp -d /tmp/winhub-pve-inventory.XXXXXX)"
trap 'rm -rf "$work_dir"' EXIT
umask 077

pvesh get /cluster/resources --type vm --output-format json >"$work_dir/guests.json"
pvesh get /cluster/resources --type node --output-format json >"$work_dir/nodes.json"
pvesh get /cluster/resources --type storage --output-format json >"$work_dir/storage.json"
: >"$work_dir/guest_configs.jsonl"
: >"$work_dir/networks.jsonl"

python3 - "$work_dir/guests.json" <<'PY' | while read -r node kind vmid; do
import json, sys
for item in json.load(open(sys.argv[1], encoding="utf-8")):
    if item.get("type") in ("qemu", "lxc"):
        print(item.get("node", ""), item["type"], item.get("vmid", ""))
PY
  config="$(pvesh get "/nodes/$node/$kind/$vmid/config" --output-format json 2>/dev/null || printf '{}')"
  printf '{"node":%s,"type":%s,"vmid":%s,"config":%s}\n' \
    "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$node")" \
    "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$kind")" \
    "$vmid" "$config" >>"$work_dir/guest_configs.jsonl"
done

python3 - "$work_dir/nodes.json" <<'PY' | while read -r node; do
import json, sys
for item in json.load(open(sys.argv[1], encoding="utf-8")):
    print(item.get("node") or item.get("name") or "")
PY
  network="$(pvesh get "/nodes/$node/network" --output-format json 2>/dev/null || printf '[]')"
  printf '{"node":%s,"interfaces":%s}\n' \
    "$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$node")" "$network" >>"$work_dir/networks.jsonl"
done

cluster_name="$(pvesh get /cluster/status --output-format json 2>/dev/null | python3 -c 'import json,sys; print(next((x.get("name","") for x in json.load(sys.stdin) if x.get("type")=="cluster"), "standalone"))' 2>/dev/null || printf standalone)"
generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

python3 - "$work_dir" "$cluster_name" "$generated_at" <<'PY'
import datetime, ipaddress, json, os, re, sys

base, cluster, generated_at = sys.argv[1:]
def load(name):
    with open(os.path.join(base, name), encoding="utf-8") as handle:
        value = json.load(handle)
        return value if isinstance(value, list) else []

def load_lines(name):
    values = []
    with open(os.path.join(base, name), encoding="utf-8") as handle:
        for line in handle:
            try: values.append(json.loads(line))
            except (ValueError, TypeError): pass
    return values

def gib(value):
    try: return round(float(value or 0) / 1073741824, 2)
    except (TypeError, ValueError): return 0

def pct(value):
    try: return round(float(value or 0) * 100, 1)
    except (TypeError, ValueError): return 0

def disk_size_gib(value):
    match = re.search(r"(?:^|,)size=([0-9.]+)([KMGT])(?:i?B)?(?:,|$)", str(value), re.I)
    if not match: return 0
    amount, unit = float(match.group(1)), match.group(2).upper()
    return round(amount * {"K": 1 / 1048576, "M": 1 / 1024, "G": 1, "T": 1024}[unit], 2)

configs = {(x.get("node"), int(x.get("vmid") or 0)): x.get("config") or {} for x in load_lines("guest_configs.jsonl")}
network_rows = {x.get("node"): x.get("interfaces") or [] for x in load_lines("networks.jsonl")}

guests = []
for row in load("guests.json"):
    if row.get("type") not in ("qemu", "lxc"):
        continue
    config = configs.get((row.get("node"), int(row.get("vmid") or 0)), {})
    local_disks = [value for key, value in config.items()
                   if re.match(r"^(scsi|sata|ide|virtio)\d+$|^rootfs$|^mp\d+$", str(key))
                   and re.search(r"(?:^|,)local:", str(value))]
    local_disk_gib = round(sum(disk_size_gib(value) for value in local_disks), 2)
    guests.append({
        "node": str(row.get("node") or ""),
        "vmid": int(row.get("vmid") or 0),
        "name": str(row.get("name") or f"VM-{row.get('vmid', '')}"),
        "type": "QEMU" if row.get("type") == "qemu" else "LXC",
        "status": str(row.get("status") or "unknown"),
        "cpu_count": int(row.get("maxcpu") or 0),
        "memory_allocated_gib": gib(row.get("maxmem")),
        "disk_allocated_gib": gib(row.get("maxdisk")),
        "local_disk_allocated_gib": local_disk_gib,
        "uses_local_storage": bool(local_disks),
        "pool": str(row.get("pool") or ""),
        "tags": str(row.get("tags") or ""),
        "template": bool(row.get("template")),
    })

nodes = []
for row in load("nodes.json"):
    node_name = str(row.get("node") or row.get("name") or "")
    interfaces = []
    for item in network_rows.get(node_name, []):
        name = str(item.get("iface") or "")
        address = str(item.get("address") or "").strip()
        if not address or re.match(r"^(tap|veth|fwbr|fwpr|fwln)", name): continue
        try:
            ip = ipaddress.ip_address(address.split("/")[0])
            if ip.version != 4 or ip.is_loopback or ip.is_link_local: continue
            scope = "private" if ip.is_private else "public"
        except ValueError: continue
        cidr = str(item.get("cidr") or address)
        if "/" not in cidr and item.get("netmask"):
            try: cidr = str(ipaddress.ip_interface(f"{address}/{item['netmask']}"))
            except ValueError: pass
        interfaces.append({"name": name, "address": cidr, "scope": scope})
    uptime = int(row.get("uptime") or 0)
    try:
        generated_dt = datetime.datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
        last_boot = (generated_dt - datetime.timedelta(seconds=uptime)).strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError, OverflowError): last_boot = "unknown"
    nodes.append({
        "name": node_name,
        "status": str(row.get("status") or "unknown"),
        "cpu_count": int(row.get("maxcpu") or 0),
        "cpu_usage_pct": pct(row.get("cpu")),
        "memory_total_gib": gib(row.get("maxmem")),
        "last_boot": last_boot,
        "interfaces": interfaces,
    })

storage = []
for row in load("storage.json"):
    storage.append({
        "node": str(row.get("node") or ""),
        "storage": str(row.get("storage") or ""),
        "status": str(row.get("status") or "unknown"),
        "used_gib": gib(row.get("disk")),
        "total_gib": gib(row.get("maxdisk")),
    })

for node in nodes:
    node_guests = [x for x in guests if x["node"] == node["name"] and not x["template"]]
    local = next((x for x in storage if x["node"] == node["name"] and x["storage"] == "local"), None)
    allocated_vcpu = sum(x["cpu_count"] for x in node_guests)
    allocated_ram = sum(x["memory_allocated_gib"] for x in node_guests)
    provisioned_local = sum(x["local_disk_allocated_gib"] for x in node_guests)
    cpu_vm_capacity = max(0, (node["cpu_count"] * 3 - allocated_vcpu) // 4)
    ram_vm_capacity = max(0, int((node["memory_total_gib"] - allocated_ram) // 16))
    if local:
        actual_free = max(0, local["total_gib"] - local["used_gib"])
        provisioned_free = max(0, local["total_gib"] - provisioned_local)
        local_free = min(actual_free, provisioned_free)
        disk_vm_capacity = max(0, int(local_free // 150))
        estimated_vms = min(cpu_vm_capacity, ram_vm_capacity, disk_vm_capacity)
    else:
        local_free, disk_vm_capacity, estimated_vms = 0, 0, 0
    limits = {"CPU": cpu_vm_capacity, "RAM": ram_vm_capacity, "LOCAL DISK": disk_vm_capacity}
    limiting_resources = [name for name, value in limits.items() if value == estimated_vms]
    node["capacity"] = {
        "allocated_vcpu": allocated_vcpu, "allocated_ram_gib": round(allocated_ram, 2),
        "local_provisioned_gib": round(provisioned_local, 2), "local_available_gib": round(local_free, 2),
        "cpu_vm_limit": cpu_vm_capacity, "ram_vm_limit": ram_vm_capacity,
        "disk_vm_limit": disk_vm_capacity, "estimated_additional_vms": estimated_vms,
        "limiting_resource": " + ".join(limiting_resources),
        "has_local_storage": bool(local),
    }

result = {
    "winhub_report_type": "proxmox_inventory",
    "cluster": cluster,
    "generated_at": generated_at,
    "collector_node": os.uname().nodename,
    "summary": {
        "nodes": len(nodes),
        "guests": len(guests),
        "running": sum(x["status"] == "running" for x in guests),
        "stopped": sum(x["status"] == "stopped" for x in guests),
        "qemu": sum(x["type"] == "QEMU" for x in guests),
        "lxc": sum(x["type"] == "LXC" for x in guests),
    },
    "nodes": sorted(nodes, key=lambda x: x["name"]),
    "guests": sorted(guests, key=lambda x: (x["node"], x["vmid"])),
    "storage": sorted(storage, key=lambda x: (x["node"], x["storage"])),
}
print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
PY
