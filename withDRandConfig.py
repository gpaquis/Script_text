#!/usr/bin/env python3
import ssl
import os
import json
import time
import argparse
import requests
from requests.auth import HTTPBasicAuth
from concurrent.futures import ThreadPoolExecutor
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim

# -----------------------------
# Configuration et globals
# -----------------------------
CONFIG = {
    "reconcile_interval": 300,
    "dry_run": False,
    "vcenters": [],
    "sonic_devices": []
}
DRY_RUN = False
CACHE_FILE = "/var/lib/vm-sonic-daemon/port_vlan_cache.json"
# Cache: {sonic_host: {port_name: set(VLAN_ID)}}
_port_vlan_cache: dict[str, dict[str, set[int]]] = {}

# -----------------------------
# Mapping VNID -> VLAN ID
# -----------------------------
def map_vni_to_vlan(vni: int) -> int:
    if 1 <= vni <= 4094:
        return vni
    return (vni % 4094) or 1

# -----------------------------
# vCenter (pyVmomi)
# -----------------------------
def vc_connect(vcenter):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    si = SmartConnect(host=vcenter["host"], user=vcenter["user"], pwd=vcenter["password"], sslContext=ctx)
    return si

def event_is_network_related(ev) -> bool:
    if isinstance(ev, (vim.event.VmConnectedToNetworkEvent,
                       vim.event.VmMigratedEvent,
                       vim.event.DrsVmMigratedEvent,
                       vim.event.VmRelocatedEvent,
                       vim.event.VmCreatedEvent)):
        return True
    if isinstance(ev, vim.event.VmReconfiguredEvent):
        spec = getattr(ev, "configSpec", None)
        if spec and getattr(spec, "deviceChange", None):
            for dc in spec.deviceChange:
                dev = getattr(dc, "device", None)
                if isinstance(dev, vim.vm.device.VirtualEthernetCard):
                    return True
    return False

def get_vm_network_vlans(si, vm) -> set[int]:
    vlan_ids = set()
    if not vm or not vm.config or not vm.config.hardware:
        return vlan_ids
    for dev in vm.config.hardware.device:
        if not isinstance(dev, vim.vm.device.VirtualEthernetCard):
            continue
        b = dev.backing
        # OpaqueNetwork -> VNID
        if isinstance(b, vim.vm.device.VirtualEthernetCard.OpaqueNetworkBackingInfo):
            try:
                vlan_ids.add(map_vni_to_vlan(int(b.opaqueNetworkId)))
            except Exception:
                pass
        # DVPortgroup -> VLAN du portgroup
        elif isinstance(b, vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo):
            try:
                pgkey = b.port.portgroupKey
                content = si.RetrieveContent()
                pg_view = content.viewManager.CreateContainerView(
                    content.rootFolder, [vim.dvs.DistributedVirtualPortgroup], True
                )
                for p in pg_view.view:
                    if p.key == pgkey:
                        cfg = p.config.defaultPortConfig
                        if hasattr(cfg, 'vlan') and hasattr(cfg.vlan, 'vlanId'):
                            vid = cfg.vlan.vlanId
                            if isinstance(vid, int) and 1 <= vid <= 4094:
                                vlan_ids.add(vid)
                pg_view.Destroy()
            except Exception:
                pass
    return vlan_ids

def list_all_vms(si):
    content = si.RetrieveContent()
    vm_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
    vms = list(vm_view.view)
    vm_view.Destroy()
    return vms

def get_host_uplinks(host) -> list[dict]:
    uplinks = []
    if not host or not host.config or not host.config.network:
        return uplinks
    for p in host.config.network.pnic:
        uplinks.append({
            "device": p.device,
            "mac": (p.mac or "").lower(),
            "speedMb": getattr(p.linkSpeed, 'speedMb', None),
        })
    return uplinks

# -----------------------------
# SONiC RESTCONF (OpenConfig)
# -----------------------------
def sonic_rest_get(dev, path):
    url = f"https://{dev['host']}/restconf/data/{path}"
    resp = requests.get(url, auth=HTTPBasicAuth(dev["user"], dev["password"]),
                        headers={"accept": "application/yang-data+json"},
                        verify=False, timeout=10)
    resp.raise_for_status()
    return resp.json()

def sonic_rest_post(dev, path, payload):
    if DRY_RUN:
        print(f"[DRY-RUN] Would POST {dev['host']} {path} payload={payload}")
        return None
    url = f"https://{dev['host']}/restconf/data/{path}"
    resp = requests.post(url, auth=HTTPBasicAuth(dev["user"], dev["password"]),
                         headers={"accept": "application/yang-data+json",
                                  "Content-Type": "application/yang-data+json"},
                         data=json.dumps(payload), verify=False, timeout=10)
    resp.raise_for_status()
    return resp

def sonic_rest_patch(dev, path, payload):
    if DRY_RUN:
        print(f"[DRY-RUN] Would PATCH {dev['host']} {path} payload={payload}")
        return None
    url = f"https://{dev['host']}/restconf/data/{path}"
    resp = requests.patch(url, auth=HTTPBasicAuth(dev["user"], dev["password"]),
                          headers={"accept": "application/yang-data+json",
                                   "Content-Type": "application/yang-data+json"},
                          data=json.dumps(payload), verify=False, timeout=10)
    resp.raise_for_status()
    return resp

def sonic_rest_delete(dev, path):
    if DRY_RUN:
        print(f"[DRY-RUN] Would DELETE {dev['host']} {path}")
        return None
    url = f"https://{dev['host']}/restconf/data/{path}"
    resp = requests.delete(url, auth=HTTPBasicAuth(dev["user"], dev["password"]),
                           headers={"accept": "application/yang-data+json"},
                           verify=False, timeout=10)
    if resp.status_code not in (200, 204, 404):
        resp.raise_for_status()
    return resp

def sonic_get_lldp_neighbors(dev):
    neighbors = {}
    try:
        data = sonic_rest_get(dev, "openconfig-lldp:lldp")
        ifaces = data.get("openconfig-lldp:lldp", {}) \
                     .get("interfaces", {}) \
                     .get("interface", [])
        for itf in ifaces:
            name = itf.get("name")
            nbrs = itf.get("neighbors", {}).get("neighbor", [])
            parsed = []
            for n in nbrs:
                st = n.get("state", {}) or {}
                parsed.append({
                    "id": n.get("id"),
                    "chassis_id": (st.get("chassis-id") or "").lower(),
                    "port_id": st.get("port-id"),
                    "system_name": st.get("system-name"),
                })
            if name:
                neighbors[name] = parsed
    except Exception:
        pass
    return neighbors

def map_mac_to_sonic_ports(dev, mac_list: list[str]) -> set[str]:
    lldp_neighbors = sonic_get_lldp_neighbors(dev)
    ports = set()
    macs = {m.lower() for m in mac_list if m}
    for itf, nbrs in lldp_neighbors.items():
        for nbr in nbrs:
            if nbr.get("chassis_id") in macs:
                ports.add(itf)
    return ports

def sonic_interface_exists(dev, interface_name: str) -> bool:
    try:
        encoded_if = requests.utils.quote(interface_name, safe='')
        sonic_rest_get(dev, f"openconfig-interfaces:interfaces/interface={encoded_if}")
        return True
    except Exception:
        return False

def ensure_vlan_interface(dev, vlan_id: int):
    name = f"Vlan{vlan_id}"
    if sonic_interface_exists(dev, name):
        return
    payload = {
        "openconfig-interfaces:interface": [{
            "config": {"name": name},
            "name": name
        }]
    }
    sonic_rest_post(dev, "openconfig-interfaces:interfaces", payload)

def delete_vlan_interface(dev, vlan_id: int):
    name = f"Vlan{vlan_id}"
    if not sonic_interface_exists(dev, name):
        return
    encoded_if = requests.utils.quote(name, safe='')
    sonic_rest_delete(dev, f"openconfig-interfaces:interfaces/interface={encoded_if}")

def get_trunk_vlans(dev, interface_name: str) -> set[int]:
    encoded_if = requests.utils.quote(interface_name, safe='')
    path = f"openconfig-interfaces:interfaces/interface={encoded_if}/openconfig-if-ethernet:ethernet/openconfig-vlan:switched-vlan/config/trunk-vlans"
    try:
        current = sonic_rest_get(dev, path)
        return set(current.get("openconfig-vlan:trunk-vlans", []))
    except Exception:
        return set()

def set_trunk_vlans(dev, interface_name: str, vlan_list: list[int]):
    encoded_if = requests.utils.quote(interface_name, safe='')
    path = f"openconfig-interfaces:interfaces/interface={encoded_if}/openconfig-if-ethernet:ethernet/openconfig-vlan:switched-vlan/config/trunk-vlans"
    payload = {"openconfig-vlan:trunk-vlans": sorted(vlan_list)}
    sonic_rest_patch(dev, path, payload)

def vlan_present_on_any_port(dev, vlan_id: int) -> bool:
    data = sonic_rest_get(dev, "openconfig-interfaces:interfaces")
    for iface in data.get("openconfig-interfaces:interfaces", {}).get("interface", []):
        name = iface.get("name", "")
        if not name:
            continue
        try:
            existing = get_trunk_vlans(dev, name)
            if vlan_id in existing:
                return True
        except Exception:
            continue
    return False

# -----------------------------
# Cache port->VLANs gérés (multi-SONiC)
# -----------------------------
def load_cache():
    global _port_vlan_cache
    try:
        if os.path.isfile(CACHE_FILE):
            with open(CACHE_FILE, "r") as f:
                data = json.load(f)
                _port_vlan_cache = {host: {p: set(v) for p, v in ports.items()} for host, ports in data.items()}
    except Exception:
        _port_vlan_cache = {}

def save_cache():
    if DRY_RUN:
        print("[DRY-RUN] Would save cache (skipped).")
        return
    try:
        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        serializable = {host: {p: sorted(list(v)) for p, v in ports.items()} for host, ports in _port_vlan_cache.items()}
        with open(CACHE_FILE, "w") as f:
            json.dump(serializable, f)
    except Exception:
        pass

# -----------------------------
# Traitement d’un événement VM (appliqué à tous les SONiC)
# -----------------------------
def process_vm_event(si, vm):
    try:
        vlan_targets = get_vm_network_vlans(si, vm)
        if not vlan_targets:
            return

        host = vm.runtime.host
        uplinks = get_host_uplinks(host)
        macs = [u["mac"] for u in uplinks if u.get("mac")]
        if not macs:
            return

        # Pour chaque SONiC, chercher les ports correspondant aux uplinks via LLDP
        for dev in CONFIG["sonic_devices"]:
            sonic_ports = map_mac_to_sonic_ports(dev, macs)
            if not sonic_ports:
                continue

            # Pré-créer les VLAN interfaces
            for vid in vlan_targets:
                ensure_vlan_interface(dev, vid)

            # Mise à jour par port (gérés uniquement)
            def update_port(iface: str):
                managed_current = _port_vlan_cache.get(dev["host"], {}).get(iface, set())
                managed_desired = managed_current.union(vlan_targets)

                current_trunk = get_trunk_vlans(dev, iface)
                non_managed = current_trunk.difference(managed_current)

                final = sorted(list(non_managed.union(managed_desired)))
                if set(final) != current_trunk:
                    set_trunk_vlans(dev, iface, final)
                    if DRY_RUN:
                        print(f"[DRY-RUN] Would set cache[{dev['host']}][{iface}] = {sorted(list(managed_desired))}")
                    else:
                        _port_vlan_cache.setdefault(dev["host"], {})[iface] = managed_desired
                        print(f"[SONiC {dev['host']}] Port {iface}: trunk-vlans = {final}")
                return iface, final

            with ThreadPoolExecutor(max_workers=min(8, len(sonic_ports))) as pool:
                futures = [pool.submit(update_port, p) for p in sonic_ports]
                for fut in futures:
                    fut.result()

        save_cache()

    except Exception as e:
        print(f"Erreur process_vm_event: {e}")

# -----------------------------
# Réconciliation (multi-vCenter, multi-SONiC)
# -----------------------------
def full_reconcile():
    try:
        # 1) Construire desired_managed_per_port par SONiC à partir de toutes les VMs de tous les vCenter
        desired_managed_per_port: dict[str, dict[str, set[int]]] = {}

        for vc in CONFIG["vcenters"]:
            si = vc_connect(vc)
            try:
                vms = list_all_vms(si)
                for vm in vms:
                    try:
                        vlans = get_vm_network_vlans(si, vm)
                        if not vlans:
                            continue
                        host = vm.runtime.host
                        uplinks = get_host_uplinks(host)
                        macs = [u["mac"] for u in uplinks if u.get("mac")]

                        for dev in CONFIG["sonic_devices"]:
                            ports = map_mac_to_sonic_ports(dev, macs)
                            for p in ports:
                                desired_managed_per_port.setdefault(dev["host"], {}).setdefault(p, set()).update(vlans)
                    except Exception:
                        continue
            finally:
                Disconnect(si)

        # 2) Appliquer par SONiC: conserver non gérés + desired gérés
        for dev in CONFIG["sonic_devices"]:
            host = dev["host"]
            desired_ports = desired_managed_per_port.get(host, {})
            for port, desired_managed in desired_ports.items():
                current_trunk = get_trunk_vlans(dev, port)
                managed_current = _port_vlan_cache.get(host, {}).get(port, set())
                non_managed = current_trunk.difference(managed_current)
                final = sorted(list(non_managed.union(desired_managed)))
                if set(final) != current_trunk:
                    set_trunk_vlans(dev, port, final)
                    if DRY_RUN:
                        print(f"[DRY-RUN] Would set cache[{host}][{port}] = {sorted(list(desired_managed))}")
                    else:
                        _port_vlan_cache.setdefault(host, {})[port] = desired_managed
                        print(f"[RECONCILE {host}] Port {port}: trunk-vlans -> {final}")

            # 3) Ports présents dans le cache mais non dans desired: retirer gérés (décommission)
            cached_ports = set(_port_vlan_cache.get(host, {}).keys())
            for port in cached_ports:
                if port not in desired_ports:
                    current_trunk = get_trunk_vlans(dev, port)
                    managed_current = _port_vlan_cache.get(host, {}).get(port, set())
                    non_managed = current_trunk.difference(managed_current)
                    final = sorted(list(non_managed))
                    if set(final) != current_trunk:
                        set_trunk_vlans(dev, port, final)
                        print(f"[RECONCILE{' DRY-RUN' if DRY_RUN else ''} {host}] Port {port}: décommission géré -> {final}")
                    if not DRY_RUN:
                        _port_vlan_cache[host][port] = set()

        save_cache()

        # 4) Suppression des interfaces VLAN inutilisées par SONiC
        for dev in CONFIG["sonic_devices"]:
            host = dev["host"]
            managed_all = set()
            for s in _port_vlan_cache.get(host, {}).values():
                managed_all.update(s)
            desired_all = set()
            for s in desired_managed_per_port.get(host, {}).values():
                desired_all.update(s)
            candidates = managed_all.difference(desired_all)
            for vid in candidates:
                if not vlan_present_on_any_port(dev, vid):
                    if DRY_RUN:
                        print(f"[DRY-RUN] Would DELETE Vlan{vid} on {host} (no longer used)")
                    else:
                        delete_vlan_interface(dev, vid)
                        print(f"[RECONCILE {host}] Suppression interface Vlan{vid} (plus utilisée)")

    except Exception as e:
        print(f"[RECONCILE] erreur: {e}")

# -----------------------------
# Boucle daemon: multi-vCenter events + reconcile
# -----------------------------
def main_daemon():
    global DRY_RUN, CONFIG
    parser = argparse.ArgumentParser(description="VM→SONiC VLAN daemon (multi-vCenter, multi-SONiC)")
    parser.add_argument("--config", required=True, help="Path to JSON config file")
    parser.add_argument("--dry-run", action="store_true", help="Simulate SONiC write operations")
    args = parser.parse_args()

    # Charger configuration
    with open(args.config, "r") as f:
        CONFIG = json.load(f)
    DRY_RUN = bool(args.dry_run or CONFIG.get("dry_run", False))
    reconcile_interval = int(CONFIG.get("reconcile_interval", 300))

    # Charger cache
    load_cache()

    # Préparer connexions vCenter (un watcher par vCenter)
    watchers = []
    for vc in CONFIG["vcenters"]:
        si = vc_connect(vc)
        watchers.append({"vc": vc, "si": si, "em": si.RetrieveContent().eventManager, "last_key": None})

    print(f"[Daemon] started (dry-run={DRY_RUN}); watching {len(watchers)} vCenter(s) + periodic reconcile...")

    try:
        last_reconcile = 0
        while True:
            now = time.time()
            if now - last_reconcile >= reconcile_interval:
                full_reconcile()
                last_reconcile = now

            for w in watchers:
                vc = w["vc"]; em = w["em"]
                try:
                    # Événements pertinents
                    efs = vim.event.EventFilterSpec()
                    efs.eventTypeId = [
                        "VmCreatedEvent", "VmMigratedEvent", "DrsVmMigratedEvent",
                        "VmRelocatedEvent", "VmConnectedToNetworkEvent", "VmReconfiguredEvent"
                    ]
                    events = em.QueryEvents(filter=efs) or []
                    if not events:
                        continue
                    max_key = max(e.key for e in events if hasattr(e, "key"))
                    if w["last_key"] is None:
                        w["last_key"] = max_key
                        continue
                    for ev in events:
                        if not hasattr(ev, "key") or ev.key <= w["last_key"]:
                            continue
                        if not event_is_network_related(ev):
                            w["last_key"] = max(w["last_key"], ev.key)
                            continue
                        vm = getattr(ev, "vm", None)
                        if vm and hasattr(vm, "vm"):
                            vm = vm.vm
                        if isinstance(vm, vim.VirtualMachine):
                            print(f"[{vc['host']}] {type(ev).__name__} VM {vm.name}, key={ev.key}")
                            process_vm_event(w["si"], vm)
                        w["last_key"] = max(w["last_key"], ev.key)
                except Exception as loop_err:
                    print(f"[Daemon] {vc['host']} loop error: {loop_err}")
            time.sleep(2)
    finally:
        for w in watchers:
            try:
                Disconnect(w["si"])
            except Exception:
                pass

if __name__ == "__main__":
    main_daemon()
