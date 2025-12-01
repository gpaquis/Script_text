#!/usr/bin/env python3
import ssl
import os
import json
import time
import requests
from requests.auth import HTTPBasicAuth
from concurrent.futures import ThreadPoolExecutor
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim

# -----------------------------
# Paramètres (adapter)
# -----------------------------
VCENTER_HOST = "vcenter.example.local"
VCENTER_USER = "administrator@vsphere.local"
VCENTER_PASS = "your_vcenter_password"

SONIC_HOST = "10.0.0.10"
SONIC_USER = "admin"
SONIC_PASS = "sonicadmin"  # utilisez un secret en prod

# Cache persistant pour VLANs "gérés par daemon" par port SONiC
CACHE_FILE = "/var/lib/vm-sonic-daemon/port_vlan_cache.json"

# Intervalle de réconciliation complète (secondes)
RECONCILE_INTERVAL = 300  # 5 minutes

# Mapping VNID -> VLAN ID (exemple)
def map_vni_to_vlan(vni: int) -> int:
    if 1 <= vni <= 4094:
        return vni
    return (vni % 4094) or 1

# -----------------------------
# vCenter (pyVmomi)
# -----------------------------
def vc_connect():
    # pyVmomi 8.0U3 compatible Python 3.12; SmartConnect accepte sslContext
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return SmartConnect(host=VCENTER_HOST, user=VCENTER_USER, pwd=VCENTER_PASS, sslContext=ctx)

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
def sonic_rest_get(path):
    url = f"https://{SONIC_HOST}/restconf/data/{path}"
    resp = requests.get(url, auth=HTTPBasicAuth(SONIC_USER, SONIC_PASS),
                        headers={"accept": "application/yang-data+json"},
                        verify=False, timeout=10)
    resp.raise_for_status()
    return resp.json()

def sonic_rest_post(path, payload):
    url = f"https://{SONIC_HOST}/restconf/data/{path}"
    resp = requests.post(url, auth=HTTPBasicAuth(SONIC_USER, SONIC_PASS),
                         headers={"accept": "application/yang-data+json",
                                  "Content-Type": "application/yang-data+json"},
                         data=json.dumps(payload), verify=False, timeout=10)
    resp.raise_for_status()
    return resp

def sonic_rest_patch(path, payload):
    url = f"https://{SONIC_HOST}/restconf/data/{path}"
    resp = requests.patch(url, auth=HTTPBasicAuth(SONIC_USER, SONIC_PASS),
                          headers={"accept": "application/yang-data+json",
                                   "Content-Type": "application/yang-data+json"},
                          data=json.dumps(payload), verify=False, timeout=10)
    resp.raise_for_status()
    return resp

def sonic_rest_delete(path):
    url = f"https://{SONIC_HOST}/restconf/data/{path}"
    resp = requests.delete(url, auth=HTTPBasicAuth(SONIC_USER, SONIC_PASS),
                           headers={"accept": "application/yang-data+json"},
                           verify=False, timeout=10)
    # 200/204/404 acceptables
    if resp.status_code not in (200, 204, 404):
        resp.raise_for_status()
    return resp

# LLDP via OpenConfig
def sonic_get_lldp_neighbors():
    neighbors = {}
    try:
        data = sonic_rest_get("openconfig-lldp:lldp")
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

def map_mac_to_sonic_ports(mac_list: list[str], lldp_neighbors: dict) -> set[str]:
    ports = set()
    macs = {m.lower() for m in mac_list if m}
    for itf, nbrs in lldp_neighbors.items():
        for nbr in nbrs:
            if nbr.get("chassis_id") in macs:
                ports.add(itf)
    return ports

# VLAN helpers
def sonic_interface_exists(interface_name: str) -> bool:
    try:
        encoded_if = requests.utils.quote(interface_name, safe='')
        sonic_rest_get(f"openconfig-interfaces:interfaces/interface={encoded_if}")
        return True
    except Exception:
        return False

def ensure_vlan_interface(vlan_id: int):
    name = f"Vlan{vlan_id}"
    if sonic_interface_exists(name):
        return
    sonic_rest_post("openconfig-interfaces:interfaces", {
        "openconfig-interfaces:interface": [{
            "config": {"name": name},
            "name": name
        }]
    })

def delete_vlan_interface(vlan_id: int):
    name = f"Vlan{vlan_id}"
    if not sonic_interface_exists(name):
        return
    encoded_if = requests.utils.quote(name, safe='')
    sonic_rest_delete(f"openconfig-interfaces:interfaces/interface={encoded_if}")

def get_trunk_vlans(interface_name: str) -> set[int]:
    encoded_if = requests.utils.quote(interface_name, safe='')
    path = f"openconfig-interfaces:interfaces/interface={encoded_if}/openconfig-if-ethernet:ethernet/openconfig-vlan:switched-vlan/config/trunk-vlans"
    try:
        current = sonic_rest_get(path)
        return set(current.get("openconfig-vlan:trunk-vlans", []))
    except Exception:
        return set()

def set_trunk_vlans(interface_name: str, vlan_list: list[int]):
    encoded_if = requests.utils.quote(interface_name, safe='')
    path = f"openconfig-interfaces:interfaces/interface={encoded_if}/openconfig-if-ethernet:ethernet/openconfig-vlan:switched-vlan/config/trunk-vlans"
    payload = {"openconfig-vlan:trunk-vlans": sorted(vlan_list)}
    sonic_rest_patch(path, payload)

def vlan_present_on_any_port(vlan_id: int) -> bool:
    # Scanner toutes les interfaces et leurs trunk-vlans
    data = sonic_rest_get("openconfig-interfaces:interfaces")
    for iface in data.get("openconfig-interfaces:interfaces", {}).get("interface", []):
        name = iface.get("name", "")
        if not name:
            continue
        # Tenter lecture trunk-vlans pour chaque interface
        try:
            existing = get_trunk_vlans(name)
            if vlan_id in existing:
                return True
        except Exception:
            continue
    return False

# -----------------------------
# Cache port->VLANs gérés
# -----------------------------
_port_vlan_cache: dict[str, set[int]] = {}

def load_cache():
    global _port_vlan_cache
    try:
        if os.path.isfile(CACHE_FILE):
            with open(CACHE_FILE, "r") as f:
                data = json.load(f)
                _port_vlan_cache = {k: set(v) for k, v in data.items()}
    except Exception:
        _port_vlan_cache = {}

def save_cache():
    try:
        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        with open(CACHE_FILE, "w") as f:
            json.dump({k: sorted(list(v)) for k, v in _port_vlan_cache.items()}, f)
    except Exception:
        pass

# -----------------------------
# Traitement d’un événement VM
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

        lldp = sonic_get_lldp_neighbors()
        ports = map_mac_to_sonic_ports(macs, lldp)
        if not ports:
            return

        # Pré-créer les VLAN interfaces
        for vid in vlan_targets:
            ensure_vlan_interface(vid)

        # Mettre à jour par port uniquement sur VLANs gérés
        def update_port(iface: str):
            # VLANs gérés désirés (ajoutés par nous)
            managed_current = _port_vlan_cache.get(iface, set())
            managed_desired = managed_current.union(vlan_targets)

            # VLANs actuels sur le port
            current_trunk = get_trunk_vlans(iface)

            # VLANs non gérés existants = actuels - gérés actuels
            non_managed = current_trunk.difference(managed_current)

            final = sorted(list(non_managed.union(managed_desired)))
            if set(final) != current_trunk:
                set_trunk_vlans(iface, final)
                _port_vlan_cache[iface] = managed_desired
                print(f"[SONiC] Port {iface}: trunk-vlans = {final}")
            return iface, final

        with ThreadPoolExecutor(max_workers=min(8, len(ports))) as pool:
            futures = [pool.submit(update_port, p) for p in ports]
            for fut in futures:
                fut.result()
        save_cache()

    except Exception as e:
        print(f"Erreur process_vm_event: {e}")

# -----------------------------
# Réconciliation complète (décommission + suppression VLAN interfaces)
# -----------------------------
def full_reconcile(si):
    try:
        # 1) Calculer les VLANs gérés désirés par port SONiC à partir de toutes les VMs
        lldp = sonic_get_lldp_neighbors()
        desired_managed_per_port: dict[str, set[int]] = {}
        for vm in list_all_vms(si):
            try:
                vlans = get_vm_network_vlans(si, vm)
                if not vlans:
                    continue
                host = vm.runtime.host
                uplinks = get_host_uplinks(host)
                macs = [u["mac"] for u in uplinks if u.get("mac")]
                ports = map_mac_to_sonic_ports(macs, lldp)
                for p in ports:
                    desired_managed_per_port.setdefault(p, set()).update(vlans)
            except Exception:
                continue

        # 2) Appliquer par port: conserver non gérés + desired gérés
        for port, desired_managed in desired_managed_per_port.items():
            current_trunk = get_trunk_vlans(port)
            managed_current = _port_vlan_cache.get(port, set())
            non_managed = current_trunk.difference(managed_current)
            final = sorted(list(non_managed.union(desired_managed)))
            if set(final) != current_trunk:
                set_trunk_vlans(port, final)
                print(f"[RECONCILE] Port {port}: trunk-vlans -> {final}")
            _port_vlan_cache[port] = desired_managed

        # 3) Ports du cache non présents dans desired: retirer gérés (décommission local)
        for port in list(_port_vlan_cache.keys()):
            if port not in desired_managed_per_port:
                current_trunk = get_trunk_vlans(port)
                managed_current = _port_vlan_cache.get(port, set())
                non_managed = current_trunk.difference(managed_current)
                final = sorted(list(non_managed))  # décommissionner tous les gérés
                if set(final) != current_trunk:
                    set_trunk_vlans(port, final)
                    print(f"[RECONCILE] Port {port}: décommission géré, trunk-vlans -> {final}")
                _port_vlan_cache[port] = set()

        save_cache()

        # 4) Supprimer les interfaces Vlan<ID> gérées inutilisées
        #    - VLANs gérés actuels = union des valeurs du cache
        managed_all = set()
        for s in _port_vlan_cache.values():
            managed_all.update(s)
        #    - VLANs gérés désirés = union des valeurs de desired_managed_per_port
        desired_all = set()
        for s in desired_managed_per_port.values():
            desired_all.update(s)
        #    - Candidats à supprimer = managed_all - desired_all (plus aucun besoin côté VMs)
        candidates = managed_all.difference(desired_all)
        for vid in candidates:
            # Supprimer interface VLAN seulement si le VLAN n’est plus présent sur aucun port (même non géré)
            if not vlan_present_on_any_port(vid):
                delete_vlan_interface(vid)
                print(f"[RECONCILE] Suppression interface Vlan{vid} (plus utilisée)")

    except Exception as e:
        print(f"[RECONCILE] erreur: {e}")

# -----------------------------
# Boucle daemon: Event + reconcile
# -----------------------------
def main_daemon():
    load_cache()
    si = vc_connect()
    try:
        content = si.RetrieveContent()
        em = content.eventManager

        event_types = [
            "VmCreatedEvent",
            "VmMigratedEvent",
            "DrsVmMigratedEvent",
            "VmRelocatedEvent",
            "VmConnectedToNetworkEvent",
            "VmReconfiguredEvent",
        ]

        last_key = None
        last_reconcile = 0
        print("[Daemon] démarré; surveillance des événements réseau VM + réconciliation périodique...")

        while True:
            try:
                # Réconciliation périodique
                now = time.time()
                if now - last_reconcile >= RECONCILE_INTERVAL:
                    full_reconcile(si)
                    last_reconcile = now

                # Écoute des événements
                efs = vim.event.EventFilterSpec()
                efs.eventTypeId = event_types
                events = em.QueryEvents(filter=efs) or []
                if not events:
                    time.sleep(3)
                    continue

                max_key = max(e.key for e in events if hasattr(e, "key"))
                if last_key is None:
                    last_key = max_key
                    time.sleep(2)
                    continue

                for ev in events:
                    if not hasattr(ev, "key") or ev.key <= last_key:
                        continue
                    if not event_is_network_related(ev):
                        last_key = max(last_key, ev.key)
                        continue

                    vm = getattr(ev, "vm", None)
                    if vm and hasattr(vm, "vm"):
                        vm = vm.vm
                    if isinstance(vm, vim.VirtualMachine):
                        print(f"[vCenter] {type(ev).__name__} VM {vm.name}, key={ev.key}")
                        process_vm_event(si, vm)

                    last_key = max(last_key, ev.key)

                time.sleep(2)
            except Exception as loop_err:
                print(f"[Daemon] erreur boucle: {loop_err}")
                time.sleep(5)
    finally:
        Disconnect(si)

if __name__ == "__main__":
    main_daemon()
