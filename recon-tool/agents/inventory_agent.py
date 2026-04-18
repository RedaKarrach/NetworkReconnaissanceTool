"""
inventory_agent.py — Run on Windows or Linux VMs
=================================================
Collects Wazuh-like host inventory and POSTs it to the dashboard.

Usage:
  pip install requests psutil
  python inventory_agent.py

Config via env:
  DASHBOARD_URL=http://192.168.56.1:8000/api/agents/inventory/
  AGENT_ID=win-victim
  AGENT_TOKEN=change-me
  INTERVAL=60
"""
import json
import os
import platform
import socket
import subprocess
import time
from datetime import datetime

import requests

try:
  import psutil
except Exception:
  psutil = None

DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "http://192.168.56.1:8000/api/agents/inventory/")
AGENT_ID = os.environ.get("AGENT_ID")
AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
INTERVAL = int(os.environ.get("INTERVAL", "60"))


def run_cmd(cmd):
  try:
    out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL, text=True)
    return out.strip()
  except Exception:
    return ""


def get_hostname():
  return platform.node() or socket.gethostname() or "unknown"


def get_domain():
  fqdn = socket.getfqdn()
  if "." in fqdn:
    return fqdn.split(".", 1)[1]
  return os.environ.get("USERDOMAIN", "")


def get_interfaces():
  interfaces = []
  ips = []
  macs = []

  if psutil:
    addrs = psutil.net_if_addrs()
    for name, addr_list in addrs.items():
      iface = {"name": name, "ips": [], "mac": ""}
      for addr in addr_list:
        if addr.family.name in ("AF_INET", "AF_INET6"):
          iface["ips"].append(addr.address)
          ips.append(addr.address)
        elif addr.family.name in ("AF_LINK", "AF_PACKET"):
          iface["mac"] = addr.address
          if addr.address:
            macs.append(addr.address)
      interfaces.append(iface)
  else:
    ip = socket.gethostbyname(socket.gethostname())
    ips.append(ip)

  return interfaces, sorted(set(ips)), sorted(set(macs))


def get_cpu_info():
  cpu_model = platform.processor() or platform.uname().processor or ""
  cores = None
  if psutil:
    cores = psutil.cpu_count(logical=False) or psutil.cpu_count()
  return cpu_model, cores


def get_memory_mb():
  if not psutil:
    return None
  return int(psutil.virtual_memory().total / (1024 * 1024))


def get_disk_gb():
  if not psutil:
    return None, None
  path = "C:\\" if os.name == "nt" else "/"
  usage = psutil.disk_usage(path)
  return round(usage.total / (1024 ** 3), 2), round(usage.free / (1024 ** 3), 2)


def get_uptime_sec():
  if not psutil:
    return None
  return int(time.time() - psutil.boot_time())


def get_users():
  if not psutil:
    return []
  return sorted(set(u.name for u in psutil.users() if u.name))


def get_open_ports():
  if not psutil:
    return []
  ports = set()
  try:
    for c in psutil.net_connections(kind="inet"):
      if c.status == "LISTEN" and c.laddr:
        ports.add(c.laddr.port)
  except Exception:
    return []
  return sorted(ports)


def get_packages():
  if os.name == "nt":
    cmd = (
      "powershell -NoProfile -Command "
      "\"Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
      "| Where-Object { $_.DisplayName } "
      "| Select-Object -ExpandProperty DisplayName\""
    )
    out = run_cmd(cmd)
    return out.splitlines()[:200] if out else []

  if run_cmd("command -v dpkg-query"):
    out = run_cmd("dpkg-query -W -f='${Package}\n'")
    return out.splitlines()[:200] if out else []

  if run_cmd("command -v rpm"):
    out = run_cmd("rpm -qa")
    return out.splitlines()[:200] if out else []

  return []


def get_services():
  if os.name == "nt":
    cmd = (
      "powershell -NoProfile -Command "
      "\"Get-Service | Where-Object { $_.Status -eq 'Running' } "
      "| Select-Object -ExpandProperty Name\""
    )
    out = run_cmd(cmd)
    return out.splitlines()[:200] if out else []

  out = run_cmd("systemctl list-units --type=service --state=running --no-legend")
  if out:
    services = [line.split()[0] for line in out.splitlines() if line.strip()]
    return services[:200]
  return []


def build_payload():
  hostname = get_hostname()
  interfaces, ips, macs = get_interfaces()
  cpu_model, cpu_cores = get_cpu_info()
  disk_total_gb, disk_free_gb = get_disk_gb()

  return {
    "agent_id": AGENT_ID or hostname,
    "hostname": hostname,
    "os_name": platform.system(),
    "os_version": platform.version(),
    "kernel": platform.release(),
    "arch": platform.machine(),
    "domain": get_domain(),
    "ips": ips,
    "macs": macs,
    "interfaces": interfaces,
    "cpu_model": cpu_model,
    "cpu_cores": cpu_cores,
    "ram_mb": get_memory_mb(),
    "disk_total_gb": disk_total_gb,
    "disk_free_gb": disk_free_gb,
    "uptime_sec": get_uptime_sec(),
    "users": get_users(),
    "packages": get_packages(),
    "services": get_services(),
    "open_ports": get_open_ports(),
    "timestamp": datetime.utcnow().isoformat(),
  }


def post_inventory(payload):
  headers = {"Content-Type": "application/json"}
  if AGENT_TOKEN:
    headers["X-AGENT-TOKEN"] = AGENT_TOKEN
  resp = requests.post(DASHBOARD_URL, headers=headers, data=json.dumps(payload), timeout=8)
  return resp.status_code, resp.text


def main():
  print("=" * 60)
  print("  Inventory Agent — Host Telemetry")
  print("=" * 60)
  print(f"  Agent ID : {AGENT_ID or get_hostname()}")
  print(f"  Dashboard: {DASHBOARD_URL}")
  print(f"  Interval : {INTERVAL}s")
  print("=" * 60)

  while True:
    payload = build_payload()
    try:
      code, _ = post_inventory(payload)
      status = "OK" if code in (200, 201) else f"HTTP {code}"
      print(f"[{datetime.now().isoformat(timespec='seconds')}] sent inventory: {status}")
    except Exception as exc:
      print(f"[{datetime.now().isoformat(timespec='seconds')}] send failed: {exc}")

    time.sleep(INTERVAL)


if __name__ == "__main__":
  main()
