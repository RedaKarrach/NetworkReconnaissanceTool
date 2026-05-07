"""
inventory_agent.py — Run on Windows or Linux VMs
=================================================
Collects Wazuh-like host inventory and POSTs it to the dashboard.

Usage:
  pip install requests psutil
  python inventory_agent.py

Config via env:
  DASHBOARD_URL=http://192.168.56.1:8000/api/agents/inventory/
  AGENT_ID=ubuntu-server
  AGENT_TOKEN=change-me
  INTERVAL=60
"""
import json
import os
import platform
import socket
import subprocess
import time
import signal
import random
import argparse
import shutil
import sys
from datetime import datetime, timezone

import requests

try:
  import psutil
except Exception:
  psutil = None

DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "http://192.168.56.1:8000/api/agents/inventory/")
AGENT_ID = os.environ.get("AGENT_ID")
AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
INTERVAL = int(os.environ.get("INTERVAL", "60"))
ONESHOT = os.environ.get("ONESHOT", "false").lower() in {"1", "true", "yes"}
AUTOSTART_NAME = os.environ.get("AUTOSTART_NAME", "ReconInventoryAgent")


def _quote_windows(arg):
  return f'"{str(arg).replace("\"", "\\\"")}"'


def _runtime_command(dashboard_url, agent_id, agent_token, interval):
  script_path = os.path.abspath(__file__)
  cmd = [sys.executable, script_path, "--dashboard-url", dashboard_url, "--interval", str(interval)]
  if agent_id:
    cmd.extend(["--agent-id", agent_id])
  if agent_token:
    cmd.extend(["--agent-token", agent_token])
  return cmd


def _windows_task_exists(name: str) -> bool:
  result = subprocess.run(["schtasks", "/Query", "/TN", name], capture_output=True, text=True)
  return result.returncode == 0


def _install_windows_task(name: str, task_run: str, trigger: str) -> None:
  create_cmd = [
    "schtasks", "/Create", "/F", "/SC", trigger,
    "/TN", name,
    "/TR", task_run,
    "/RL", "HIGHEST",
    "/RU", "SYSTEM",
    "/DELAY", "0000:30",
  ]
  completed = subprocess.run(create_cmd, capture_output=True, text=True)
  if completed.returncode != 0:
    raise RuntimeError((completed.stderr or completed.stdout or "schtasks failed").strip())


def install_autostart(dashboard_url, agent_id, agent_token, interval):
  cmd = _runtime_command(dashboard_url, agent_id, agent_token, interval)

  if os.name == "nt":
    task_run = " ".join(_quote_windows(part) for part in cmd)
    start_name = AUTOSTART_NAME
    logon_name = f"{AUTOSTART_NAME}-Logon"
    _install_windows_task(start_name, task_run, "ONSTART")
    _install_windows_task(logon_name, task_run, "ONLOGON")
    return f"Installed Windows startup tasks: {start_name}, {logon_name}"

  service_name = f"{AUTOSTART_NAME}.service"
  service_path = f"/etc/systemd/system/{service_name}"
  exec_cmd = " ".join(f'"{part}"' for part in cmd)
  service_body = "\n".join([
    "[Unit]",
    "Description=Recon Tool Inventory Agent",
    "After=network-online.target",
    "Wants=network-online.target",
    "",
    "[Service]",
    "Type=simple",
    f"ExecStart={exec_cmd}",
    "Restart=always",
    "RestartSec=5",
    "",
    "[Install]",
    "WantedBy=multi-user.target",
    "",
  ])

  try:
    with open(service_path, "w", encoding="utf-8") as handle:
      handle.write(service_body)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "enable", "--now", service_name], check=True)
  except PermissionError as exc:
    raise RuntimeError("Permission denied writing systemd service; run as root/sudo.") from exc
  except subprocess.CalledProcessError as exc:
    raise RuntimeError(f"systemctl failed: {exc}") from exc

  return f"Installed Linux systemd service: {service_name}"


def uninstall_autostart():
  if os.name == "nt":
    names = [AUTOSTART_NAME, f"{AUTOSTART_NAME}-Logon"]
    for name in names:
      subprocess.run(["schtasks", "/Delete", "/F", "/TN", name], capture_output=True, text=True)
    return f"Removed Windows startup tasks: {', '.join(names)}"

  service_name = f"{AUTOSTART_NAME}.service"
  service_path = f"/etc/systemd/system/{service_name}"
  try:
    subprocess.run(["systemctl", "disable", "--now", service_name], check=False)
    if os.path.exists(service_path):
      os.remove(service_path)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
  except PermissionError as exc:
    raise RuntimeError("Permission denied removing systemd service; run as root/sudo.") from exc
  except subprocess.CalledProcessError as exc:
    raise RuntimeError(f"systemctl failed: {exc}") from exc

  return f"Removed Linux systemd service: {service_name}"


def _autostart_installed():
  if os.name == "nt":
    start_name = AUTOSTART_NAME
    logon_name = f"{AUTOSTART_NAME}-Logon"
    return _windows_task_exists(start_name) and _windows_task_exists(logon_name)

  service_name = f"{AUTOSTART_NAME}.service"
  result = subprocess.run(["systemctl", "is-enabled", service_name],
                          capture_output=True, text=True)
  return result.returncode == 0


def get_default_agent_id():
  if os.name == "nt":
    return platform.node() or socket.gethostname() or "windows-host"
  return "ubuntu server"


def get_display_name(agent_id):
  if os.name == "nt":
    return str(agent_id or get_hostname()).strip() or "Windows Host"

  value = str(agent_id or "ubuntu server").replace("-", " ").strip()
  return value.title() if value else "Ubuntu Server"


def get_linux_os_info():
  name = "Linux"
  version = platform.version()

  try:
    os_release = {}
    if hasattr(platform, "freedesktop_os_release"):
      os_release = platform.freedesktop_os_release()
    else:
      with open("/etc/os-release", "r", encoding="utf-8") as handle:
        for line in handle:
          if "=" not in line:
            continue
          key, raw_value = line.rstrip().split("=", 1)
          os_release[key] = raw_value.strip().strip('"')

    name = os_release.get("PRETTY_NAME") or os_release.get("NAME") or name
    version = os_release.get("VERSION") or os_release.get("VERSION_ID") or version
  except Exception:
    pass

  return name, version


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
    try:
      ip = socket.gethostbyname(socket.gethostname())
      ips.append(ip)
    except Exception:
      # Best-effort fallback
      ips.append("0.0.0.0")

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
  try:
    if os.name == "nt":
      # Use system drive if available, fallback to C:\
      system_drive = os.environ.get("SystemDrive", "C:")
      path = system_drive + "\\"
      if not os.path.exists(path):
        path = "C:\\"
    else:
      # Prefer root
      path = "/"
    usage = psutil.disk_usage(path)
    return round(usage.total / (1024 ** 3), 2), round(usage.free / (1024 ** 3), 2)
  except Exception:
    return None, None


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
    # Could be permission error; report empty but log a warning
    try:
      print(f"[WARN] get_open_ports(): failed to list connections (insufficient privileges or platform restriction)")
    except Exception:
      pass
    return []
  return sorted(ports)


def get_packages():
  if os.name == "nt":
    # Query both 64-bit and 32-bit uninstall registry hives to capture all installed programs
    cmd = (
      "powershell -NoProfile -Command "
      "\"Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* , \\\n+HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* "
      "| Where-Object { $_.DisplayName } "
      "| Select-Object -ExpandProperty DisplayName\""
    )
    out = run_cmd(cmd)
    return out.splitlines()[:200] if out else []

  # Prefer using shutil.which to check command availability
  if shutil.which("dpkg-query"):
    out = run_cmd("dpkg-query -W -f='${Package}\n'")
    return out.splitlines()[:200] if out else []

  if shutil.which("rpm"):
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
  agent_id = AGENT_ID or get_default_agent_id()
  hostname = get_display_name(agent_id)
  interfaces, ips, macs = get_interfaces()
  cpu_model, cpu_cores = get_cpu_info()
  disk_total_gb, disk_free_gb = get_disk_gb()

  if os.name == "nt":
    os_name = platform.system()
    os_version = platform.version()
  else:
    os_name, os_version = get_linux_os_info()

  return {
    "agent_id": agent_id,
    "hostname": hostname,
    "os_name": os_name,
    "os_version": os_version,
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
    "timestamp": datetime.now(timezone.utc).isoformat(),
  }


def post_inventory(payload):
  headers = {"Content-Type": "application/json"}
  if AGENT_TOKEN:
    headers["X-AGENT-TOKEN"] = AGENT_TOKEN
  # Retry with small exponential backoff on transient network failures
  backoff = 1
  for attempt in range(1, 4):
    try:
      resp = requests.post(DASHBOARD_URL, headers=headers, data=json.dumps(payload), timeout=8)
      return resp.status_code, resp.text
    except Exception as exc:
      if attempt == 3:
        raise
      time.sleep(backoff)
      backoff *= 2


def main():
  global DASHBOARD_URL, AGENT_ID, AGENT_TOKEN, INTERVAL

  parser = argparse.ArgumentParser(description="Recon inventory agent")
  parser.add_argument("--interval", type=int, default=None)
  parser.add_argument("--once", action="store_true")
  parser.add_argument("--dashboard-url", default=None)
  parser.add_argument("--agent-id", default=None)
  parser.add_argument("--agent-token", default=None)
  parser.add_argument("--install-autostart", action="store_true")
  parser.add_argument("--uninstall-autostart", action="store_true")
  parser.add_argument("--ensure-autostart", action="store_true")
  args, _ = parser.parse_known_args()

  if args.dashboard_url:
    DASHBOARD_URL = args.dashboard_url
  if args.agent_id:
    AGENT_ID = args.agent_id
  if args.agent_token is not None:
    AGENT_TOKEN = args.agent_token
  if args.interval:
    INTERVAL = max(5, args.interval)

  if args.install_autostart and args.uninstall_autostart:
    print("[ERR] choose only one of --install-autostart or --uninstall-autostart")
    sys.exit(2)

  if args.install_autostart:
    try:
      message = install_autostart(DASHBOARD_URL, AGENT_ID or get_default_agent_id(), AGENT_TOKEN, INTERVAL)
      print(f"[OK] {message}")
      sys.exit(0)
    except Exception as exc:
      print(f"[ERR] {exc}")
      sys.exit(1)

  if args.uninstall_autostart:
    try:
      message = uninstall_autostart()
      print(f"[OK] {message}")
      sys.exit(0)
    except Exception as exc:
      print(f"[ERR] {exc}")
      sys.exit(1)

  ensure_autostart = args.ensure_autostart or os.environ.get("ENSURE_AUTOSTART", "").lower() in {
    "1", "true", "yes"
  }
  if ensure_autostart:
    try:
      if not _autostart_installed():
        message = install_autostart(DASHBOARD_URL, AGENT_ID or get_default_agent_id(), AGENT_TOKEN, INTERVAL)
        print(f"[OK] {message}")
    except Exception as exc:
      print(f"[ERR] Autostart install failed: {exc}")

  print("=" * 60)
  print("  Inventory Agent — Host Telemetry")
  print("=" * 60)
  print(f"  Agent ID : {AGENT_ID or get_default_agent_id()}")
  print(f"  Dashboard: {DASHBOARD_URL}")
  print(f"  Interval : {INTERVAL}s")
  print("=" * 60)

  interval = INTERVAL
  oneshot = args.once or ONESHOT

  running = True

  def _signal_handler(signum, frame):
    nonlocal running
    running = False
    print(f"[{datetime.now().isoformat(timespec='seconds')}] received stop signal ({signum}), exiting gracefully...")

  try:
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
  except Exception:
    # Some platforms (e.g., Windows) may behave differently; ignore if unsupported
    pass

  while running:
    payload = build_payload()
    try:
      code, _ = post_inventory(payload)
      status = "OK" if code in (200, 201) else f"HTTP {code}"
      print(f"[{datetime.now().isoformat(timespec='seconds')}] sent inventory: {status}")
    except Exception as exc:
      print(f"[{datetime.now().isoformat(timespec='seconds')}] send failed: {exc}")

    if oneshot:
      break

    # Add small jitter to avoid synchronization storms when many agents run
    jitter = random.uniform(-0.1, 0.1) * max(1, interval)
    sleep_time = max(1, interval + jitter)
    slept = 0
    while running and slept < sleep_time:
      time.sleep(1)
      slept += 1


if __name__ == "__main__":
  main()
