"""
api/views.py  (v2 — with detection + ICMP redirect endpoint)
-------------------------------------------------------------
REST API views — each endpoint launches a background thread and returns
a session/thread ID immediately so the frontend can subscribe via WebSocket.
"""
import uuid
import json
import threading
import platform
import subprocess
import ipaddress
from datetime import datetime

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings

from models import ScanSession, Host, PortResult, Alert, PacketLog, AttackLog, HostInventory, AgentRegistry
from threads.manager import start_thread, stop_thread, get_status
from websockets.consumers import broadcast_packet, broadcast_alert, broadcast_status, broadcast_inventory

# Import scanner modules
from scanner.discovery   import arp_sweep
from scanner.portscan    import run_port_scan
from scanner.fingerprint import fingerprint_os
from scanner.attacks     import arp_spoof, syn_flood, icmp_redirect
from scanner import detection

# PDF report
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import io
from django.http import HttpResponse


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _new_session(subnet=""):
    sid = str(uuid.uuid4())
    session = ScanSession(session_id=sid, subnet=subnet, status="running")
    session.save()
    return session, sid


def _log_packet(session, pkt_dict):
    """Persist a packet event to MongoDB and push to WebSocket."""
    PacketLog(
        session   = session,
        summary   = pkt_dict.get("summary", ""),
        flags     = pkt_dict.get("flags", ""),
        ttl       = pkt_dict.get("ttl", 0),
        src_ip    = pkt_dict.get("src_ip", ""),
        dst_ip    = pkt_dict.get("dst_ip", ""),
        protocol  = pkt_dict.get("protocol", ""),
    ).save()
    broadcast_packet(session.session_id, pkt_dict)
    broadcast_packet("live", pkt_dict)


def _emit_alert(session, alert_dict):
    """Broadcast alert to session and live SOC stream."""
    payload = {
        "event_type": "alert",
        **alert_dict,
    }
    broadcast_alert(session.session_id, payload)
    broadcast_alert("live", payload)


def _get_live_session():
    session = ScanSession.objects(session_id="live").first()
    if not session:
        session = ScanSession(session_id="live", subnet="", status="running")
        session.save()
    return session


def _check_agent_token(request):
    """Optional shared-token check for agent POSTs."""
    expected = getattr(settings, "AGENT_TOKEN", "")
    if not expected:
        return True

    header_token = request.headers.get("X-AGENT-TOKEN")
    auth_header = request.headers.get("Authorization", "")
    bearer_token = auth_header.replace("Bearer ", "") if auth_header.startswith("Bearer ") else ""
    return header_token == expected or bearer_token == expected


def _is_ip_reachable(ip: str) -> bool:
    """Best-effort ICMP reachability check from the server container."""
    if not ip:
        return False

    if platform.system().lower().startswith("win"):
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    try:
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        return result.returncode == 0
    except Exception:
        return False


def _has_recent_inventory(ip: str) -> bool:
    """Treat IP as reachable if an agent reported inventory recently."""
    try:
        inv = HostInventory.objects(ips=ip).order_by("-last_seen").first()
        if not inv:
            return False
        age = datetime.utcnow() - inv.last_seen
        return age.total_seconds() < 300
    except Exception:
        return False


def _is_registered_agent_ip(ip: str) -> bool:
    try:
        return AgentRegistry.objects(ip=ip).first() is not None
    except Exception:
        return False


def _is_ip_allowed(ip: str) -> bool:
    """Restrict scan targets to a configured subnet if provided."""
    allowed = getattr(settings, "SCAN_ALLOWED_SUBNET", "")
    if not allowed:
        return True
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(allowed, strict=False)
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# 1. Host Discovery
# ─────────────────────────────────────────────────────────────────────────────

class HostDiscoveryView(APIView):
    """POST /api/scan/host-discovery/  { "subnet": "192.168.56.0/24" }"""

    def post(self, request):
        subnet = request.data.get("subnet")
        if not subnet:
            return Response({"error": "subnet required"}, status=400)

        session, session_id = _new_session(subnet=subnet)

        def _run(stop_flag):
            def on_host(ip, mac):
                host = Host(session=session, ip=ip, mac=mac)
                host.save()
                packet = {
                    "event_type": "host_found",
                    "ip": ip, "mac": mac,
                    "timestamp": datetime.utcnow().isoformat()
                }
                broadcast_packet(session_id, packet)
                broadcast_packet("live", packet)
                detection.check_arp(session, ip, mac, on_alert=lambda a: _emit_alert(session, a))

            def on_pkt(pkt_dict):
                _log_packet(session, pkt_dict)

            arp_sweep(subnet, stop_flag, session_id,
                      on_host=on_host, on_packet=on_pkt)

            session.status = "complete"
            session.save()
            broadcast_status(session_id, "complete",
                             {"message": "Host discovery finished"})
            _emit_alert(session, {
                "type": "host_discovery_complete",
                "src_ip": "scanner",
                "dst_ip": subnet,
                "severity": "low",
                "message": f"Host discovery completed for {subnet}",
                "timestamp": datetime.utcnow().isoformat(),
            })

        thread_id = start_thread(target=_run, name=f"discovery-{session_id}")

        _emit_alert(session, {
            "type": "host_discovery_start",
            "src_ip": "scanner",
            "dst_ip": subnet,
            "severity": "low",
            "message": f"Host discovery started for {subnet}",
            "timestamp": datetime.utcnow().isoformat(),
        })

        return Response({
            "session_id": session_id,
            "thread_id":  thread_id,
            "subnet":     subnet,
            "status":     "running"
        }, status=202)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Port Scan
# ─────────────────────────────────────────────────────────────────────────────

class PortScanView(APIView):
    """POST /api/scan/port-scan/  { "ip": "...", "ports": [22,80,443], "protocol": "tcp" }"""

    def post(self, request):
        ip       = request.data.get("ip")
        ports    = request.data.get("ports", list(range(1, 1025)))
        protocol = request.data.get("protocol", "tcp")

        if not ip:
            return Response({"error": "ip required"}, status=400)

        if not _is_ip_allowed(ip):
            return Response({"error": "ip not in allowed subnet"}, status=400)

        if not (_is_registered_agent_ip(ip) or _has_recent_inventory(ip) or _is_ip_reachable(ip)):
            return Response({"error": "ip unreachable"}, status=400)

        session, session_id = _new_session()

        # Find or create a Host record for this IP
        host_doc = Host.objects(session=session, ip=ip).first()
        if not host_doc:
            host_doc = Host(session=session, ip=ip)
            host_doc.save()

        def _run(stop_flag):
            def on_result(res):
                PortResult(
                    host     = host_doc,
                    port     = res["port"],
                    protocol = res["protocol"],
                    status   = res["status"],
                    banner   = res.get("banner", "")
                ).save()
                packet = {
                    "event_type": "port_result",
                    "ip": ip,
                    "port": res["port"],
                    "status": res["status"],
                    "banner": res.get("banner", ""),
                    "timestamp": datetime.utcnow().isoformat()
                }
                broadcast_packet(session_id, packet)
                broadcast_packet("live", packet)
                detection.check_port_sweep(session, "scanner", res["port"], on_alert=lambda a: _emit_alert(session, a))

            def on_pkt(pkt_dict):
                _log_packet(session, pkt_dict)

            run_port_scan(ip, ports, stop_flag, session_id,
                          protocol=protocol,
                          on_result=on_result, on_packet=on_pkt)

            session.status = "complete"
            session.save()
            broadcast_status(session_id, "complete",
                             {"message": "Port scan finished"})
            _emit_alert(session, {
                "type": "port_scan_complete",
                "src_ip": "scanner",
                "dst_ip": ip,
                "severity": "low",
                "message": f"Port scan completed for {ip}",
                "timestamp": datetime.utcnow().isoformat(),
            })

        thread_id = start_thread(target=_run, name=f"portscan-{ip}")

        _emit_alert(session, {
            "type": "port_scan_start",
            "src_ip": "scanner",
            "dst_ip": ip,
            "severity": "low",
            "message": f"Port scan started for {ip} ({len(ports)} ports)",
            "timestamp": datetime.utcnow().isoformat(),
        })

        return Response({
            "session_id": session_id,
            "thread_id":  thread_id,
            "ip":         ip,
            "protocol":   protocol,
            "port_count": len(ports),
            "status":     "running"
        }, status=202)


# ─────────────────────────────────────────────────────────────────────────────
# 3. OS Fingerprint
# ─────────────────────────────────────────────────────────────────────────────

class OSFingerprintView(APIView):
    """POST /api/scan/os-fingerprint/  { "ip": "..." }"""

    def post(self, request):
        ip = request.data.get("ip")
        if not ip:
            return Response({"error": "ip required"}, status=400)

        if not _is_ip_allowed(ip):
            return Response({"error": "ip not in allowed subnet"}, status=400)

        if not (_is_registered_agent_ip(ip) or _has_recent_inventory(ip) or _is_ip_reachable(ip)):
            return Response({"error": "ip unreachable"}, status=400)

        session, session_id = _new_session()

        def _run(stop_flag):
            def on_pkt(pkt_dict):
                _log_packet(session, pkt_dict)

            result = fingerprint_os(ip, stop_flag=stop_flag, on_packet=on_pkt)

            # Persist result
            host_doc = Host.objects(session=session, ip=ip).first()
            if not host_doc:
                host_doc = Host(session=session, ip=ip)
            host_doc.os_guess   = result["os_guess"]
            host_doc.confidence = result["confidence"]
            host_doc.save()

            packet = {
                "event_type":   "os_result",
                "ip":           ip,
                "os_guess":     result["os_guess"],
                "confidence":   result["confidence"],
                "ttl":          result["ttl"],
                "window_size":  result["window_size"],
                "xmas_result":  result["xmas_result"],
                "details":      result["details"],
                "timestamp":    datetime.utcnow().isoformat()
            }
            broadcast_packet(session_id, packet)
            broadcast_packet("live", packet)

            session.status = "complete"
            session.save()
            broadcast_status(session_id, "complete",
                             {"message": "OS fingerprint complete"})
            _emit_alert(session, {
                "type": "os_fingerprint_complete",
                "src_ip": "scanner",
                "dst_ip": ip,
                "severity": "low",
                "message": f"OS fingerprint completed for {ip}",
                "timestamp": datetime.utcnow().isoformat(),
            })

        thread_id = start_thread(target=_run, name=f"osfp-{ip}")

        _emit_alert(session, {
            "type": "os_fingerprint_start",
            "src_ip": "scanner",
            "dst_ip": ip,
            "severity": "low",
            "message": f"OS fingerprint started for {ip}",
            "timestamp": datetime.utcnow().isoformat(),
        })

        return Response({
            "session_id": session_id,
            "thread_id":  thread_id,
            "ip":         ip,
            "status":     "running"
        }, status=202)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Attack: ARP Spoof
# ─────────────────────────────────────────────────────────────────────────────

class ARPSpoofView(APIView):
    """POST /api/attack/arp-spoof/  { "target_ip": "...", "gateway_ip": "..." }"""

    def post(self, request):
        target_ip  = request.data.get("target_ip")
        gateway_ip = request.data.get("gateway_ip")
        if not target_ip or not gateway_ip:
            return Response({"error": "target_ip and gateway_ip required"}, status=400)

        session, session_id = _new_session()

        attack_log = AttackLog(
            session     = session,
            attack_type = "arp_spoof",
            target_ip   = target_ip,
            params      = json.dumps({"gateway_ip": gateway_ip}),
            status      = "running"
        )
        attack_log.save()

        def _run(stop_flag):
            def on_pkt(pkt_dict):
                attack_log.packets_sent += 1
                attack_log.save()
                _log_packet(session, pkt_dict)

            arp_spoof(target_ip, gateway_ip, stop_flag, on_packet=on_pkt)

            attack_log.status     = "stopped"
            attack_log.stopped_at = datetime.utcnow()
            attack_log.save()
            broadcast_status(session_id, "stopped",
                             {"message": "ARP spoof stopped"})

        thread_id = start_thread(target=_run, name=f"arp-spoof-{target_ip}")

        _emit_alert(session, {
            "type": "arp_spoof",
            "src_ip": "attacker",
            "dst_ip": target_ip,
            "severity": "high",
            "message": f"ARP spoof started against {target_ip} via {gateway_ip}",
            "timestamp": datetime.utcnow().isoformat(),
        })

        return Response({
            "session_id": session_id,
            "thread_id":  thread_id,
            "target_ip":  target_ip,
            "gateway_ip": gateway_ip,
            "status":     "running"
        }, status=202)


# ─────────────────────────────────────────────────────────────────────────────
# 5. Attack: SYN Flood
# ─────────────────────────────────────────────────────────────────────────────

class SYNFloodView(APIView):
    """POST /api/attack/syn-flood/  { "target_ip": "...", "target_port": 80 }"""

    def post(self, request):
        target_ip   = request.data.get("target_ip")
        target_port = int(request.data.get("target_port", 80))
        if not target_ip:
            return Response({"error": "target_ip required"}, status=400)

        session, session_id = _new_session()

        attack_log = AttackLog(
            session     = session,
            attack_type = "syn_flood",
            target_ip   = target_ip,
            params      = json.dumps({"target_port": target_port}),
        )
        attack_log.save()

        def _run(stop_flag):
            def on_pkt(pkt_dict):
                attack_log.packets_sent += 1
                attack_log.save()
                _log_packet(session, pkt_dict)
                detection.check_syn_flood(session, target_ip, target_port, on_alert=lambda a: _emit_alert(session, a))

            syn_flood(target_ip, target_port, stop_flag, on_packet=on_pkt)

            attack_log.status     = "stopped"
            attack_log.stopped_at = datetime.utcnow()
            attack_log.save()
            broadcast_status(session_id, "stopped",
                             {"message": "SYN flood stopped"})

        thread_id = start_thread(target=_run, name=f"syn-flood-{target_ip}")

        _emit_alert(session, {
            "type": "syn_flood",
            "src_ip": "spoofed",
            "dst_ip": target_ip,
            "severity": "critical",
            "message": f"SYN flood started against {target_ip}:{target_port}",
            "timestamp": datetime.utcnow().isoformat(),
        })

        return Response({
            "session_id":  session_id,
            "thread_id":   thread_id,
            "target_ip":   target_ip,
            "target_port": target_port,
            "status":      "running"
        }, status=202)


# ─────────────────────────────────────────────────────────────────────────────
# 6. Stop any thread
# ─────────────────────────────────────────────────────────────────────────────

class StopThreadView(APIView):
    """POST /api/attack/stop/  { "thread_id": "..." }"""

    def post(self, request):
        thread_id = request.data.get("thread_id")
        if not thread_id:
            return Response({"error": "thread_id required"}, status=400)

        stopped = stop_thread(thread_id)
        return Response({
            "thread_id": thread_id,
            "stopped":   stopped
        })


# ─────────────────────────────────────────────────────────────────────────────
# 6b. Agent inventory ingestion
# ─────────────────────────────────────────────────────────────────────────────

class InventoryIngestView(APIView):
    """POST /api/agents/inventory/  { inventory payload }"""

    def post(self, request):
        if not _check_agent_token(request):
            return Response({"error": "unauthorized"}, status=401)

        data = request.data or {}
        agent_id = data.get("agent_id") or data.get("hostname")
        if not agent_id:
            return Response({"error": "agent_id or hostname required"}, status=400)

        def _limit_list(value, max_items=200):
            if not isinstance(value, list):
                return []
            return value[:max_items]

        inventory = HostInventory.objects(agent_id=agent_id).first()
        if not inventory:
            inventory = HostInventory(agent_id=agent_id)

        inventory.hostname     = data.get("hostname")
        inventory.os_name      = data.get("os_name")
        inventory.os_version   = data.get("os_version")
        inventory.kernel       = data.get("kernel")
        inventory.arch         = data.get("arch")
        inventory.domain       = data.get("domain")
        inventory.ips          = _limit_list(data.get("ips"), 64)
        inventory.macs         = _limit_list(data.get("macs"), 64)
        inventory.interfaces   = _limit_list(data.get("interfaces"), 64)
        inventory.cpu_model    = data.get("cpu_model")
        inventory.cpu_cores    = data.get("cpu_cores")
        inventory.ram_mb       = data.get("ram_mb")
        inventory.disk_total_gb = data.get("disk_total_gb")
        inventory.disk_free_gb  = data.get("disk_free_gb")
        inventory.uptime_sec   = data.get("uptime_sec")
        inventory.users        = _limit_list(data.get("users"), 200)
        inventory.packages     = _limit_list(data.get("packages"), 500)
        inventory.services     = _limit_list(data.get("services"), 300)
        inventory.open_ports   = _limit_list(data.get("open_ports"), 200)
        inventory.last_seen    = datetime.utcnow()
        inventory.save()

        payload = {
            "agent_id": agent_id,
            "hostname": inventory.hostname,
            "os_name": inventory.os_name,
            "os_version": inventory.os_version,
            "arch": inventory.arch,
            "ips": inventory.ips,
            "macs": inventory.macs,
            "cpu_model": inventory.cpu_model,
            "cpu_cores": inventory.cpu_cores,
            "ram_mb": inventory.ram_mb,
            "disk_total_gb": inventory.disk_total_gb,
            "disk_free_gb": inventory.disk_free_gb,
            "uptime_sec": inventory.uptime_sec,
            "last_seen": inventory.last_seen.isoformat(),
        }
        broadcast_inventory(payload)

        return Response({"status": "ok", "agent_id": agent_id}, status=201)


class InventoryLatestView(APIView):
    """GET /api/agents/inventory/latest/"""

    def get(self, request):
        items = HostInventory.objects.order_by("-last_seen")
        limit = int(request.query_params.get("limit", 50))
        limit = min(max(limit, 1), 200)

        payload = []
        for inv in items[:limit]:
            payload.append({
                "agent_id": inv.agent_id,
                "hostname": inv.hostname,
                "os_name": inv.os_name,
                "os_version": inv.os_version,
                "kernel": inv.kernel,
                "arch": inv.arch,
                "domain": inv.domain,
                "ips": inv.ips,
                "macs": inv.macs,
                "interfaces": inv.interfaces,
                "cpu_model": inv.cpu_model,
                "cpu_cores": inv.cpu_cores,
                "ram_mb": inv.ram_mb,
                "disk_total_gb": inv.disk_total_gb,
                "disk_free_gb": inv.disk_free_gb,
                "uptime_sec": inv.uptime_sec,
                "users": inv.users,
                "packages": inv.packages,
                "services": inv.services,
                "open_ports": inv.open_ports,
                "last_seen": inv.last_seen.isoformat(),
            })

        return Response({"items": payload})


# ─────────────────────────────────────────────────────────────────────────────
# 6c. Agent registry (manual UI entries)
# ─────────────────────────────────────────────────────────────────────────────

class AgentRegistryView(APIView):
    """GET/POST /api/agents/registry/"""

    def get(self, request):
        items = AgentRegistry.objects.order_by("-created_at")
        payload = []
        for a in items:
            payload.append({
                "agent_id": a.agent_id,
                "hostname": a.hostname,
                "ip": a.ip,
                "os_name": a.os_name,
                "notes": a.notes,
                "created_at": a.created_at.isoformat(),
            })
        return Response({"items": payload})

    def post(self, request):
        data = request.data or {}
        agent_id = data.get("agent_id")
        if not agent_id:
            return Response({"error": "agent_id required"}, status=400)

        existing = AgentRegistry.objects(agent_id=agent_id).first()
        if existing:
            return Response({"error": "agent_id already exists"}, status=409)

        ip = data.get("ip")
        if ip and AgentRegistry.objects(ip=ip).first():
            return Response({"error": "ip already exists"}, status=409)

        agent = AgentRegistry(
            agent_id=agent_id,
            hostname=data.get("hostname"),
            ip=ip,
            os_name=data.get("os_name"),
            notes=data.get("notes"),
        )
        agent.save()

        return Response({"status": "ok", "agent_id": agent_id}, status=201)

    def delete(self, request):
        data = request.data or {}
        agent_id = data.get("agent_id")
        ip = data.get("ip")

        if not agent_id and not ip:
            return Response({"error": "agent_id or ip required"}, status=400)

        query = {}
        if agent_id:
            query["agent_id"] = agent_id
        if ip:
            query["ip"] = ip

        agent = AgentRegistry.objects(**query).first()
        if not agent:
            return Response({"error": "agent not found"}, status=404)

        agent.delete()
        return Response({"status": "deleted"})


# ─────────────────────────────────────────────────────────────────────────────
# 7. Session results
# ─────────────────────────────────────────────────────────────────────────────

class SessionResultsView(APIView):
    """GET /api/results/<session_id>/"""

    def get(self, request, session_id):
        session = ScanSession.objects(session_id=session_id).first()
        if not session:
            return Response({"error": "session not found"}, status=404)

        hosts = Host.objects(session=session)
        host_data = []
        for h in hosts:
            ports = PortResult.objects(host=h)
            host_data.append({
                "ip":         h.ip,
                "mac":        h.mac,
                "os_guess":   h.os_guess,
                "confidence": h.confidence,
                "ports": [
                    {
                        "port":     p.port,
                        "protocol": p.protocol,
                        "status":   p.status,
                        "banner":   p.banner
                    }
                    for p in ports
                ]
            })

        alerts = Alert.objects(session=session)
        packets = PacketLog.objects(session=session).limit(500)

        return Response({
            "session_id": session_id,
            "subnet":     session.subnet,
            "status":     session.status,
            "timestamp":  session.timestamp.isoformat(),
            "hosts":      host_data,
            "alerts": [
                {
                    "type":      a.type,
                    "src_ip":    a.src_ip,
                    "dst_ip":    a.dst_ip,
                    "severity":  a.severity,
                    "message":   a.message,
                    "timestamp": a.timestamp.isoformat()
                }
                for a in alerts
            ],
            "packet_count": packets.count()
        })


# ─────────────────────────────────────────────────────────────────────────────
# 8. PDF Report export
# ─────────────────────────────────────────────────────────────────────────────

class PDFReportView(APIView):
    """GET /api/report/<session_id>/pdf/"""

    def get(self, request, session_id):
        session = ScanSession.objects(session_id=session_id).first()
        if not session:
            return Response({"error": "session not found"}, status=404)

        buffer = io.BytesIO()
        doc    = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story  = []

        story.append(Paragraph("Network Recon Report", styles["Title"]))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"Session: {session_id}", styles["Normal"]))
        story.append(Paragraph(f"Subnet:  {session.subnet}", styles["Normal"]))
        story.append(Paragraph(f"Status:  {session.status}", styles["Normal"]))
        story.append(Paragraph(f"Time:    {session.timestamp.isoformat()}", styles["Normal"]))
        story.append(Spacer(1, 20))

        hosts = Host.objects(session=session)
        story.append(Paragraph("Discovered Hosts", styles["Heading2"]))

        table_data = [["IP", "MAC", "OS Guess", "Confidence"]]
        for h in hosts:
            table_data.append([
                h.ip or "", h.mac or "",
                h.os_guess or "unknown",
                f"{int((h.confidence or 0) * 100)}%"
            ])

        t = Table(table_data, colWidths=[120, 140, 160, 80])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("GRID",       (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
        ]))
        story.append(t)
        story.append(Spacer(1, 20))

        # Alerts section
        alerts = Alert.objects(session=session)
        if alerts:
            story.append(Paragraph("Alerts", styles["Heading2"]))
            alert_data = [["Type", "Src IP", "Dst IP", "Severity", "Timestamp"]]
            for a in alerts:
                alert_data.append([
                    a.type or "", a.src_ip or "", a.dst_ip or "",
                    a.severity or "", a.timestamp.isoformat()
                ])
            at = Table(alert_data, colWidths=[100, 110, 110, 80, 100])
            at.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.red),
                ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
                ("GRID",       (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            story.append(at)

        doc.build(story)
        buffer.seek(0)

        response = HttpResponse(buffer, content_type="application/pdf")
        response["Content-Disposition"] = (
            f'attachment; filename="recon-report-{session_id[:8]}.pdf"'
        )
        return response


# ─────────────────────────────────────────────────────────────────────────────
# 10. Inbound alerts from VM agents (victim_agent.py)
# ─────────────────────────────────────────────────────────────────────────────

class InboundAlertView(APIView):
    """
    POST /api/alerts/
    Called by victim_agent.py running on the Windows VM.
    Saves the alert to MongoDB and broadcasts it via WebSocket
    to the live dashboard.

    Expected body:
    {
        "agent":    "win-victim",
        "type":     "syn_flood" | "arp_anomaly" | "port_sweep",
        "src_ip":   "192.168.56.10",
        "dst_ip":   "192.168.56.20",
        "severity": "low" | "medium" | "high" | "critical",
        "message":  "Human readable description"
    }
    """
    def post(self, request):
        session = _get_live_session()

        alert = Alert(
            session  = session,
            type     = request.data.get("type",     "unknown"),
            src_ip   = request.data.get("src_ip",   ""),
            dst_ip   = request.data.get("dst_ip",   ""),
            severity = request.data.get("severity", "low"),
            message  = request.data.get("message",  ""),
        )
        alert.save()

        _emit_alert(session, {
            "agent":      request.data.get("agent", "unknown"),
            "type":       alert.type,
            "src_ip":     alert.src_ip,
            "dst_ip":     alert.dst_ip,
            "severity":   alert.severity,
            "message":    alert.message,
            "timestamp":  alert.timestamp.isoformat(),
        })

        return Response({
            "status":     "ok",
            "session_id": session.session_id,
            "alert_id":   str(alert.id),
        }, status=201)


# ─────────────────────────────────────────────────────────────────────────────
# 11. Inbound packet events from VM agents
# ─────────────────────────────────────────────────────────────────────────────

class InboundPacketView(APIView):
    """POST /api/packets/  { packet summary }"""

    def post(self, request):
        session = _get_live_session()

        pkt = {
            "summary":  request.data.get("summary", ""),
            "flags":    request.data.get("flags", ""),
            "ttl":      request.data.get("ttl", 0),
            "src_ip":   request.data.get("src_ip", ""),
            "dst_ip":   request.data.get("dst_ip", ""),
            "protocol": request.data.get("protocol", ""),
            "timestamp": request.data.get("timestamp", datetime.utcnow().isoformat()),
        }

        PacketLog(
            session   = session,
            summary   = pkt["summary"],
            flags     = pkt["flags"],
            ttl       = pkt["ttl"],
            src_ip    = pkt["src_ip"],
            dst_ip    = pkt["dst_ip"],
            protocol  = pkt["protocol"],
        ).save()

        broadcast_packet("live", pkt)

        return Response({"status": "ok"}, status=201)
