"""
api/views.py  (v2 — with detection + ICMP redirect endpoint)
-------------------------------------------------------------
REST API views — each endpoint launches a background thread and returns
a session/thread ID immediately so the frontend can subscribe via WebSocket.
"""
import uuid
import json
import threading
from datetime import datetime

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from models import ScanSession, Host, PortResult, Alert, PacketLog, AttackLog
from threads.manager import start_thread, stop_thread, get_status
from websockets.consumers import broadcast_packet, broadcast_alert, broadcast_status

# Import scanner modules
from scanner.discovery   import arp_sweep
from scanner.portscan    import run_port_scan
from scanner.fingerprint import fingerprint_os
from scanner.attacks     import arp_spoof, syn_flood, icmp_redirect

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
                broadcast_packet(session_id, {
                    "event_type": "host_found",
                    "ip": ip, "mac": mac,
                    "timestamp": datetime.utcnow().isoformat()
                })

            def on_pkt(pkt_dict):
                _log_packet(session, pkt_dict)

            arp_sweep(subnet, stop_flag, session_id,
                      on_host=on_host, on_packet=on_pkt)

            session.status = "complete"
            session.save()
            broadcast_status(session_id, "complete",
                             {"message": "Host discovery finished"})

        thread_id = start_thread(target=_run, name=f"discovery-{session_id}")

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
                broadcast_packet(session_id, {
                    "event_type": "port_result",
                    "ip": ip,
                    "port": res["port"],
                    "status": res["status"],
                    "banner": res.get("banner", ""),
                    "timestamp": datetime.utcnow().isoformat()
                })

            def on_pkt(pkt_dict):
                _log_packet(session, pkt_dict)

            run_port_scan(ip, ports, stop_flag, session_id,
                          protocol=protocol,
                          on_result=on_result, on_packet=on_pkt)

            session.status = "complete"
            session.save()
            broadcast_status(session_id, "complete",
                             {"message": "Port scan finished"})

        thread_id = start_thread(target=_run, name=f"portscan-{ip}")

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

            broadcast_packet(session_id, {
                "event_type":   "os_result",
                "ip":           ip,
                "os_guess":     result["os_guess"],
                "confidence":   result["confidence"],
                "ttl":          result["ttl"],
                "window_size":  result["window_size"],
                "xmas_result":  result["xmas_result"],
                "details":      result["details"],
                "timestamp":    datetime.utcnow().isoformat()
            })

            session.status = "complete"
            session.save()
            broadcast_status(session_id, "complete",
                             {"message": "OS fingerprint complete"})

        thread_id = start_thread(target=_run, name=f"osfp-{ip}")

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

            syn_flood(target_ip, target_port, stop_flag, on_packet=on_pkt)

            attack_log.status     = "stopped"
            attack_log.stopped_at = datetime.utcnow()
            attack_log.save()
            broadcast_status(session_id, "stopped",
                             {"message": "SYN flood stopped"})

        thread_id = start_thread(target=_run, name=f"syn-flood-{target_ip}")

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
        # Reuse the current running session or create a live one
        session = ScanSession.objects(status="running").first()
        if not session:
            import uuid as _uuid
            session = ScanSession(
                session_id = str(_uuid.uuid4()),
                subnet     = "192.168.56.0/24",
                status     = "running",
            )
            session.save()

        alert = Alert(
            session  = session,
            type     = request.data.get("type",     "unknown"),
            src_ip   = request.data.get("src_ip",   ""),
            dst_ip   = request.data.get("dst_ip",   ""),
            severity = request.data.get("severity", "low"),
            message  = request.data.get("message",  ""),
        )
        alert.save()

        # Broadcast immediately to all WebSocket clients
        broadcast_alert(session.session_id, {
            "event_type": "alert",
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
