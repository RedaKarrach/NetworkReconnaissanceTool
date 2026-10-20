"""
websockets/consumers.py
-----------------------
Django Channels WebSocket consumer.

Each session gets its own group: "scan_<session_id>". A shared "scan_live"
group carries the SOC live stream and "scan_inventory" the inventory stream.

Background scan/attack worker threads call the broadcast_* helpers below. With
the Redis channel layer these cross-thread/cross-process sends are reliable
(the old InMemoryChannelLayer dropped them because its queues are bound to the
Daphne event loop).
"""
import json
import asyncio
from urllib.parse import parse_qs

from channels.generic.websocket import AsyncWebsocketConsumer
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.conf import settings

# Server → client heartbeat interval (seconds). Keeps idle connections alive
# through proxies and lets the client notice a dead socket quickly.
HEARTBEAT_INTERVAL = 20


class ScanConsumer(AsyncWebsocketConsumer):
    """
    WebSocket endpoint: ws://host/ws/scan/<session_id>/

    The frontend connects here to receive live packet/alert/event streams for a
    session (or "live" for the SOC-wide stream, "inventory" for inventory).
    """

    async def connect(self):
        self.session_id = self.scope["url_route"]["kwargs"]["session_id"]
        self.group_name = f"scan_{self.session_id}"
        self._heartbeat_task = None

        # Operator-token auth (dev bypass when API_AUTH_TOKEN is empty). The
        # browser WebSocket API cannot set headers, so the token arrives as a
        # ?token= query parameter.
        expected = getattr(settings, "API_AUTH_TOKEN", "")
        if expected:
            qs = parse_qs((self.scope.get("query_string") or b"").decode("utf-8"))
            provided = (qs.get("token", [""])[0] or "").strip()
            if provided != expected:
                await self.close(code=4401)
                return

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

        await self.send(text_data=json.dumps({
            "event_type": "connection_established",
            "session_id": self.session_id,
            "message": "Connected to live stream",
        }))

        self._heartbeat_task = asyncio.create_task(self._heartbeat())

    async def disconnect(self, close_code):
        if getattr(self, "_heartbeat_task", None):
            self._heartbeat_task.cancel()
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def _heartbeat(self):
        """Periodically ping the client so idle connections stay open."""
        try:
            while True:
                await asyncio.sleep(HEARTBEAT_INTERVAL)
                await self.send(text_data=json.dumps({"event_type": "ping"}))
        except asyncio.CancelledError:
            return
        except Exception:
            return

    async def receive(self, text_data):
        """Handle client control frames (ping/pong keepalive)."""
        try:
            data = json.loads(text_data)
        except Exception:
            return
        msg_type = str(data.get("type") or data.get("event_type") or "").lower()
        if msg_type == "ping":
            await self.send(text_data=json.dumps({"event_type": "pong"}))

    # ── Group message handlers (dots → underscores) ─────────────────────────
    async def packet_event(self, event):
        await self.send(text_data=json.dumps(event["data"]))

    async def alert_event(self, event):
        await self.send(text_data=json.dumps(event["data"]))

    async def stream_event(self, event):
        """Generic handler for event/ml_alert and any future stream types."""
        await self.send(text_data=json.dumps(event["data"]))


# ─────────────────────────────────────────────────────────────────────────────
# Utility: push events from sync worker threads into the async channel layer.
# Every helper is best-effort: a broadcast failure must never crash a worker.
# ─────────────────────────────────────────────────────────────────────────────

def _group_send(group_name: str, handler_type: str, data: dict):
    """Best-effort group_send from any synchronous thread."""
    try:
        channel_layer = get_channel_layer()
        if channel_layer is None:
            return
        async_to_sync(channel_layer.group_send)(
            group_name,
            {"type": handler_type, "data": data},
        )
    except Exception as exc:
        try:
            print(f"[websockets] group_send to {group_name} failed: {exc}")
        except Exception:
            pass


def _sanitize(data: dict, default_event_type: str) -> dict:
    """Coerce a payload into a flat, JSON-serializable, size-bounded dict."""
    from datetime import datetime as _dt

    safe = {"event_type": default_event_type}
    for k, v in (data or {}).items():
        if isinstance(v, _dt):
            safe[k] = v.isoformat()
        elif isinstance(v, (dict, list)):
            try:
                s = json.dumps(v)
            except Exception:
                s = str(v)
            safe[k] = s if len(s) <= 2000 else s[:2000] + "..."
        elif v is None or isinstance(v, (str, int, float, bool)):
            if isinstance(v, str) and len(v) > 2000:
                safe[k] = v[:2000] + "..."
            else:
                safe[k] = v
        else:
            try:
                safe[k] = str(v)
            except Exception:
                safe[k] = "<unserializable>"
    return safe


def broadcast_packet(session_id: str, packet_data: dict):
    """Send a packet event to all clients watching this session."""
    payload = {"event_type": "packet", **(packet_data or {})}
    _group_send(f"scan_{session_id}", "packet.event", payload)


def broadcast_alert(session_id: str, alert_data: dict):
    """Send a security alert to all clients watching this session."""
    payload = _sanitize(alert_data, "alert")
    _group_send(f"scan_{session_id}", "alert.event", payload)


def broadcast_event(session_id: str, event_data: dict):
    """Send a lifecycle/activity event (non-security) to a session's clients."""
    payload = _sanitize(event_data, "event")
    _group_send(f"scan_{session_id}", "stream.event", payload)


def broadcast_ml_alert(session_id: str, ml_data: dict):
    """Send a machine-learning detection to a session's clients."""
    payload = _sanitize(ml_data, "ml_alert")
    _group_send(f"scan_{session_id}", "stream.event", payload)


def broadcast_status(session_id: str, status: str, extra: dict = None):
    """Notify clients of a session status change."""
    payload = {"event_type": "status", "session_id": session_id, "status": status}
    if extra:
        payload.update(extra)
    _group_send(f"scan_{session_id}", "packet.event", payload)


def broadcast_inventory(inventory_data: dict):
    """Broadcast host inventory updates on the shared inventory stream."""
    payload = {"event_type": "inventory", **(inventory_data or {})}
    _group_send("scan_inventory", "packet.event", payload)


def broadcast_mitigation(session_id: str, data: dict):
    """Broadcast an IPS/response action to a session's clients."""
    payload = _sanitize(data, "mitigation")
    _group_send(f"scan_{session_id}", "stream.event", payload)
