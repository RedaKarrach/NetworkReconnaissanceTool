"""
websockets/consumers.py
-----------------------
Django Channels WebSocket consumer.

Each session gets its own group: "scan_<session_id>"
When a background scan/attack thread produces a packet event, it calls
`broadcast_packet()` which sends to the group — all connected clients receive it.
"""
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync


class ScanConsumer(AsyncWebsocketConsumer):
    """
    WebSocket endpoint: ws://host/ws/scan/<session_id>/

    The frontend connects here to receive live packet events for a session.
    """

    async def connect(self):
        self.session_id  = self.scope["url_route"]["kwargs"]["session_id"]
        self.group_name  = f"scan_{self.session_id}"

        # Join the session's channel group
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )
        await self.accept()

        await self.send(text_data=json.dumps({
            "type": "connection_established",
            "session_id": self.session_id,
            "message": "Connected to packet stream"
        }))

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )

    # Receive message from WebSocket client (e.g. ping or control message)
    async def receive(self, text_data):
        data = json.loads(text_data)
        # Echo back for acknowledgement
        await self.send(text_data=json.dumps({
            "type": "ack",
            "received": data
        }))

    # Handler for messages sent to the group via channel layer
    async def packet_event(self, event):
        """Called when broadcast_packet() pushes to this group."""
        await self.send(text_data=json.dumps(event["data"]))

    async def alert_event(self, event):
        """Called when broadcast_alert() pushes to this group."""
        await self.send(text_data=json.dumps(event["data"]))


# ─────────────────────────────────────────────────────────────────────────────
# Utility: push events from sync threads into the async channel layer
# ─────────────────────────────────────────────────────────────────────────────

def broadcast_packet(session_id: str, packet_data: dict):
    """
    Send a packet event to all WebSocket clients watching this session.
    Safe to call from any synchronous thread.
    """
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f"scan_{session_id}",
        {
            "type": "packet.event",   # maps to packet_event handler (dots→underscores)
            "data": {
                "event_type": "packet",
                **packet_data
            }
        }
    )


def broadcast_alert(session_id: str, alert_data: dict):
    """Send an alert event to all WebSocket clients watching this session."""
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f"scan_{session_id}",
        {
            "type": "alert.event",
            "data": {
                "event_type": "alert",
                **alert_data
            }
        }
    )


def broadcast_status(session_id: str, status: str, extra: dict = None):
    """Notify clients of a session status change."""
    channel_layer = get_channel_layer()
    payload = {"event_type": "status", "session_id": session_id, "status": status}
    if extra:
        payload.update(extra)
    async_to_sync(channel_layer.group_send)(
        f"scan_{session_id}",
        {"type": "packet.event", "data": payload}
    )
