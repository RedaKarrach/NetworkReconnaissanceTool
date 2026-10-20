"""
backend/tests/smoke_ws.py
-------------------------
Smoke test for the real-time fix (Phase 1).

It reproduces the exact failure mode: a broadcast issued with async_to_sync from
a background worker thread must reach a websocket group subscriber. With the old
InMemoryChannelLayer this message was dropped; with the Redis channel layer it
is delivered.

Requires a running Redis (REDIS_URL, default redis://localhost:6379/0). Run it
against the real layer — NOT the in-memory fallback:

    cd recon-tool/backend
    REDIS_URL=redis://localhost:6379/0 python tests/smoke_ws.py

Exit code 0 and "PASS" on success; non-zero on failure/timeout.
"""
import asyncio
import os
import sys
import threading

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

# Allow `python tests/smoke_ws.py` from the backend dir.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import django  # noqa: E402
django.setup()

from channels.layers import get_channel_layer  # noqa: E402


async def main():
    layer = get_channel_layer()
    layer_name = type(layer).__name__
    if layer_name == "InMemoryChannelLayer":
        print("WARNING: using InMemoryChannelLayer — cross-thread delivery is "
              "expected to FAIL. Point REDIS_URL at a running Redis to validate "
              "the real fix.")

    group = "scan_smoketest"
    channel = await layer.new_channel()
    await layer.group_add(group, channel)

    # Broadcast from a worker thread — the real-world path that used to drop.
    def worker():
        from websockets.consumers import broadcast_alert
        broadcast_alert("smoketest", {
            "type": "smoke_test",
            "message": "worker-thread broadcast",
            "src_ip": "192.168.56.5",
            "dst_ip": "192.168.56.10",
            "severity": "high",
        })

    t = threading.Thread(target=worker)
    t.start()
    t.join()

    try:
        msg = await asyncio.wait_for(layer.receive(channel), timeout=5.0)
    except asyncio.TimeoutError:
        print(f"FAIL: no message received over {layer_name} within 5s "
              "(worker-thread broadcast was dropped)")
        return 1

    data = msg.get("data", {})
    if data.get("type") == "smoke_test" and data.get("event_type") == "alert":
        print(f"PASS: worker-thread broadcast delivered via {layer_name}")
        return 0

    print(f"FAIL: unexpected message: {msg}")
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
