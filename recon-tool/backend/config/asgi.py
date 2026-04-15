"""
config/asgi.py
--------------
ASGI entry-point that wires Django Channels into the app.
HTTP requests go to Django; WebSocket connections go to Channels consumers.
"""
import os
import django
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django.setup()

# Import routing AFTER setup to avoid AppRegistryNotReady errors
from websockets.routing import websocket_urlpatterns   # noqa: E402

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(
        URLRouter(websocket_urlpatterns)
    ),
})
