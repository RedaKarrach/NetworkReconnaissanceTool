"""
api/permissions.py
------------------
Minimal operator-token auth for the offensive (scan/attack) endpoints.

A shared token is read from settings.API_AUTH_TOKEN. The token may be supplied
as an `X-API-TOKEN` header, an `Authorization: Bearer <token>` header, or a
`?token=` query parameter (the last so a browser WebSocket, which cannot set
headers, can authenticate too).

Dev bypass: if API_AUTH_TOKEN is empty the permission allows everything. This
keeps the local lab usable out of the box; set API_AUTH_TOKEN to turn auth on.
"""
from rest_framework.permissions import BasePermission
from django.conf import settings


def extract_token(request):
    token = request.headers.get("X-API-TOKEN")
    if token:
        return token.strip()
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[len("Bearer "):].strip()
    try:
        qp = request.query_params.get("token")
    except AttributeError:
        qp = request.GET.get("token")
    return (qp or "").strip()


class OperatorTokenPermission(BasePermission):
    message = "A valid operator token is required for this action."

    def has_permission(self, request, view):
        expected = getattr(settings, "API_AUTH_TOKEN", "")
        if not expected:
            return True  # documented dev bypass: no token configured
        return extract_token(request) == expected
