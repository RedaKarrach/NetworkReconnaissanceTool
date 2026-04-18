"""api/urls.py"""
from django.urls import path
from .views import (
    HostDiscoveryView, PortScanView, OSFingerprintView,
    ARPSpoofView, SYNFloodView, StopThreadView,
    SessionResultsView, PDFReportView, InboundAlertView,
    InventoryIngestView, InventoryLatestView,
    AgentRegistryView,
    InboundPacketView,
)

try:
    from .views import ICMPRedirectView
    _has_icmp = True
except ImportError:
    _has_icmp = False

urlpatterns = [
    # Scan endpoints
    path("scan/host-discovery/",  HostDiscoveryView.as_view()),
    path("scan/port-scan/",       PortScanView.as_view()),
    path("scan/os-fingerprint/",  OSFingerprintView.as_view()),

    # Attack simulation
    path("attack/arp-spoof/",     ARPSpoofView.as_view()),
    path("attack/syn-flood/",     SYNFloodView.as_view()),
    path("attack/stop/",          StopThreadView.as_view()),

    # Inbound alerts from VM agents
    path("alerts/",               InboundAlertView.as_view()),
    path("packets/",              InboundPacketView.as_view()),

    # Agent inventory
    path("agents/inventory/",        InventoryIngestView.as_view()),
    path("agents/inventory/latest/", InventoryLatestView.as_view()),
    path("agents/registry/",         AgentRegistryView.as_view()),

    # Results & reports
    path("results/<str:session_id>/",    SessionResultsView.as_view()),
    path("report/<str:session_id>/pdf/", PDFReportView.as_view()),
] + ([path("attack/icmp-redirect/", ICMPRedirectView.as_view())] if _has_icmp else [])
