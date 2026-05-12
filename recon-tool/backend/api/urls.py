"""api/urls.py"""
from django.urls import path
from .views import (
    HostDiscoveryView, PortScanView, OSFingerprintView,
    ARPSpoofView, SYNFloodView, StopThreadView,
    ThreadRegistryView, ThreadStatusView,
    SessionResultsView, PDFReportView, InboundAlertView,
    InventoryIngestView, InventoryLatestView,
    AgentRegistryView,
    AgentHealthView,
    InboundPacketView,
    SessionAlertsView,
    SessionPacketsView,
    MitreMappingView,
    HostRiskScoreView,
    AuditLogView,
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
    path("threads/",              ThreadRegistryView.as_view()),
    path("threads/<str:thread_id>/", ThreadStatusView.as_view()),

    # Inbound alerts from VM agents
    path("alerts/",               InboundAlertView.as_view()),
    path("packets/",              InboundPacketView.as_view()),

    # History for UI refreshes
    path("alerts/history/<str:session_id>/", SessionAlertsView.as_view()),
    path("packets/history/<str:session_id>/", SessionPacketsView.as_view()),

    # Agent inventory
    path("agents/inventory/",        InventoryIngestView.as_view()),
    path("agents/inventory/latest/", InventoryLatestView.as_view()),
    path("agents/registry/",         AgentRegistryView.as_view()),
    path("agents/health/",           AgentHealthView.as_view()),

    # MITRE mapping
    path("mitre-mapping/",         MitreMappingView.as_view()),

    # Results & reports
    path("results/<str:session_id>/",    SessionResultsView.as_view()),
    path("report/<str:session_id>/pdf/", PDFReportView.as_view()),

    # Host risk scores
    path("hosts/<str:ip>/risk-score/", HostRiskScoreView.as_view()),

    # Audit logs
    path("audit-logs/", AuditLogView.as_view()),
] + ([path("attack/icmp-redirect/", ICMPRedirectView.as_view())] if _has_icmp else [])
