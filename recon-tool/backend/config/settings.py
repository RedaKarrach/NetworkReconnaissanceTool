"""
config/settings.py
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-secret-key-change-me")
DEBUG      = os.environ.get("DEBUG", "True") == "True"
AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "")
SCAN_ALLOWED_SUBNET = os.environ.get("SCAN_ALLOWED_SUBNET", "192.168.56.0/24")

# Operator token for scan/attack endpoints and the WebSocket.
# Leave empty to disable auth (documented dev bypass for the local lab).
API_AUTH_TOKEN = os.environ.get("API_AUTH_TOKEN", "")

# IPS response layer. Off by default: confirmed detections are recorded as
# "would_block" recommendations only; nothing on the network is touched.
# Real enforcement is lab-only — see docs/ARCHITECTURE.md.
IPS_ENFORCE = os.environ.get("IPS_ENFORCE", "false").strip().lower() in {"1", "true", "yes"}

# Classic-ML scoring + triage. Off by default; degrades gracefully if the ml
# package, sklearn, or trained artifacts are missing. See recon-tool/ml/.
ML_ENABLED = os.environ.get("ML_ENABLED", "false").strip().lower() in {"1", "true", "yes"}

ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "corsheaders",
    "channels",
    "api",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF  = "config.urls"
ASGI_APPLICATION = "config.asgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]

# SQLite for Django auth; MongoEngine for all scan data
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

# MongoEngine connection
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://mongo:27017/recon_db")

import mongoengine
mongoengine.connect(host=MONGO_URI)

# Django Channels — Redis channel layer.
#
# InMemoryChannelLayer queues are bound to Daphne's event loop, so a
# group_send issued with async_to_sync from a background worker thread is
# silently dropped. The whole app broadcasts alerts/packets from threads, so a
# cross-process broker (Redis) is required for live streaming to work.
#
# Set CHANNEL_LAYER_BACKEND=memory to force the in-memory layer (tests only;
# live streaming from worker threads will not work with it).
REDIS_URL = os.environ.get("REDIS_URL", "redis://redis:6379/0")
CHANNEL_LAYER_BACKEND = os.environ.get("CHANNEL_LAYER_BACKEND", "redis").strip().lower()

if CHANNEL_LAYER_BACKEND == "memory" or not REDIS_URL:
    CHANNEL_LAYERS = {
        "default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}
    }
else:
    CHANNEL_LAYERS = {
        "default": {
            "BACKEND": "channels_redis.core.RedisChannelLayer",
            "CONFIG": {
                "hosts": [REDIS_URL],
                "capacity": 2000,          # max messages queued per channel
                "expiry": 30,              # seconds before an undelivered message expires
            },
        }
    }

STATIC_URL = "/static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# CORS: allow the React dev server and production Nginx
CORS_ALLOW_ALL_ORIGINS = True

REST_FRAMEWORK = {
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
    ]
}
