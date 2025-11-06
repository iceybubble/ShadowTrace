import os
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

# General app config
PORT = os.getenv("PORT", 8000)
APP_ENV = os.getenv("APP_ENV", "development")

# MongoDB
MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB = os.getenv("MONGO_DB")

# Elasticsearch (optional)
ELASTIC_URL = os.getenv("ELASTIC_URL")
ELASTIC_USERNAME = os.getenv("ELASTIC_USERNAME")
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD")
ELASTIC_VERIFY_SSL = os.getenv("ELASTIC_VERIFY_SSL", "false").lower() == "true"

# API Keys (OSINT integrations)
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
MAXMIND_LICENSE_KEY = os.getenv("MAXMIND_LICENSE_KEY")
HIBP_API_KEY = os.getenv("HIBP_API_KEY")

# Threat Feeds
DARK_FEEDS = os.getenv("DARK_FEEDS", "").split(",")

# SMTP (email alerts)
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = os.getenv("SMTP_PORT")
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
ALERT_EMAIL_FROM = os.getenv("ALERT_EMAIL_FROM")
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO")

# Redis / Celery
REDIS_URL = os.getenv("REDIS_URL")
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL")
RESULT_BACKEND = os.getenv("RESULT_BACKEND")

# Monitoring / Webhooks
SENTRY_DSN = os.getenv("SENTRY_DSN")
ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL")

# Security
JWT_SECRET = os.getenv("JWT_SECRET")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
