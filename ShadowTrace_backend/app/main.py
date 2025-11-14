from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from dotenv import load_dotenv
import os

# ------------------ Load .env ------------------
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../"))
ENV_PATH = os.path.join(BASE_DIR, ".env")
load_dotenv(ENV_PATH)

# ------------------ Import MongoDB ------------------
from app.database.mongo import db, db_status, scans_collection

# ------------------ Import Elasticsearch ------------------
from app.database.elastic import (
    get_status as get_elastic_status,
    create_index,
    index_doc
)

# ------------------ Import ES Index Mappings ------------------
from app.database.es_mapping import SCAN_INDEX, MAPPING as SCAN_MAPPING

# ------------------ Alerts Mapping (if missing) ------------------
try:
    from app.database.alerts_mapping import ALERT_INDEX, ALERT_MAPPING
except ImportError:
    ALERT_INDEX, ALERT_MAPPING = "shadowtrace_alerts", {
        "properties": {
            "title": {"type": "text"},
            "severity": {"type": "keyword"},
            "description": {"type": "text"},
            "timestamp": {"type": "date"},
            "raw": {"type": "object", "enabled": False}
        }
    }

# ------------------ Router Imports ------------------
from app.api.search import router as search_router
from app.api.alerts import router as alerts_router
from app.api.history import router as history_router
from app.api.utils import router as utils_router
from routers import osint

# ------------------ FastAPI App Setup ------------------
app = FastAPI(
    title="ShadowTrace OSINT Engine",
    description="Automated OSINT & Threat Actor Profiling for Hackathon",
    version="1.0"
)

# ------------------ CORS ------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------ Register Routers ------------------
app.include_router(search_router)
app.include_router(alerts_router)
app.include_router(history_router)
app.include_router(utils_router)
app.include_router(osint.router)
# ====================================================================
#  FRONTEND (ShadowTrace + SpiderFoot Integrated UI)
# ====================================================================

SPIDERFOOT_WEB_PATH = os.path.join(BASE_DIR, "spiderfoot", "spiderfoot", "web")
SPIDERFOOT_STATIC_PATH = os.path.join(SPIDERFOOT_WEB_PATH, "static")
SPIDERFOOT_INDEX_PATH = os.path.join(SPIDERFOOT_WEB_PATH, "templates", "index.html")

# Serve static assets (CSS, JS, etc.)
if os.path.exists(SPIDERFOOT_STATIC_PATH):
    app.mount("/static", StaticFiles(directory=SPIDERFOOT_STATIC_PATH), name="static")
else:
    print(f" SpiderFoot static directory not found: {SPIDERFOOT_STATIC_PATH}")

# Serve main integrated dashboard (index.html)
@app.get("/")
async def serve_frontend():
    """Serve the integrated ShadowTrace + SpiderFoot dashboard."""
    if not os.path.exists(SPIDERFOOT_INDEX_PATH):
        return {"error": "Frontend index.html not found", "path": SPIDERFOOT_INDEX_PATH}
    return FileResponse(SPIDERFOOT_INDEX_PATH)


# ====================================================================
#  HEALTH + UTILITY ENDPOINTS
# ====================================================================

@app.get("/health")
async def health():
    """Check health of MongoDB and Elasticsearch connections."""
    if not db:
        return {"status": "error", "db": db_status}

    try:
        db.command("ping")
        return {
            "status": "healthy",
            "db": {"name": db.name, "status": "connected"},
            "elastic": get_elastic_status(),
            "collections": db.list_collection_names()[:5]
        }
    except Exception as e:
        return {"status": "error", "db": {"status": "failed", "error": str(e)}}


@app.get("/utils/elastic-status")
async def elastic_status():
    """Return Elasticsearch connection status."""
    return get_elastic_status()


@app.post("/utils/elastic-test")
async def elastic_test():
    """Test if Elasticsearch can create and index documents."""
    try:
        create_index("shadowtrace_test")
        index_doc("shadowtrace_test", {"message": "Elasticsearch test document"})
        return {"status": "indexed"}
    except Exception as e:
        return {"status": "error", "error": str(e)}


# ====================================================================
#  STARTUP EVENT
# ====================================================================

@app.on_event("startup")
async def startup_event():
    print(" Starting ShadowTrace Backend...")

    # MongoDB
    if db_status["db_status"] == "connected":
        print(f" MongoDB connected: {db.name}")
    else:
        print(f" MongoDB connection failed: {db_status.get('error')}")

    # Elasticsearch
    elastic_info = get_elastic_status()
    if elastic_info.get("elastic") == "connected":
        print(" Elasticsearch connected.")
    else:
        print(f" Elasticsearch issue: {elastic_info}")

    # Create indices if missing
    try:
        create_index(SCAN_INDEX, mapping=SCAN_MAPPING)
        print(f"Index '{SCAN_INDEX}' ensured.")
    except Exception as e:
        print(f" Could not create '{SCAN_INDEX}': {e}")

    try:
        create_index(ALERT_INDEX, mapping=ALERT_MAPPING)
        print(f" Index '{ALERT_INDEX}' ensured.")
    except Exception as e:
        print(f" Could not create '{ALERT_INDEX}': {e}")

    print(" ShadowTrace Backend startup complete.")
