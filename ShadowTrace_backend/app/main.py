from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
import os

# ------------------ Load .env ------------------
load_dotenv()  # Loads from project root: D:\ShadowTrace\.env

# ------------------ Import DB from database/mongo.py ------------------
from app.database.mongo import db, db_status, scans_collection


# ------------------ Router Imports ------------------
from app.api.search import router as search_router
from app.api.alerts import router as alerts_router
from app.api.history import router as history_router
from app.api.utils import router as utils_router

# ------------------ FastAPI Setup ------------------
app = FastAPI(
    title="ShadowTrace OSINT Engine",
    description="Automated OSINT & Threat Actor Profiling for Hackathon",
    version="1.0"
)

# CORS for frontend (adjust in production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change to your frontend URL in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------ Register Routers ------------------
app.include_router(search_router)
app.include_router(alerts_router)
app.include_router(history_router)
app.include_router(utils_router)

# ------------------ Root Route ------------------
@app.get("/")
async def root():
    return {
        "message": "ShadowTrace Backend Running",
        "status": "online",
        "version": "1.0",
        "db": db_status,
        "endpoints": {
            "start_scan": "/search/start",
            "get_scan": "/search/status/{query_id}",
            "run_scan": "/search/run/{query_id}",
            "alerts": "/alerts/",
            "history": "/history/",
            "utils": "/utils/test-keys"
        }
    }

# ------------------ Health Check ------------------
@app.get("/health")
async def health():
    if not db:
        return {"status": "error", "db": db_status}

    try:
        db.command("ping")
        return {
            "status": "healthy",
            "db": {"name": db.name, "status": "connected"},
            "collections": db.list_collection_names()[:5]  # First 5
        }
    except Exception as e:
        return {"status": "error", "db": {"status": "failed", "error": str(e)}}

# ------------------ Startup Event (Optional) ------------------
@app.on_event("startup")
async def startup_event():
    if db_status["db_status"] == "connected":
        print(f"Database '{db.name}' is ready.")
    else:
        print(f"Database connection failed: {db_status.get('error')}")