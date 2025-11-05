from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from dotenv import load_dotenv
import os

# Load env vars
load_dotenv()

# MongoDB connection
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["shadowtrace"]

# Routers
from app.api.search import router as search_router
from app.api.alerts import router as alerts_router
from app.api.history import router as history_router

app = FastAPI(
    title="ShadowTrace OSINT Engine",
    description="Automated OSINT & Threat Actor Profiling for Hackathon",
    version="1.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routes
app.include_router(search_router)
app.include_router(alerts_router)
app.include_router(history_router)

# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "ShadowTrace Backend Running ✅",
        "status": "online",
        "version": "1.0",
        "endpoints": {
            "start_scan": "/scan/",
            "get_scan": "/scan/{query_id}",
            "alerts": "/alerts/",
            "history": "/history/"
        }
    }

# DB test route
@app.get("/db-test")
async def db_test():
    try:
        db.command("ping")
        return {"db_status": "connected ✅", "db_name": "shadowtrace"}
    except Exception as e:
        return {"db_status": "failed ❌", "error": str(e)}
