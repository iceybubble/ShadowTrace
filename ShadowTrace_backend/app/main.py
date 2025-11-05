# app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI) if MONGO_URI else MongoClient()
db = client["shadowtrace"]

# Routers will import db from here: from app.main import db
from app.api.search import router as search_router
from app.api.alerts import router as alerts_router
from app.api.history import router as history_router

app = FastAPI(
    title="ShadowTrace OSINT Engine",
    description="Automated OSINT & Threat Actor Profiling for Hackathon",
    version="1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],     # dev-only
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(search_router)
app.include_router(alerts_router)
app.include_router(history_router)

@app.get("/")
async def root():
    return {
        "message": "ShadowTrace Backend Running ✅",
        "status": "online",
        "version": "1.0",
        "endpoints": {
            "start_scan": "/search/start",
            "get_scan": "/search/status/{query_id}",
            "run_scan": "/search/run/{query_id}",
            "alerts": "/alerts/",
            "history": "/history/"
        }
    }

@app.get("/db-test")
async def db_test():
    try:
        db.command("ping")
        return {"db_status": "connected", "db_name": "shadowtrace"}
    except Exception as e:
        return {"db_status": "failed", "error": str(e)}
