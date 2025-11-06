from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pymongo import MongoClient
from dotenv import load_dotenv
import certifi, ssl, os

# Load environment variables (.env file)
load_dotenv()

# ------------------ MongoDB Connection ------------------
MONGO_URI = os.getenv("MONGO_URI")
db = None

def connect_mongo():
    """Attempts TLS-secure connection, falls back to relaxed SSL if needed."""
    global db

    if not MONGO_URI:
        print("[!] MONGO_URI not found in .env")
        return

    # Create secure SSL context (forces TLS 1.2+)
    ssl_ctx = ssl.create_default_context(cafile=certifi.where())
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    try:
        # First, attempt a strict TLS connection
        client = MongoClient(
            MONGO_URI,
            tls=True,
            tlsCAFile=certifi.where(),
            tlsAllowInvalidCertificates=False,
            ssl=True,
            ssl_cert_reqs=ssl.CERT_REQUIRED,
            ssl_match_hostname=True,
            serverSelectionTimeoutMS=8000,
            ssl_context=ssl_ctx
        )
        client.admin.command("ping")
        db = client["shadowtrace"]
        print("[+] MongoDB Atlas connected successfully via secure TLS")
    except Exception as e:
        print("[!] Secure TLS connection failed, retrying with relaxed SSL...")
        print("    Error:", e)
        try:
            # Retry with relaxed verification
            client = MongoClient(
                MONGO_URI,
                tls=True,
                tlsCAFile=certifi.where(),
                tlsAllowInvalidCertificates=True,
                ssl=True,
                ssl_cert_reqs=ssl.CERT_NONE,
                ssl_match_hostname=False,
                serverSelectionTimeoutMS=8000
            )
            client.admin.command("ping")
            db = client["shadowtrace"]
            print("[+] MongoDB connected (TLS verification bypassed for development)")
        except Exception as err:
            print("[!] MongoDB connection failed completely:", err)
            db = None

# Run connection on startup
connect_mongo()

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

# Allow all origins (safe for local development)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
        "endpoints": {
            "start_scan": "/search/start",
            "get_scan": "/search/status/{query_id}",
            "run_scan": "/search/run/{query_id}",
            "alerts": "/alerts/",
            "history": "/history/",
            "utils": "/utils/test-keys"
        }
    }

# ------------------ Database Connectivity Test ------------------
@app.get("/db-test")
async def db_test():
    if not db:
        return {"db_status": "failed", "error": "Database not connected"}
    try:
        db.command("ping")
        return {"db_status": "connected", "db_name": "shadowtrace"}
    except Exception as e:
        return {"db_status": "failed", "error": str(e)}
