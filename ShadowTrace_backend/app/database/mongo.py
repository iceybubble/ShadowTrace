# database/mongo.py
import os
import certifi
from pymongo import MongoClient
from dotenv import load_dotenv

# Load .env from D:\ShadowTrace\.env
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
load_dotenv(os.path.join(BASE_DIR, ".env"))

MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME", "ShadowTrace")

db = None
scans_collection = None
db_status = {"db_status": "failed", "error": "Not connected"}

if not MONGO_URI:
    print("[!] MONGO_URI not found in .env")
else:
    try:
        # Force modern TLS + fresh CA bundle
        client = MongoClient(
            MONGO_URI,
            tls=True,
            tlsCAFile=certifi.where(),
            serverSelectionTimeoutMS=15000,
            connectTimeoutMS=15000,
            socketTimeoutMS=15000,
            tlsAllowInvalidCertificates=False  # NEVER True in prod
        )
        # Test connection
        client.admin.command("ping")
        db = client[DB_NAME]
        scans_collection = db["scans"]
        db_status = {"db_status": "connected"}
        print(f"MongoDB Atlas CONNECTED: {DB_NAME}")
    except Exception as e:
        error_msg = str(e)
        db_status = {"db_status": "failed", "error": error_msg}
        print(f"MongoDB connection FAILED: {error_msg}")