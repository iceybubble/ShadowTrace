import os
from dotenv import load_dotenv
load_dotenv()

class Settings:
    MONGO_URI = os.getenv("MONGO_URI", "")
    MONGO_DB = os.getenv("MONGO_DB", "shadowtrace")

    ELASTIC_URL = os.getenv("ELASTIC_URL", "https://localhost:9200")
    ELASTIC_USERNAME = os.getenv("ELASTIC_USERNAME", "")
    ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD", "")
    ELASTIC_VERIFY_SSL = False

    DARK_FEEDS = [
        "https://raw.githubusercontent.com/andreafortuna/awesome-breached-data/main/data/db_leaks.txt"
    ]

settings = Settings()
