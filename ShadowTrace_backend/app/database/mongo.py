from pymongo import MongoClient
from app.config import settings

client = MongoClient(settings.MONGO_URI)
db = client[settings.MONGO_DB]

queries = db["queries"]
raw_intel = db["raw_intel"]
entities = db["entities"]
connections = db["connections"]
alerts = db["alerts"]
