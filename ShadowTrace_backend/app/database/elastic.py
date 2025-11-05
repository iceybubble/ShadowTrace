from elasticsearch import Elasticsearch
from app.config import settings

es = Elasticsearch(
    settings.ELASTIC_URL,
    basic_auth=(settings.ELASTIC_USERNAME, settings.ELASTIC_PASSWORD),
    verify_certs=settings.ELASTIC_VERIFY_SSL
)

INDEX = "shadowtrace-osint"
