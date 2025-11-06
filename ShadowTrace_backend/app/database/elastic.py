# app/database/elastic.py
import os
import time
from dotenv import load_dotenv

# load .env located two levels up from this file
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
ENV_PATH = os.path.join(BASE_DIR, ".env")
load_dotenv(ENV_PATH)

ELASTIC_URL = os.getenv("ELASTIC_URL", "http://localhost:9200")
ELASTIC_USERNAME = os.getenv("ELASTIC_USERNAME", "")
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD", "")
ELASTIC_VERIFY_SSL = os.getenv("ELASTIC_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

# late import to avoid import errors while loading module
try:
    from elasticsearch import Elasticsearch
    # try to import known exception classes if available
    try:
        from elasticsearch import exceptions as es_exceptions
        # alias for older/newer clients
        ElasticsearchException = getattr(es_exceptions, "ElasticsearchException", None)
    except Exception:
        es_exceptions = None
        ElasticsearchException = None
except Exception as e:
    Elasticsearch = None
    es_exceptions = None
    ElasticsearchException = None
    print("Elasticsearch python client import error:", e)

es_client = None
es_status = {"elastic": "not_connected", "error": None}


def init_elasticsearch():
    """Initialize ES client. Safe to call multiple times."""
    global es_client, es_status
    if Elasticsearch is None:
        es_status = {"elastic": "error", "error": "elasticsearch client not installed"}
        return

    try:
        kwargs = {}
        verify = ELASTIC_VERIFY_SSL
        # If URL is https and no username/password provided, client will still try anonymous TLS
        if ELASTIC_USERNAME and ELASTIC_PASSWORD:
            kwargs["basic_auth"] = (ELASTIC_USERNAME, ELASTIC_PASSWORD)

        # Use the URL list form to allow http/https
        es_client = Elasticsearch([ELASTIC_URL], verify_certs=verify, request_timeout=20, **kwargs)

        # ping will perform a simple request to the root
        if es_client.ping():
            es_status = {"elastic": "connected"}
            print("Connected to Elasticsearch at", ELASTIC_URL)
        else:
            # if ping returns False, show info
            es_status = {"elastic": "unreachable", "error": f"ping returned False for {ELASTIC_URL}"}
            es_client = None
    except Exception as e:
        es_client = None
        es_status = {"elastic": "error", "error": str(e)}
        # print brief info for logs
        print("Elasticsearch connection failed:", e)


# initialize on import
init_elasticsearch()


def create_index(index_name: str, mapping: dict = None, wait_for_active_shards: str = "1"):
    """
    Create an index if missing. mapping should be the `mappings` dictionary (not wrapped).
    """
    if es_client is None:
        raise RuntimeError("Elasticsearch client not initialized")

    try:
        # indices.exists returns True/False in modern client
        exists = es_client.indices.exists(index=index_name)
        if not exists:
            body = {}
            if mapping:
                # new client expects mappings under 'mappings'
                body["mappings"] = mapping
            es_client.indices.create(index=index_name, **({"body": body} if body else {}))
            # option: wait for shard active (not blocking by default)
            # es_client.indices.refresh(index=index_name)
            return True
        return False
    except Exception as e:
        # re-raise to let caller handle failures
        raise


def index_doc(index_name: str, body: dict, doc_id: str = None, refresh: bool = False):
    """
    Index a document into ES. doc_id optional.
    """
    if es_client is None:
        raise RuntimeError("Elasticsearch client not initialized")

    try:
        if doc_id:
            # modern client uses 'document' keyword
            es_client.index(index=index_name, id=doc_id, document=body, refresh=refresh)
        else:
            es_client.index(index=index_name, document=body, refresh=refresh)
    except Exception as e:
        # bubble up to callers so they can retry
        raise


def index_doc_with_retry(index_name: str, body: dict, doc_id: str = None, attempts: int = 3, delay: float = 1.0):
    last_exc = None
    for i in range(attempts):
        try:
            index_doc(index_name, body, doc_id=doc_id, refresh=False)
            return True
        except Exception as e:
            last_exc = e
            time.sleep(delay)
    raise last_exc


def search_docs(index_name: str, query: dict, size: int = 10):
    """
    Execute a search. Query should be the body (dict).
    """
    if es_client is None:
        raise RuntimeError("Elasticsearch client not initialized")

    try:
        # modern client: search(index=..., body=...)
        response = es_client.search(index=index_name, body=query, size=size)
        return response
    except Exception as e:
        raise


def get_status():
    return es_status
