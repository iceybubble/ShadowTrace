from fastapi import APIRouter
from pydantic import BaseModel
from app.services.spiderfoot_client import SpiderFootClient

router = APIRouter(prefix="/osint", tags=["OSINT"])

class ScanRequest(BaseModel):
    scan_name: str
    target: str
    use_case: str = "all"

@router.post("/start")
def start_scan(data: ScanRequest):
    return SpiderFootClient.start_scan(
        scan_name=data.scan_name,
        target=data.target,
        use_case=data.use_case
    )

@router.get("/status/{scan_id}")
def get_status(scan_id: str):
    return SpiderFootClient.scan_status(scan_id)

@router.get("/stop/{scan_id}")
def stop_scan(scan_id: str):
    return SpiderFootClient.stop_scan(scan_id)

@router.get("/results/{scan_id}")
def fetch_results(scan_id: str):
    return SpiderFootClient.scan_results(scan_id)
