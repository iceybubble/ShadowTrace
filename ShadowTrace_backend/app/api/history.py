from fastapi import APIRouter
from app.database.mongo import scans_collection

router = APIRouter(prefix="/history", tags=["History"])

@router.get("/")
async def get_history():
    data = list(scans_collection.find({}, {"_id": 0}).sort("_id", -1))
    return {"count": len(data), "data": data}
