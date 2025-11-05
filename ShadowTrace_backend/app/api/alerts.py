from fastapi import APIRouter
router = APIRouter(prefix="/alerts", tags=["Alerts"])

@router.get("/")
def get_alerts():
    return {"alerts": []}  # soon we add webhook + email alerts
