from fastapi import FastAPI, BackgroundTasks
from app.api.search import router as search_router
from app.api.alerts import router as alerts_router

app = FastAPI(
    title="ShadowTrace OSINT Engine",
    version="1.0",
    description="Automated OSINT & Threat Profiling for Hackathon"
)

app.include_router(search_router)
app.include_router(alerts_router)

@app.get("/")
def root():
    return {"message": "ShadowTrace Backend Running ✅"}
