from fastapi import FastAPI
from app.config import settings

from app.routers import auth, webhooks, vulns

app = FastAPI(title="Vulnerability Management API")

app.include_router(webhooks.router, prefix="/api/v1")
app.include_router(vulns.router, prefix="/api/v1")
app.include_router(auth.router, prefix="/api/v1")

@app.get("/health")
async def health():
    return {"status": "ok", "service": "vuln-mgmt"}