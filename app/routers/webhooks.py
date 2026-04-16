import hashlib
import hmac
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import Any, Dict
import structlog

from app.config import settings
from app.database import get_db
from app.models import Scan
from app.tasks import process_scan_data

router = APIRouter(prefix="/webhooks", tags=["ingestion"])
logger = structlog.get_logger()

def verify_webhook_signature(request: Request, payload: bytes) -> bool:
    """Dependency to verify HMAC signature from scanner."""
    signature_header = request.headers.get("X-Signature-256") # Adjust based on tool
    if not signature_header:
        raise HTTPException(status_code=401, detail="Missing signature header")
    
    expected_sig = hmac.new(
        settings.webhook_secret.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    # Use hmac.compare_digest to prevent timing attacks!
    if not hmac.compare_digest(expected_sig, signature_header):
        raise HTTPException(status_code=403, detail="Invalid signature")
    return True

class WebhookPayload(BaseModel):
    tool: str
    repository: str
    data: Dict[str, Any]

@router.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest_scan(
    request: Request, # Need raw request for headers
    payload: WebhookPayload,
    db: AsyncSession = Depends(get_db)
):
    # CRITICAL: Read raw body for signature verification
    raw_body = await request.body()
    verify_webhook_signature(request, raw_body)

    # Parse AFTER verification
    payload = WebhookPayload.model_validate_json(raw_body)
    
    logger.info("scan_ingested_securely", tool=payload.tool, repo=payload.repository)
    
    scan = Scan(
        tool_name=payload.tool,
        repository=payload.repository,
        status="pending"
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    
    # Send to Celery
    process_scan_data.delay(scan_id=scan.id, raw_data=payload.data)
    
    return {"message": "Scan accepted", "scan_id": scan.id, "status": "pending"}