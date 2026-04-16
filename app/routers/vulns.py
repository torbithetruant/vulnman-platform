from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, ConfigDict
from typing import List, Optional

from app.database import get_db
from app.deps import get_current_active_user
from app.models import Vulnerability, SeverityLevel, VulnStatus, Scan, User, AuditLog
from app.schemas import AuditLogResponse # IMPORT THE NEW SCHEMA

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])

class VulnerabilityUpdate(BaseModel):
    status: VulnStatus

class VulnerabilityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    scan_id: int
    cve_id: Optional[str]
    title: str
    severity: SeverityLevel
    cvss_score: Optional[float]
    calculated_risk: Optional[float]
    status: VulnStatus
    affected_package: Optional[str]
    repository: Optional[str] = None

@router.get("/", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    severity: Optional[SeverityLevel] = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    query = (
        select(Vulnerability, Scan.repository.label("repository"))
        .join(Scan, Vulnerability.scan_id == Scan.id)
    )
    
    if severity:
        query = query.where(Vulnerability.severity == severity)
        
    query = query.order_by(Vulnerability.calculated_risk.desc()).offset(offset).limit(limit)
    result = await db.execute(query)
    
    vulns = []
    for row in result.all():
        vuln = row[0]
        vuln.repository = row[1]
        vulns.append(vuln)
        
    return vulns

@router.put("/{vuln_id}", response_model=VulnerabilityResponse)
async def update_vulnerability(
    vuln_id: int,
    update_data: VulnerabilityUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    query = (
        select(Vulnerability, Scan.repository.label("repository"))
        .join(Scan)
        .where(Vulnerability.id == vuln_id)
    )
    result = await db.execute(query)
    row = result.one_or_none()
    
    if not row:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    
    # 1. EXTRACT VULN FIRST
    vuln = row[0]
    
    # 2. SENIOR TOUCH: Prevent no-op updates (Don't log an audit if status didn't change)
    if vuln.status == update_data.status:
        raise HTTPException(status_code=400, detail="Vulnerability already has this status")
    
    # 3. NOW we can safely create the Audit Log
    audit_entry = AuditLog(
        vuln_id=vuln.id,
        changed_by_user_id=current_user.id,
        old_status=vuln.status,
        new_status=update_data.status
    )
    db.add(audit_entry)

    # 4. Update the actual vulnerability
    vuln.status = update_data.status

    await db.commit()
    await db.refresh(vuln)
    vuln.repository = row[1] 
    
    return vuln

@router.get("/{vuln_id}/history", response_model=List[AuditLogResponse]) # USE PYDANTIC SCHEMA
async def get_vulnerability_history(
    vuln_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
):
    query = (
        select(AuditLog)
        .where(AuditLog.vuln_id == vuln_id)
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .offset(offset)
        .limit(limit)
    )
    result = await db.execute(query)
    return result.scalars().all()