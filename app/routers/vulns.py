from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from pydantic import BaseModel, ConfigDict
from typing import List, Optional

from app.database import get_db
from app.models import Vulnerability, SeverityLevel, VulnStatus, Scan
from sqlalchemy.orm import selectinload

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
    repository: Optional[str] = None # We will alias this in the query

@router.get("/", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(
    severity: Optional[SeverityLevel] = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db)
):
    # 1. Start with a clean base query
    query = (
        select(
            Vulnerability,
            Scan.repository.label("repository")
        )
        .join(Scan, Vulnerability.scan_id == Scan.id)
    )
    
    # 2. Safely apply the filter ONLY if severity is provided
    if severity:
        query = query.where(Vulnerability.severity == severity)
        
    # 3. Now it's safe to chain ordering and pagination
    query = query.order_by(Vulnerability.calculated_risk.desc()).offset(offset).limit(limit)
    
    result = await db.execute(query)
    
    # 4. Map the tuple result back to our schema
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
    db: AsyncSession = Depends(get_db)
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
    
    vuln = row[0]
    vuln.status = update_data.status
    vuln.repository = row[1]
    
    await db.commit()
    await db.refresh(vuln)
    vuln.repository = row[1] # Ensure it persists after refresh if not mapped
    
    return vuln