from celery import Celery
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.config import settings
from app.models import Scan, Vulnerability, SeverityLevel, Base
from app.services.scoring import RiskCalculator
import structlog

logger = structlog.get_logger()

# Synchronous engine for Celery (DO NOT use async here)
sync_engine = create_engine(
    settings.database_url.replace("+asyncpg", "+psycopg2"), # Use sync driver
    pool_size=5,
    max_overflow=10
)

celery = Celery(
    "vuln_worker",
    broker=settings.redis_url,
    backend=settings.redis_url
)

def map_severity(tool_severity: str) -> SeverityLevel:
    if not tool_severity: return SeverityLevel.INFO
    s = tool_severity.upper().strip()
    mapping = {
        "CRITICAL": SeverityLevel.CRITICAL, "CRITICALITY": SeverityLevel.CRITICAL,
        "HIGH": SeverityLevel.HIGH, "MEDIUM": SeverityLevel.MEDIUM, "LOW": SeverityLevel.LOW
    }
    return mapping.get(s, SeverityLevel.INFO)

@celery.task(name="app.tasks.process_scan_data", bind=True, max_retries=3)
def process_scan_data(self, scan_id: int, raw_data: dict):
    """
    Synchronous Celery task. Safe, reliable, uses connection pooling.
    """
    with Session(sync_engine) as db:
        try:
            scan = db.execute(select(Scan).where(Scan.id == scan_id)).scalar_one_or_none()
            if not scan:
                logger.error("scan_not_found", scan_id=scan_id)
                return

            scan.status = "processing"
            db.commit()

            findings = raw_data.get("results", []) or raw_data.get("vulnerabilities", [])
            
            for finding in findings:
                # ACTUALLY PARSE THE DATA (You need to adapt this to Trivy/Snyk actual JSON schema)
                cvss_score = finding.get("cvss", {}).get("nvd", {}).get("score") or finding.get("cvssScore", 0.0)
                cve_id = finding.get("vulnerabilityID") or finding.get("id", "UNKNOWN")
                
                is_prod = "prod" in scan.repository.lower()
                has_exploit = finding.get("exploit", False) # Example field

                calculated_risk = RiskCalculator.calculate(
                    cvss_score=float(cvss_score), 
                    is_public_facing=is_prod,
                    has_known_exploit=has_exploit
                )

                vuln = Vulnerability(
                    scan_id=scan.id,
                    cve_id=cve_id,
                    title=finding.get("title", f"Vuln in {cve_id}"),
                    severity=map_severity(finding.get("severity")),
                    description=finding.get("description", ""),
                    affected_package=finding.get("package", {}).get("name", "unknown"),
                    cvss_score=float(cvss_score), 
                    calculated_risk=calculated_risk
                )
                db.add(vuln)
            
            scan.status = "completed"
            scan.finished_at = datetime.now(timezone.utc)
            db.commit()
            logger.info("scan_processed_successfully", scan_id=scan_id)
            
        except Exception as e:
            db.rollback()
            logger.error("scan_processing_failed", scan_id=scan_id, error=str(e))
            scan.status = "failed"
            db.commit()
            raise self.retry(exc=e, countdown=60)