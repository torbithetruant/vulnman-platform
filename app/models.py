import enum
from sqlalchemy import Boolean, Column, Integer, String, Float, DateTime, ForeignKey, Text, Enum as SQLEnum
from sqlalchemy.orm import relationship, declarative_base
from sqlalchemy.sql import func

Base = declarative_base()


class SeverityLevel(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnStatus(enum.Enum):
    OPEN = "open"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"
    RISK_ACCEPTED = "risk_accepted"
    IN_PROGRESS = "in_progress"


class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    

class Scan(Base):
    """Represents a single execution of a security scanner (e.g., Trivy run)."""
    __tablename__ = "scans"
    
    id = Column(Integer, primary_key=True, index=True)
    tool_name = Column(String(50), nullable=False) # e.g., "trivy", "snyk"
    repository = Column(String(255)) # Target repo/target
    status = Column(String(20), default="pending") # pending, completed, failed
    started_at = Column(DateTime(timezone=True), server_default=func.now())
    finished_at = Column(DateTime(timezone=True))
    
    # Relationship
    vulnerabilities = relationship("Vulnerability", back_populates="scan")


class Vulnerability(Base):
    """A specific security finding."""
    __tablename__ = "vulnerabilities"
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    
    # Identification
    cve_id = Column(String(50), index=True) # CVE-2021-44228
    title = Column(String(500), nullable=False)
    description = Column(Text)
    
    # Risk Scoring
    severity = Column(SQLEnum(SeverityLevel), nullable=False, index=True)
    cvss_score = Column(Float) # 0.0 - 10.0
    calculated_risk = Column(Float)
    
    # Remediation
    remediation = Column(Text)
    affected_package = Column(String(255))
    installed_version = Column(String(100))
    fixed_version = Column(String(100))
    
    # Lifecycle
    status = Column(SQLEnum(VulnStatus), default=VulnStatus.OPEN, index=True)
    status_updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    discovered_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationship
    scan = relationship("Scan", back_populates="vulnerabilities")


class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    vuln_id = Column(Integer, ForeignKey("vulnerabilities.id"), nullable=False, index=True)
    
    # The Change
    old_status = Column(SQLEnum(VulnStatus), nullable=False)
    new_status = Column(SQLEnum(VulnStatus), nullable=False)
    
    # The Actor (Who did it?)
    changed_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now())