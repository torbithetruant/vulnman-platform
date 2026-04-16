from unittest.mock import AsyncMock, MagicMock
from fastapi.testclient import TestClient
import pytest

from app.models import VulnStatus, AuditLog, SeverityLevel
from app.database import get_db
from app.main import app

def test_list_vulnerabilities_empty(client, auth_headers):
    response = client.get(
        "/api/v1/vulnerabilities/",
        headers=auth_headers
    )
    assert response.status_code == 200
    assert response.json() == []

def test_list_vulnerabilities_with_pagination(client, auth_headers):
    response = client.get(
        "/api/v1/vulnerabilities/?limit=10&offset=0",
        headers=auth_headers
    )
    assert response.status_code == 200

def test_get_vulnerability_history_empty(client, auth_headers):
    """Test fetching history when no audit logs exist."""
    response = client.get(
        "/api/v1/vulnerabilities/999/history",
        headers=auth_headers
    )
    assert response.status_code == 200
    assert response.json() == []

def test_update_vulnerability_creates_audit_log(client):
    """
    CRITICAL TEST: Proves that changing a status creates an immutable AuditLog 
    with the correct old/new values and actor ID.
    """
    db_mock_instance = None

    # 1. Create a custom DB mock for this specific test
    async def override_audit_db():
        nonlocal db_mock_instance
        db_mock_instance = AsyncMock()
        
        # Simulate fetching the existing vulnerability from the DB
        mock_vuln = MagicMock()
        mock_vuln.id = 1
        mock_vuln.status = VulnStatus.OPEN  # Simulate the OLD status
        
        # FIX: Give it real data so Pydantic can serialize it for the 200 response
        mock_vuln.scan_id = 1
        mock_vuln.cve_id = "CVE-2021-44228"
        mock_vuln.title = "Log4Shell"
        mock_vuln.severity = SeverityLevel.CRITICAL
        mock_vuln.affected_package = "log4j-core"
        mock_vuln.cvss_score = 10.0
        mock_vuln.calculated_risk = 10.0
        
        # Simulate the JOIN query returning a tuple: (Vulnerability, repository)
        mock_row = (mock_vuln, "test-repo")
        
        mock_result = MagicMock()
        mock_result.one_or_none.return_value = mock_row
        
        db_mock_instance.execute.return_value = mock_result
        db_mock_instance.commit.return_value = None
        db_mock_instance.refresh.return_value = None
        db_mock_instance.add = MagicMock() # FIX: Force db.add to be synchronous
        
        yield db_mock_instance

    # 2. Temporarily apply this specific mock
    original_db_override = app.dependency_overrides[get_db]
    app.dependency_overrides[get_db] = override_audit_db

    # 3. Execute the PUT request
    response = client.put(
        "/api/v1/vulnerabilities/1",
        json={"status": "fixed"}, # The NEW status
        headers={"Authorization": "Bearer dummy-token"}
    )

    # 4. Restore the original mock for other tests
    app.dependency_overrides[get_db] = original_db_override

    # --- ASSERTIONS ---

    # Did the endpoint return success?
    assert response.status_code == 200
    assert response.json()["status"] == "fixed"
    assert response.json()["cve_id"] == "CVE-2021-44228"

    # Did the endpoint call db.add()?
    assert db_mock_instance.add.called

    # Extract the exact object that was passed to db.add()
    added_obj = db_mock_instance.add.call_args[0][0]

    # Is it an AuditLog?
    assert isinstance(added_obj, AuditLog)
    
    # Does it contain the correct compliance data?
    assert added_obj.vuln_id == 1
    assert added_obj.old_status == VulnStatus.OPEN
    assert added_obj.new_status == VulnStatus.FIXED
    assert added_obj.changed_by_user_id == 999  # Matches FAKE_USER in conftest.py

def test_update_vulnerability_rejects_noop(client):
    """
    Senior-level touch: Ensure we don't pollute the audit log if the 
    user sends a request to change the status to what it already is.
    """
    db_mock_instance = None

    async def override_noop_db():
        nonlocal db_mock_instance
        db_mock_instance = AsyncMock()
        
        mock_vuln = MagicMock()
        mock_vuln.id = 1
        mock_vuln.status = VulnStatus.FIXED # Already fixed!
        
        mock_row = (mock_vuln, "test-repo")
        mock_result = MagicMock()
        mock_result.one_or_none.return_value = mock_row
        
        db_mock_instance.execute.return_value = mock_result
        yield db_mock_instance

    original_db_override = app.dependency_overrides[get_db]
    app.dependency_overrides[get_db] = override_noop_db

    # Try to change it to FIXED again
    response = client.put(
        "/api/v1/vulnerabilities/1",
        json={"status": "fixed"},
        headers={"Authorization": "Bearer dummy-token"}
    )

    app.dependency_overrides[get_db] = original_db_override

    # Should be rejected by our custom logic
    assert response.status_code == 400
    assert "already has this status" in response.json()["detail"]
    
    # db.add() should NEVER have been called
    assert not db_mock_instance.add.called