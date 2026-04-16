import hashlib
import hmac
import json
from unittest.mock import patch
from app.routers import webhooks # Import the module to patch settings

def test_webhook_rejects_missing_signature(client):
    payload = {"tool": "trivy", "repository": "prod-api", "data": {"results": []}}
    response = client.post("/api/v1/webhooks/ingest", json=payload)
    assert response.status_code == 401

def test_webhook_rejects_invalid_signature(client):
    payload = {"tool": "trivy", "repository": "prod-api", "data": {"results": []}}
    response = client.post(
        "/api/v1/webhooks/ingest", 
        json=payload,
        headers={"X-Signature-256": "invalid-signature"}
    )
    assert response.status_code == 403

def test_webhook_accepts_valid_signature(client):
    # 1. Force a known secret for this test
    secret = "absolute-certain-test-secret"
    
    payload = {
        "tool": "snyk", 
        "repository": "frontend-prod", 
        "data": {"vulnerabilities": [{"id": "CVE-2021-44228"}]}
    }
    raw_bytes = json.dumps(payload).encode('utf-8')
    
    # 2. Calculate signature
    expected_sig = hmac.new(
        secret.encode('utf-8'),
        raw_bytes,
        hashlib.sha256
    ).hexdigest()
    
    # 3. Patch the setting in the webhook router to match our secret
    with patch.object(webhooks.settings, "webhook_secret", secret):
        response = client.post(
            "/api/v1/webhooks/ingest",
            content=raw_bytes,
            headers={
                "X-Signature-256": expected_sig,
                "Content-Type": "application/json"
            }
        )
        
    assert response.status_code == 202
    assert response.json()["status"] == "pending"