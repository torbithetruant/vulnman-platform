def test_register_user(client):
    response = client.post("/api/v1/auth/register", json={
        "username": "newuser",
        "email": "new@test.com",
        "password": "password123"
    })
    assert response.status_code == 201
    assert response.json()["username"] == "newuser"

def test_login_wrong_password(client):
    # Because default mock returns None, this will correctly hit the 401 path
    response = client.post("/api/v1/auth/login", data={
        "username": "testuser",
        "password": "wrongpassword"
    })
    assert response.status_code == 401

def test_access_protected_route_without_token(client):
    from app.deps import get_current_active_user
    from app.main import app
    
    # 1. Temporarily remove the auth bypass
    auth_override = app.dependency_overrides.pop(get_current_active_user, None)
    
    # 2. Make the request with NO token (FastAPI will now enforce real security)
    response = client.get("/api/v1/vulnerabilities/")
    
    # 3. Assert we get the security 401
    assert response.status_code == 401
    
    # 4. Restore the bypass so subsequent tests in the session keep working
    if auth_override:
        app.dependency_overrides[get_current_active_user] = auth_override

def test_access_protected_route_with_valid_token(client, auth_headers):
    # Proves the token generated in conftest.py works with deps.py
    response = client.get("/api/v1/vulnerabilities/", headers=auth_headers)
    assert response.status_code == 200