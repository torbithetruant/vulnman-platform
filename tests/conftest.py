import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.database import get_db
from app.deps import get_current_active_user
from app.models import User

# Create a fake user object to inject into protected routes
FAKE_USER = User(
    id=999,
    username="testuser",
    email="test@test.com",
    is_active=True
)

@pytest.fixture(scope="session")
def client():
    # 1. Mock the Database
    async def override_get_db():
        db = AsyncMock()
        mock_result = MagicMock()
        
        mock_result.scalar_one_or_none.return_value = None
        mock_result.all.return_value = [] 
        mock_result.scalars.return_value.all.return_value = []
        
        db.execute.return_value = mock_result
        db.commit.return_value = None
        db.refresh.return_value = None
        db.add = MagicMock() # FIX: db.add is sync in SQLAlchemy 2.0
        yield db
    
    # 2. Mock the Auth Dependency
    async def override_auth():
        return FAKE_USER

    with patch("app.routers.webhooks.process_scan_data") as mock_celery:
        mock_celery.delay = MagicMock(return_value="fake-task-id")
        
        # Apply overrides globally to the TestClient
        app.dependency_overrides[get_db] = override_get_db
        app.dependency_overrides[get_current_active_user] = override_auth
        
        with TestClient(app) as c:
            yield c
            
        # Clean up
        app.dependency_overrides.clear()

@pytest.fixture
def auth_headers():
    """
    Because we overrode get_current_active_user in conftest.py,
    FastAPI ignores the JWT token entirely and injects FAKE_USER.
    We still pass a dummy header to keep the test syntax realistic.
    """
    return {"Authorization": "Bearer dummy-token"}