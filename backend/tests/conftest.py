import pytest
import pytest_asyncio
from httpx import AsyncClient
from app.main import app
import os

@pytest.fixture
def anyio_backend():
    return 'asyncio'

@pytest_asyncio.fixture
async def client():
    # Monkeypatch the global variable used by the dependency
    from app import main as app_module
    
    original_code = app_module.INTERNAL_ACCESS_CODE
    app_module.INTERNAL_ACCESS_CODE = "test-secret"
    
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
    
    # Cleanup
    app_module.INTERNAL_ACCESS_CODE = original_code

@pytest.fixture
def auth_headers():
    return {"X-Internal-Code": "test-secret"}

@pytest.fixture
def mock_plan_json():
    return {
        "terraform_version": "1.5.0",
        "format_version": "1.2",
        "resource_changes": [
            {
                "address": "aws_security_group.test",
                "type": "aws_security_group",
                "change": {
                    "actions": ["create"],
                    "after": {"ingress": []}
                }
            }
        ]
    }
