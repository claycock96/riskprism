import pytest
from httpx import AsyncClient
from app.main import app
import os

@pytest.fixture
def anyio_backend():
    return 'asyncio'

@pytest.fixture
async def client():
    # Set secure env var for tests
    os.environ["INTERNAL_ACCESS_CODE"] = "test-secret"
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
    # Cleanup
    del os.environ["INTERNAL_ACCESS_CODE"]

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
