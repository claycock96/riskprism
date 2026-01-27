import os
# Set test environment defaults BEFORE importing app
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["INTERNAL_ACCESS_CODE"] = "test-secret"
os.environ["LLM_PROVIDER"] = "mock"

import pytest
from httpx import AsyncClient
from app.database import init_db
from app.main import app, limiter

@pytest.fixture(autouse=True)
async def setup_db():
    await init_db()
    yield

@pytest.fixture
def anyio_backend():
    return 'asyncio'

@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Reset rate limiter state before each test to avoid cross-test pollution."""
    limiter.reset()
    yield
    limiter.reset()

@pytest.fixture
async def client(anyio_backend):
    # Set secure env var for tests
    os.environ["INTERNAL_ACCESS_CODE"] = "test-secret"
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
    # Cleanup
    if "INTERNAL_ACCESS_CODE" in os.environ:
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
