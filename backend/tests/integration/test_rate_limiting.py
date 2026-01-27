"""
Rate limiting tests for the API endpoints.

These tests verify that rate limiting is properly enforced.
Note: These tests intentionally do NOT use the auto-reset fixture.
"""

import pytest
from httpx import AsyncClient
from app.main import app, limiter


@pytest.fixture
def anyio_backend():
    return 'asyncio'


@pytest.fixture
async def rate_limit_client(anyio_backend):
    """Client with rate limiting enabled for testing rate limits."""
    import os
    os.environ["INTERNAL_ACCESS_CODE"] = "test-secret"
    # Enable and reset limiter for rate limit tests
    limiter.enabled = True
    limiter.reset()
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
    # Cleanup - disable again for other tests
    limiter.enabled = False
    limiter.reset()


@pytest.fixture
def auth_headers():
    return {"X-Internal-Code": "test-secret"}


@pytest.mark.anyio
async def test_rate_limit_on_analyze_endpoint(rate_limit_client, auth_headers):
    """Verify rate limiting kicks in after limit is exceeded."""
    plan = {
        "resource_changes": [
            {
                "address": "aws_instance.rate_test",
                "type": "aws_instance",
                "change": {"actions": ["create"], "after": {}}
            }
        ]
    }

    # Make requests up to the limit (10/minute for /analyze)
    success_count = 0
    rate_limited_count = 0

    for i in range(15):
        response = await rate_limit_client.post(
            "/analyze",
            json={"plan_json": plan},
            headers=auth_headers
        )
        if response.status_code == 200:
            success_count += 1
        elif response.status_code == 429:
            rate_limited_count += 1

    # Should have some successes and some rate limited
    assert success_count > 0, "Some requests should succeed"
    assert rate_limited_count > 0, "Some requests should be rate limited"
    assert success_count <= 10, "Should not exceed rate limit"


@pytest.mark.anyio
async def test_rate_limit_returns_429(rate_limit_client, auth_headers):
    """Verify rate limited requests return 429 status code."""
    plan = {
        "resource_changes": [
            {
                "address": "aws_instance.test",
                "type": "aws_instance",
                "change": {"actions": ["create"], "after": {}}
            }
        ]
    }

    # Exhaust the rate limit
    for _ in range(12):
        await rate_limit_client.post(
            "/analyze",
            json={"plan_json": plan},
            headers=auth_headers
        )

    # Next request should be rate limited
    response = await rate_limit_client.post(
        "/analyze",
        json={"plan_json": plan},
        headers=auth_headers
    )

    assert response.status_code == 429


@pytest.mark.anyio
async def test_rate_limit_on_auth_validate(rate_limit_client, auth_headers):
    """Verify rate limiting on auth/validate endpoint (5/minute)."""
    success_count = 0
    rate_limited_count = 0

    for i in range(8):
        response = await rate_limit_client.get(
            "/auth/validate",
            headers=auth_headers
        )
        if response.status_code == 200:
            success_count += 1
        elif response.status_code == 429:
            rate_limited_count += 1

    # /auth/validate has 5/minute limit
    assert success_count <= 5, "Should not exceed auth validate rate limit"
    assert rate_limited_count > 0, "Should have some rate limited requests"


@pytest.mark.anyio
async def test_health_endpoint_not_rate_limited(rate_limit_client):
    """Verify health endpoint is not rate limited."""
    # Make many requests to health endpoint
    for _ in range(20):
        response = await rate_limit_client.get("/health")
        assert response.status_code == 200, "Health endpoint should not be rate limited"


@pytest.mark.anyio
async def test_root_endpoint_not_rate_limited(rate_limit_client):
    """Verify root endpoint is not rate limited."""
    # Make many requests to root endpoint
    for _ in range(20):
        response = await rate_limit_client.get("/")
        assert response.status_code == 200, "Root endpoint should not be rate limited"


@pytest.mark.anyio
async def test_rate_limit_different_endpoints_independent(rate_limit_client, auth_headers):
    """Verify rate limits are tracked per-endpoint."""
    plan = {
        "resource_changes": [
            {
                "address": "aws_instance.test",
                "type": "aws_instance",
                "change": {"actions": ["create"], "after": {}}
            }
        ]
    }

    # Exhaust /analyze rate limit
    for _ in range(12):
        await rate_limit_client.post(
            "/analyze",
            json={"plan_json": plan},
            headers=auth_headers
        )

    # /history should still work (different endpoint)
    response = await rate_limit_client.get(
        "/history",
        headers=auth_headers
    )
    # History doesn't have rate limiting, should always work
    assert response.status_code == 200
