import pytest
from httpx import AsyncClient
import os

@pytest.mark.asyncio
async def test_endpoint_no_auth_rejected(client):
    """Verify that requests without header are rejected (401)."""
    response = await client.post("/analyze", json={"plan_json": {}})
    assert response.status_code == 401
    assert "Invalid or missing access code" in response.json()["detail"]

@pytest.mark.asyncio
async def test_endpoint_bad_auth_rejected(client):
    """Verify that requests with WRONG header are rejected (401)."""
    response = await client.post("/analyze", json={"plan_json": {}}, headers={"X-Internal-Code": "wrong-secret"})
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_endpoint_valid_auth_accepted(client, auth_headers, mock_plan_json):
    """Verify that legitimate requests are accepted."""
    # We expect 200 OK or 500 (if mock logic fails), but definitely NOT 401
    response = await client.post("/analyze", json={"plan_json": mock_plan_json}, headers=auth_headers)
    assert response.status_code != 401

@pytest.mark.asyncio
async def test_payload_size_limit(client, auth_headers):
    """Verify that massive payloads are rejected (413)."""
    # Simulate a 15MB content-length header
    headers = auth_headers.copy()
    headers["Content-Length"] = str(15 * 1024 * 1024)
    
    response = await client.post("/analyze", json={"plan_json": {}}, headers=headers)
    assert response.status_code == 413
    assert "Payload too large" in response.json()["detail"]
