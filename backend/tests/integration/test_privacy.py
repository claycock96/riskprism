import pytest


@pytest.mark.anyio
async def test_strict_no_store_respected(client):
    # Mock plan data
    plan_json = {
        "resource_changes": [
            {
                "address": "aws_instance.test",
                "type": "aws_instance",
                "change": {"actions": ["create"], "after": {"instance_type": "t2.micro"}},
            }
        ]
    }

    # Request with strict_no_store = True
    response = await client.post(
        "/analyze/terraform",
        json={"plan_json": plan_json, "options": {"strict_no_store": True}},
        headers={"X-Internal-Code": "test-secret"},
    )

    assert response.status_code == 200
    data = response.json()

    # session_id should be None
    assert data["session_id"] is None


@pytest.mark.anyio
async def test_default_storage_behavior(client):
    plan_json = {
        "resource_changes": [
            {
                "address": "aws_instance.test_store",
                "type": "aws_instance",
                "change": {"actions": ["create"], "after": {"instance_type": "t2.micro"}},
            }
        ]
    }

    response = await client.post(
        "/analyze/terraform",
        json={"plan_json": plan_json, "options": {"strict_no_store": False}},
        headers={"X-Internal-Code": "test-secret"},
    )

    assert response.status_code == 200
    data = response.json()

    # session_id should exist
    assert data["session_id"] is not None
    session_id = data["session_id"]

    # Verify we can retrieve it
    res_response = await client.get(f"/results/{session_id}", headers={"X-Internal-Code": "test-secret"})
    assert res_response.status_code == 200
