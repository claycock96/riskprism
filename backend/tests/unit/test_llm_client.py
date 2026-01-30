"""
Unit tests for the LLM client.

Tests cover:
- Initialization with different providers
- Mock mode behavior
- Prompt building for Terraform and IAM
- Response parsing (including edge cases)
- PR comment generation
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.llm_client import LLMClient
from app.models import BedrockExplanation


class TestLLMClientInitialization:
    """Tests for LLM client initialization."""

    def test_default_provider_is_bedrock(self):
        """Default provider should be bedrock when no env var is set."""
        with patch.dict("os.environ", {}, clear=True):
            with patch.object(LLMClient, "_init_bedrock"):
                client = LLMClient()
                assert client.provider == "bedrock"

    def test_anthropic_provider_initialization(self):
        """Anthropic provider should be initialized when specified."""
        with patch.dict(
            "os.environ",
            {"LLM_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "test-key"},  # pragma: allowlist secret
        ):
            client = LLMClient(provider="anthropic")
            assert client.provider == "anthropic"

    def test_unknown_provider_defaults_to_mock(self):
        """Unknown provider should result in mock mode."""
        with patch.dict("os.environ", {"LLM_PROVIDER": "unknown"}):
            client = LLMClient(provider="unknown")
            assert client.provider == "unknown"
            assert client.credentials_valid is False

    def test_bedrock_without_credentials_uses_mock(self):
        """Bedrock client without valid credentials should use mock mode."""
        with patch("boto3.client") as mock_boto:
            with patch("boto3.Session") as mock_session:
                mock_session.return_value.get_credentials.return_value = None
                client = LLMClient(provider="bedrock")
                assert client.credentials_valid is False


class TestMockResponse:
    """Tests for mock response generation."""

    def test_mock_response_contains_summary(self):
        """Mock response should include plan summary."""
        client = LLMClient(provider="mock")
        payload = {
            "summary": {
                "total_changes": 5,
                "creates": 2,
                "updates": 1,
                "deletes": 1,
                "replaces": 1,
            },
            "risk_findings": [
                {"severity": "critical", "risk_id": "TEST-001"},
                {"severity": "high", "risk_id": "TEST-002"},
            ],
        }

        response = client._generate_mock_response(payload)
        response_data = json.loads(response)

        assert "executive_summary" in response_data
        assert len(response_data["executive_summary"]) >= 1
        assert "review_questions" in response_data

    def test_mock_response_counts_severities(self):
        """Mock response should correctly count critical and high findings."""
        client = LLMClient(provider="mock")
        payload = {
            "summary": {"total_changes": 1, "creates": 1, "updates": 0, "deletes": 0, "replaces": 0},
            "risk_findings": [
                {"severity": "critical"},
                {"severity": "critical"},
                {"severity": "high"},
                {"severity": "medium"},
            ],
        }

        response = client._generate_mock_response(payload)
        response_data = json.loads(response)

        # Should mention 2 critical and 1 high in summary
        summary_text = " ".join(response_data["executive_summary"])
        assert "2 critical" in summary_text
        assert "1 high" in summary_text


class TestPromptBuilding:
    """Tests for prompt building."""

    def test_terraform_prompt_contains_required_sections(self):
        """Terraform prompt should include all required instruction sections."""
        client = LLMClient(provider="mock")
        payload = {
            "summary": {"total_changes": 1, "creates": 1, "updates": 0, "deletes": 0, "replaces": 0},
            "risk_findings": [],
            "diff_skeleton": [],
        }

        prompt = client._build_prompt(payload)

        assert "Terraform" in prompt
        assert "EXECUTIVE SUMMARY" in prompt
        assert "TOP RISKS" in prompt
        assert "REVIEW QUESTIONS" in prompt
        assert "JSON" in prompt  # Should ask for JSON response

    def test_iam_prompt_contains_required_sections(self):
        """IAM prompt should include IAM-specific instructions."""
        client = LLMClient(provider="mock")
        payload = {
            "analyzer_type": "iam",
            "summary": {"total_statements": 3, "allow_statements": 2, "deny_statements": 1},
            "risk_findings": [],
        }

        prompt = client._build_prompt(payload)

        assert "IAM" in prompt
        assert "policy" in prompt.lower()
        assert "EXECUTIVE SUMMARY" in prompt
        assert "TOP RISKS" in prompt

    def test_prompt_sanitizes_payload(self):
        """Prompt should include sanitized payload as JSON."""
        client = LLMClient(provider="mock")
        payload = {
            "summary": {"total_changes": 1, "creates": 1, "updates": 0, "deletes": 0, "replaces": 0},
            "risk_findings": [{"risk_id": "TEST-001", "severity": "high"}],
        }

        prompt = client._build_prompt(payload)

        # Should contain the payload as JSON
        assert "TEST-001" in prompt
        assert '"severity"' in prompt or "'severity'" in prompt


class TestResponseParsing:
    """Tests for LLM response parsing."""

    def test_parse_valid_json_response(self):
        """Valid JSON response should be parsed correctly."""
        client = LLMClient(provider="mock")
        response_text = json.dumps(
            {
                "executive_summary": ["Change 1", "Change 2"],
                "plain_english_changes": "Some changes were made.",
                "top_risks_explained": "No critical risks found.",
                "review_questions": ["Is this intentional?"],
            }
        )
        payload = {
            "summary": {"total_changes": 1, "creates": 1, "updates": 0, "deletes": 0, "replaces": 0},
            "risk_findings": [],
        }

        explanation, pr_comment = client._parse_response(response_text, payload)

        assert isinstance(explanation, BedrockExplanation)
        assert len(explanation.executive_summary) == 2
        assert explanation.plain_english_changes == "Some changes were made."
        assert "Change 1" in explanation.executive_summary

    def test_parse_json_with_markdown_fences(self):
        """JSON wrapped in markdown code fences should be parsed."""
        client = LLMClient(provider="mock")
        response_text = """```json
{
    "executive_summary": ["Summary"],
    "plain_english_changes": "Changes",
    "top_risks_explained": "Risks",
    "review_questions": []
}
```"""
        payload = {
            "summary": {"total_changes": 1, "creates": 1, "updates": 0, "deletes": 0, "replaces": 0},
            "risk_findings": [],
        }

        explanation, pr_comment = client._parse_response(response_text, payload)

        assert isinstance(explanation, BedrockExplanation)
        assert explanation.executive_summary == ["Summary"]

    def test_parse_invalid_json_falls_back_to_raw(self):
        """Invalid JSON should fall back to using raw text."""
        client = LLMClient(provider="mock")
        response_text = "This is not valid JSON but a plain text response."
        payload = {
            "summary": {"total_changes": 1, "creates": 1, "updates": 0, "deletes": 0, "replaces": 0},
            "risk_findings": [],
        }

        explanation, pr_comment = client._parse_response(response_text, payload)

        assert isinstance(explanation, BedrockExplanation)
        assert "This is not valid JSON" in explanation.plain_english_changes

    def test_parse_partial_json_uses_defaults(self):
        """Partial JSON response should use defaults for missing fields."""
        client = LLMClient(provider="mock")
        response_text = json.dumps(
            {
                "executive_summary": ["Only summary provided"],
                # Missing other fields
            }
        )
        payload = {
            "summary": {"total_changes": 1, "creates": 1, "updates": 0, "deletes": 0, "replaces": 0},
            "risk_findings": [],
        }

        explanation, pr_comment = client._parse_response(response_text, payload)

        assert explanation.executive_summary == ["Only summary provided"]
        assert explanation.plain_english_changes == ""
        assert explanation.review_questions == []


class TestPRCommentGeneration:
    """Tests for PR comment generation."""

    def test_terraform_pr_comment_format(self):
        """Terraform PR comment should have correct structure."""
        client = LLMClient(provider="mock")
        explanation = BedrockExplanation(
            executive_summary=["Change summary"],
            plain_english_changes="Some changes",
            top_risks_explained="Risk details",
            review_questions=["Check this?"],
        )
        payload = {
            "summary": {"total_changes": 5, "creates": 2, "updates": 1, "deletes": 1, "replaces": 1},
            "risk_findings": [
                {"severity": "critical"},
                {"severity": "high"},
                {"severity": "medium"},
            ],
        }

        comment = client._generate_pr_comment(explanation, payload)

        assert "## 🔍 Terraform Plan Analysis" in comment
        assert "**Total Changes**: 5" in comment
        assert "🔴 **Critical**: 1" in comment
        assert "🟠 **High**: 1" in comment
        assert "### Executive Summary" in comment
        assert "- Change summary" in comment
        assert "### Review Checklist" in comment
        assert "- [ ] Check this?" in comment

    def test_iam_pr_comment_format(self):
        """IAM PR comment should have IAM-specific structure."""
        client = LLMClient(provider="mock")
        explanation = BedrockExplanation(
            executive_summary=["Policy summary"],
            plain_english_changes="Policy allows admin access",
            top_risks_explained="Overly permissive",
            review_questions=["Is admin access needed?"],
        )
        payload = {
            "analyzer_type": "iam",
            "summary": {
                "analyzer_type": "iam",
                "total_statements": 3,
                "allow_statements": 2,
                "deny_statements": 1,
                "wildcard_actions": 1,
                "wildcard_resources": 0,
            },
            "risk_findings": [{"severity": "critical"}],
        }

        comment = client._generate_pr_comment(explanation, payload)

        assert "## 🔐 IAM Policy Analysis" in comment
        assert "**Total Statements**: 3" in comment
        assert "Allow: 2" in comment
        assert "Deny: 1" in comment

    def test_pr_comment_excludes_mock_mode_risks(self):
        """PR comment should not show 'MOCK MODE' in top risks section."""
        client = LLMClient(provider="mock")
        explanation = BedrockExplanation(
            executive_summary=["Summary"],
            plain_english_changes="Changes",
            top_risks_explained="MOCK MODE: This is a test",
            review_questions=[],
        )
        payload = {
            "summary": {"total_changes": 1, "creates": 1, "updates": 0, "deletes": 0, "replaces": 0},
            "risk_findings": [],
        }

        comment = client._generate_pr_comment(explanation, payload)

        # Top Risks section should be skipped when in mock mode
        assert "### Top Risks" not in comment


class TestGenerateExplanation:
    """Integration tests for the full generate_explanation flow."""

    @pytest.mark.anyio
    async def test_generate_explanation_mock_mode(self):
        """Generate explanation should work in mock mode."""
        client = LLMClient(provider="mock")
        payload = {
            "summary": {"total_changes": 3, "creates": 1, "updates": 1, "deletes": 1, "replaces": 0},
            "risk_findings": [{"severity": "high", "risk_id": "TEST-001"}],
            "diff_skeleton": [],
        }

        result = await client.generate_explanation(payload)

        assert "explanation" in result
        assert "pr_comment" in result
        assert isinstance(result["explanation"], BedrockExplanation)
        assert "Terraform Plan Analysis" in result["pr_comment"]

    @pytest.mark.anyio
    async def test_generate_explanation_anthropic_fallback(self):
        """Anthropic provider should fall back to mock on API error."""
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):  # pragma: allowlist secret
            client = LLMClient(provider="anthropic")
            client.anthropic_client = AsyncMock()
            client.anthropic_client.messages.create.side_effect = Exception("API Error")

            payload = {
                "summary": {"total_changes": 1, "creates": 1, "updates": 0, "deletes": 0, "replaces": 0},
                "risk_findings": [],
                "diff_skeleton": [],
            }

            result = await client.generate_explanation(payload)

            # Should still return a valid response (mock fallback)
            assert "explanation" in result
            assert isinstance(result["explanation"], BedrockExplanation)

    @pytest.mark.anyio
    async def test_generate_explanation_bedrock_fallback(self):
        """Bedrock provider should fall back to mock on API error."""
        with patch("boto3.client") as mock_boto:
            with patch("boto3.Session") as mock_session:
                mock_session.return_value.get_credentials.return_value = MagicMock()
                client = LLMClient(provider="bedrock")
                client.credentials_valid = True
                client.client = MagicMock()
                client.client.invoke_model.side_effect = Exception("Bedrock Error")

                payload = {
                    "summary": {"total_changes": 1, "creates": 1, "updates": 0, "deletes": 0, "replaces": 0},
                    "risk_findings": [],
                    "diff_skeleton": [],
                }

                result = await client.generate_explanation(payload)

                # Should still return a valid response (mock fallback)
                assert "explanation" in result
                assert isinstance(result["explanation"], BedrockExplanation)


class TestExampleGeneration:
    """Tests for LLM example generation."""

    @pytest.mark.anyio
    async def test_generate_terraform_example_mock_mode(self):
        """Terraform example generation should work in mock mode."""
        client = LLMClient(provider="mock")

        result = await client.generate_terraform_example()

        assert "example" in result
        assert "description" in result
        assert "generated" in result
        assert result["generated"] is False  # Mock mode uses static example
        assert "format_version" in result["example"]
        assert "resource_changes" in result["example"]

    @pytest.mark.anyio
    async def test_generate_iam_example_mock_mode(self):
        """IAM example generation should work in mock mode."""
        client = LLMClient(provider="mock")

        result = await client.generate_iam_example()

        assert "example" in result
        assert "description" in result
        assert "generated" in result
        assert result["generated"] is False  # Mock mode uses static example
        assert "Version" in result["example"]
        assert "Statement" in result["example"]

    @pytest.mark.anyio
    async def test_generate_terraform_example_llm_success(self):
        """Terraform example generation should use LLM when available."""
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):  # pragma: allowlist secret
            client = LLMClient(provider="anthropic")
            client.anthropic_client = AsyncMock()

            mock_response = MagicMock()
            mock_response.content = [MagicMock()]
            mock_response.content[0].text = json.dumps(
                {"format_version": "0.1", "resource_changes": [{"address": "aws_s3_bucket.test"}]}
            )
            client.anthropic_client.messages.create = AsyncMock(return_value=mock_response)

            result = await client.generate_terraform_example()

            assert result["generated"] is True
            assert "example" in result
            assert "format_version" in result["example"]

    @pytest.mark.anyio
    async def test_generate_iam_example_llm_success(self):
        """IAM example generation should use LLM when available."""
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):  # pragma: allowlist secret
            client = LLMClient(provider="anthropic")
            client.anthropic_client = AsyncMock()

            mock_response = MagicMock()
            mock_response.content = [MagicMock()]
            mock_response.content[0].text = json.dumps(
                {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
            )
            client.anthropic_client.messages.create = AsyncMock(return_value=mock_response)

            result = await client.generate_iam_example()

            assert result["generated"] is True
            assert "example" in result
            assert "Version" in result["example"]

    @pytest.mark.anyio
    async def test_generate_terraform_example_fallback_on_error(self):
        """Terraform example should fall back to static on LLM error."""
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):  # pragma: allowlist secret
            client = LLMClient(provider="anthropic")
            client.anthropic_client = AsyncMock()
            client.anthropic_client.messages.create.side_effect = Exception("API Error")

            result = await client.generate_terraform_example()

            # Should fall back to static example
            assert result["generated"] is False
            assert "example" in result
            assert "format_version" in result["example"]

    @pytest.mark.anyio
    async def test_generate_iam_example_fallback_on_error(self):
        """IAM example should fall back to static on LLM error."""
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "test-key"}):  # pragma: allowlist secret
            client = LLMClient(provider="anthropic")
            client.anthropic_client = AsyncMock()
            client.anthropic_client.messages.create.side_effect = Exception("API Error")

            result = await client.generate_iam_example()

            # Should fall back to static example
            assert result["generated"] is False
            assert "example" in result
            assert "Version" in result["example"]

    def test_static_terraform_example_has_security_issues(self):
        """Static Terraform example should contain intentional security issues."""
        client = LLMClient(provider="mock")
        result = client._get_static_terraform_example()

        example = result["example"]
        # Should have a security group with 0.0.0.0/0
        sg_found = False
        for change in example["resource_changes"]:
            if change["type"] == "aws_security_group":
                ingress = change["change"]["after"].get("ingress", [])
                for rule in ingress:
                    if "0.0.0.0/0" in rule.get("cidr_blocks", []):
                        sg_found = True
        assert sg_found, "Static example should have open security group"

    def test_static_iam_example_has_security_issues(self):
        """Static IAM example should contain intentional security issues."""
        client = LLMClient(provider="mock")
        result = client._get_static_iam_example()

        example = result["example"]
        # Should have wildcard permissions
        wildcard_found = False
        for statement in example["Statement"]:
            if statement.get("Action") == "*" and statement.get("Resource") == "*":
                wildcard_found = True
        assert wildcard_found, "Static example should have wildcard permissions"
