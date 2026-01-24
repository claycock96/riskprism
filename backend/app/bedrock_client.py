import json
import logging
from typing import Dict, Any
import boto3
from botocore.config import Config

from app.models import BedrockExplanation

logger = logging.getLogger(__name__)


class BedrockClient:
    """
    AWS Bedrock client for generating plain-English explanations.

    Uses Claude on Bedrock to transform sanitized plan data into
    human-readable explanations and PR comments.

    Security: Only receives sanitized payloads (no raw plan data).
    """

    def __init__(self, region: str = "us-east-1", model_id: str = "anthropic.claude-3-5-sonnet-20241022-v2:0"):
        """
        Initialize Bedrock client.

        Args:
            region: AWS region for Bedrock
            model_id: Bedrock model ID (default: Claude 3.5 Sonnet)
        """
        self.region = region
        self.model_id = model_id
        self.credentials_valid = False

        # Configure boto3 with retry logic
        config = Config(
            region_name=region,
            retries={
                'max_attempts': 3,
                'mode': 'adaptive'
            }
        )

        try:
            self.client = boto3.client('bedrock-runtime', config=config)
            # Test if credentials are actually valid
            try:
                session = boto3.Session()
                credentials = session.get_credentials()
                if credentials:
                    self.credentials_valid = True
                    logger.info(f"Bedrock client initialized with valid credentials (model: {model_id})")
                else:
                    logger.warning("Bedrock client initialized but no AWS credentials found. Will operate in mock mode.")
            except Exception as cred_error:
                logger.warning(f"AWS credentials not available: {cred_error}. Will operate in mock mode.")
        except Exception as e:
            logger.warning(f"Bedrock client initialization failed: {e}. Will operate in mock mode.")
            self.client = None

    async def generate_explanation(self, sanitized_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate plain-English explanation from sanitized plan data.

        Args:
            sanitized_payload: Sanitized data containing:
                - summary: PlanSummary
                - diff_skeleton: List[ResourceChange]
                - risk_findings: List[RiskFinding]

        Returns:
            Dict with 'explanation' (BedrockExplanation) and 'pr_comment' (str)
        """
        # Build prompt
        prompt = self._build_prompt(sanitized_payload)

        # Call Bedrock (or mock if not available)
        response_text = None
        if self.client:
            try:
                response_text = await self._call_bedrock(prompt)
            except Exception as e:
                logger.warning(f"Bedrock call failed ({str(e)}), falling back to mock mode")
                response_text = self._generate_mock_response(sanitized_payload)
        else:
            logger.warning("Bedrock client not available, using mock response")
            response_text = self._generate_mock_response(sanitized_payload)

        # Parse response
        explanation, pr_comment = self._parse_response(response_text, sanitized_payload)

        return {
            "explanation": explanation,
            "pr_comment": pr_comment
        }

    def _build_prompt(self, sanitized_payload: Dict[str, Any]) -> str:
        """
        Build prompt for Bedrock with sanitized data.

        The prompt instructs the model to:
        - Not invent resource names or IDs
        - Use only provided sanitized facts
        - Generate structured output
        """
        summary = sanitized_payload["summary"]
        risk_findings = sanitized_payload["risk_findings"]

        # Convert to JSON for structured input
        payload_json = json.dumps(sanitized_payload, indent=2, default=str)

        prompt = f"""You are an AWS infrastructure and Terraform security reviewer. Your task is to analyze a Terraform plan and generate a clear, actionable review.

IMPORTANT CONSTRAINTS:
- Do NOT invent resource names, IDs, or specific identifiers
- Use ONLY the sanitized facts provided in the payload
- If information is missing, say so and suggest what the reviewer should check
- Focus on the risk findings and their security implications

INPUT DATA (Sanitized):
{payload_json}

Generate a structured review with the following sections:

1. EXECUTIVE SUMMARY (2-5 bullets)
   - High-level overview of changes
   - Call out critical risks immediately

2. CHANGES OVERVIEW
   - Group by resource type and action (create/update/delete/replace)
   - Use generic descriptions (e.g., "2 security groups being created")
   - Mention changed attribute categories without specific values

3. TOP RISKS
   - Explain each CRITICAL and HIGH severity finding
   - Relate findings to security best practices
   - Be specific about the implications

4. REVIEW QUESTIONS
   - What the reviewer should double-check
   - Configuration details to verify
   - Potential dependencies or blast radius concerns

Format your response as JSON with this structure:
{{
  "executive_summary": ["bullet 1", "bullet 2", ...],
  "plain_english_changes": "... grouped description ...",
  "top_risks_explained": "... explanation of critical risks ...",
  "review_questions": ["question 1", "question 2", ...]
}}
"""
        return prompt

    async def _call_bedrock(self, prompt: str) -> str:
        """
        Call AWS Bedrock API.

        Args:
            prompt: Formatted prompt

        Returns:
            Model response text
        """
        try:
            # Bedrock API request body for Claude
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 4096,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": 0.3,  # Lower temperature for more consistent output
            }

            logger.info(f"Calling Bedrock model: {self.model_id}")

            response = self.client.invoke_model(
                modelId=self.model_id,
                body=json.dumps(request_body)
            )

            # Parse response
            response_body = json.loads(response['body'].read())
            response_text = response_body['content'][0]['text']

            logger.info("Bedrock call successful")
            return response_text

        except Exception as e:
            logger.error(f"Bedrock API call failed: {e}")
            raise

    def _generate_mock_response(self, sanitized_payload: Dict[str, Any]) -> str:
        """
        Generate mock response when Bedrock is not available.

        Useful for local development without AWS credentials.
        """
        summary = sanitized_payload["summary"]
        risk_findings = sanitized_payload["risk_findings"]

        critical_count = sum(1 for f in risk_findings if f.get("severity") == "critical")
        high_count = sum(1 for f in risk_findings if f.get("severity") == "high")

        mock_response = {
            "executive_summary": [
                f"Terraform plan creates {summary['creates']} resources, updates {summary['updates']}, deletes {summary['deletes']}, replaces {summary['replaces']}",
                f"Found {len(risk_findings)} security findings ({critical_count} critical, {high_count} high severity)",
                "Review required before applying changes"
            ],
            "plain_english_changes": f"This plan modifies {summary['total_changes']} resources. The changes include infrastructure updates that require security review. Check the risk findings below for specific concerns.",
            "top_risks_explained": "MOCK MODE: Bedrock not configured. See risk_findings in the response for detailed security issues detected by the rule engine.",
            "review_questions": [
                "Are the security group rules appropriately scoped?",
                "Do IAM policies follow least privilege?",
                "Is encryption enabled for data at rest?",
                "Are public access configurations intentional and approved?"
            ]
        }

        return json.dumps(mock_response)

    def _parse_response(
        self,
        response_text: str,
        sanitized_payload: Dict[str, Any]
    ) -> tuple[BedrockExplanation, str]:
        """
        Parse Bedrock response into structured format.

        Args:
            response_text: Raw response from Bedrock
            sanitized_payload: Original sanitized payload

        Returns:
            Tuple of (BedrockExplanation, pr_comment string)
        """
        try:
            # Try to parse JSON response
            response_data = json.loads(response_text)

            explanation = BedrockExplanation(
                executive_summary=response_data.get("executive_summary", []),
                plain_english_changes=response_data.get("plain_english_changes", ""),
                top_risks_explained=response_data.get("top_risks_explained", ""),
                review_questions=response_data.get("review_questions", [])
            )

            # Generate PR comment
            pr_comment = self._generate_pr_comment(explanation, sanitized_payload)

            return explanation, pr_comment

        except json.JSONDecodeError:
            logger.warning("Failed to parse Bedrock response as JSON, using fallback")

            # Fallback: use raw text
            explanation = BedrockExplanation(
                executive_summary=["See full explanation below"],
                plain_english_changes=response_text,
                top_risks_explained="",
                review_questions=[]
            )

            pr_comment = f"## Terraform Plan Review\n\n{response_text}"

            return explanation, pr_comment

    def _generate_pr_comment(
        self,
        explanation: BedrockExplanation,
        sanitized_payload: Dict[str, Any]
    ) -> str:
        """
        Generate formatted PR comment text.

        Args:
            explanation: Parsed explanation
            sanitized_payload: Original sanitized payload

        Returns:
            Markdown-formatted PR comment
        """
        summary = sanitized_payload["summary"]
        risk_findings = sanitized_payload["risk_findings"]

        # Count by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }

        for finding in risk_findings:
            severity = finding.get("severity", "info")
            severity_counts[severity] += 1

        # Build PR comment
        comment_parts = [
            "## 🔍 Terraform Plan Analysis",
            "",
            "### Summary",
            f"- **Total Changes**: {summary['total_changes']}",
            f"- Creates: {summary['creates']}, Updates: {summary['updates']}, Deletes: {summary['deletes']}, Replaces: {summary['replaces']}",
            "",
            "### Security Findings",
            f"- 🔴 **Critical**: {severity_counts['critical']}",
            f"- 🟠 **High**: {severity_counts['high']}",
            f"- 🟡 **Medium**: {severity_counts['medium']}",
            f"- 🔵 **Low**: {severity_counts['low']}",
            "",
        ]

        if explanation.executive_summary:
            comment_parts.extend([
                "### Executive Summary",
                ""
            ])
            for bullet in explanation.executive_summary:
                comment_parts.append(f"- {bullet}")
            comment_parts.append("")

        if explanation.top_risks_explained and "MOCK MODE" not in explanation.top_risks_explained:
            comment_parts.extend([
                "### Top Risks",
                "",
                explanation.top_risks_explained,
                ""
            ])

        if explanation.review_questions:
            comment_parts.extend([
                "### Review Checklist",
                ""
            ])
            for question in explanation.review_questions:
                comment_parts.append(f"- [ ] {question}")
            comment_parts.append("")

        comment_parts.extend([
            "---",
            "_Generated by [Terraform Plan Analyzer](https://github.com/yourusername/terraform-plan-analyzer)_"
        ])

        return "\n".join(comment_parts)
