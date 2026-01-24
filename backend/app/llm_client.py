import json
import logging
import os
from typing import Dict, Any, Optional
import boto3
from botocore.config import Config

from app.models import BedrockExplanation

logger = logging.getLogger(__name__)


class LLMClient:
    """
    LLM client for generating plain-English explanations.

    Supports multiple providers:
    - Anthropic API (direct Claude access)
    - AWS Bedrock (Claude via Bedrock)
    - Mock mode (fallback when no credentials)

    Security: Only receives sanitized payloads (no raw plan data).
    """

    def __init__(
        self,
        provider: Optional[str] = None,
        region: str = "us-east-1",
        bedrock_model_id: Optional[str] = None,
        anthropic_model: Optional[str] = None
    ):
        """
        Initialize LLM client.

        Args:
            provider: LLM provider ("anthropic" or "bedrock"). If None, reads from LLM_PROVIDER env var
            region: AWS region for Bedrock
            bedrock_model_id: Bedrock model ID (reads from BEDROCK_MODEL_ID env var if not provided)
            anthropic_model: Anthropic API model name (reads from ANTHROPIC_MODEL env var if not provided)
        """
        self.provider = provider or os.getenv("LLM_PROVIDER", "bedrock")
        self.region = region
        self.bedrock_model_id = bedrock_model_id or os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-5-sonnet-20241022-v2:0")
        self.anthropic_model = anthropic_model or os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-20241022")
        self.credentials_valid = False
        self.client = None
        self.anthropic_client = None

        if self.provider == "anthropic":
            self._init_anthropic()
        elif self.provider == "bedrock":
            self._init_bedrock()
        else:
            logger.warning(f"Unknown provider '{self.provider}', defaulting to mock mode")

    def _init_anthropic(self):
        """Initialize Anthropic API client"""
        try:
            import anthropic

            api_key = os.getenv("ANTHROPIC_API_KEY")
            if api_key:
                self.anthropic_client = anthropic.Anthropic(api_key=api_key)
                self.credentials_valid = True
                logger.info(f"Anthropic client initialized (model: {self.anthropic_model})")
            else:
                logger.warning("ANTHROPIC_API_KEY not set. Will operate in mock mode.")
        except ImportError:
            logger.warning("anthropic package not installed. Will operate in mock mode.")
        except Exception as e:
            logger.warning(f"Anthropic client initialization failed: {e}. Will operate in mock mode.")

    def _init_bedrock(self):
        """Initialize AWS Bedrock client"""
        config = Config(
            region_name=self.region,
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
                    logger.info(f"Bedrock client initialized with valid credentials (model: {self.bedrock_model_id})")
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

        # Call appropriate provider (or mock if not available)
        response_text = None

        if self.provider == "anthropic" and self.anthropic_client:
            try:
                response_text = await self._call_anthropic(prompt)
            except Exception as e:
                logger.warning(f"Anthropic API call failed ({str(e)}), falling back to mock mode")
                response_text = self._generate_mock_response(sanitized_payload)
        elif self.provider == "bedrock" and self.client:
            try:
                response_text = await self._call_bedrock(prompt)
            except Exception as e:
                logger.warning(f"Bedrock call failed ({str(e)}), falling back to mock mode")
                response_text = self._generate_mock_response(sanitized_payload)
        else:
            logger.warning(f"LLM provider '{self.provider}' not available, using mock response")
            response_text = self._generate_mock_response(sanitized_payload)

        # Parse response
        explanation, pr_comment = self._parse_response(response_text, sanitized_payload)

        return {
            "explanation": explanation,
            "pr_comment": pr_comment
        }

    def _build_prompt(self, sanitized_payload: Dict[str, Any]) -> str:
        """
        Build prompt for LLM with sanitized data.

        The prompt instructs the model to:
        - Not invent resource names or IDs
        - Use only provided sanitized facts
        - Generate structured output
        """
        # Convert to JSON for structured input
        payload_json = json.dumps(sanitized_payload, indent=2, default=str)

        # Log the sanitized payload size for debugging
        logger.debug(f"Sanitized payload size: {len(payload_json)} characters")

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

3. TOP RISKS (REASONING ONLY)
   - **CRITICAL**: Do NOT identify any new risks. Only explain the `risk_findings` provided above.
   - **NO COUNTS**: Never mention the total number of risks (e.g., dont say "Found 5 risks"). The UI handles all data counting.
   - **MANDATORY FORMATTING**:
     - Use a Level 3 header `###` for each risk title.
     - Use bold keys for details:
       - **Risk**: A brief description.
       - **Why This Matters**: The security implication.
       - **Attack Scenario**: A realistic exploit example.
     - Ensure there is a blank line between each risk item.

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

    async def _call_anthropic(self, prompt: str) -> str:
        """
        Call Anthropic API directly.

        Args:
            prompt: Formatted prompt

        Returns:
            Model response text
        """
        try:
            logger.info(f"Calling Anthropic API (model: {self.anthropic_model})")

            message = self.anthropic_client.messages.create(
                model=self.anthropic_model,
                max_tokens=4096,
                temperature=0.3,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )

            response_text = message.content[0].text
            logger.info("Anthropic API call successful")
            return response_text

        except Exception as e:
            logger.error(f"Anthropic API call failed: {e}")
            raise

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
                "temperature": 0.3,
            }

            logger.info(f"Calling Bedrock model: {self.bedrock_model_id}")

            response = self.client.invoke_model(
                modelId=self.bedrock_model_id,
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
        Generate mock response when LLM is not available.

        Useful for local development without credentials.
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
            "top_risks_explained": f"MOCK MODE: LLM provider '{self.provider}' not configured. See risk_findings in the response for detailed security issues detected by the rule engine.",
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
        Parse LLM response into structured format.

        Args:
            response_text: Raw response from LLM
            sanitized_payload: Original sanitized payload

        Returns:
            Tuple of (BedrockExplanation, pr_comment string)
        """
        try:
            # Strip markdown code fences if present (Claude sometimes wraps JSON in ```json ... ```)
            cleaned_text = response_text.strip()
            if cleaned_text.startswith("```json"):
                cleaned_text = cleaned_text[7:]  # Remove ```json
            if cleaned_text.startswith("```"):
                cleaned_text = cleaned_text[3:]  # Remove ```
            if cleaned_text.endswith("```"):
                cleaned_text = cleaned_text[:-3]  # Remove trailing ```
            cleaned_text = cleaned_text.strip()

            # Try to parse JSON response
            response_data = json.loads(cleaned_text)

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
            logger.warning("Failed to parse LLM response as JSON, using fallback")

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
            "_Generated by Terraform Plan Analyzer_"
        ])

        return "\n".join(comment_parts)
