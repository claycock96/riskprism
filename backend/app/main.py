from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import logging
from datetime import datetime

from app.parser import TerraformPlanParser
from app.risk_engine import RiskEngine
from app.llm_client import LLMClient
from app.models import AnalyzeRequest, AnalyzeResponse
from app.session_store import session_store

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Track application start time
START_TIME = datetime.utcnow()

app = FastAPI(
    title="Terraform Plan Analyzer",
    description="Analyzes Terraform plans for security risks and generates explanations",
    version="0.1.0"
)

# CORS configuration for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Next.js default port
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
plan_parser = TerraformPlanParser()
risk_engine = RiskEngine()
llm_client = LLMClient()


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "terraform-plan-analyzer",
        "version": "0.1.0"
    }


@app.get("/health")
async def health():
    """
    Detailed health check that validates all components.

    Returns:
        - status: overall health (healthy/degraded/unhealthy)
        - components: status of each component with details
    """
    health_status = {
        "status": "healthy",
        "components": {}
    }

    # Test parser
    try:
        minimal_plan = {
            "terraform_version": "1.0.0",
            "resource_changes": []
        }
        plan_parser.parse(minimal_plan)
        health_status["components"]["parser"] = {
            "status": "healthy",
            "message": "Parser operational"
        }
    except Exception as e:
        health_status["components"]["parser"] = {
            "status": "unhealthy",
            "message": f"Parser failed: {str(e)}"
        }
        health_status["status"] = "unhealthy"

    # Test risk engine
    try:
        rule_count = len(risk_engine.rules)
        if rule_count > 0:
            health_status["components"]["risk_engine"] = {
                "status": "healthy",
                "message": f"{rule_count} rules loaded"
            }
        else:
            health_status["components"]["risk_engine"] = {
                "status": "degraded",
                "message": "No rules loaded"
            }
            if health_status["status"] == "healthy":
                health_status["status"] = "degraded"
    except Exception as e:
        health_status["components"]["risk_engine"] = {
            "status": "unhealthy",
            "message": f"Risk engine failed: {str(e)}"
        }
        health_status["status"] = "unhealthy"

    # Test LLM client
    try:
        if llm_client.credentials_valid:
            if llm_client.provider == "anthropic":
                health_status["components"]["llm"] = {
                    "status": "healthy",
                    "message": f"Anthropic API connected (model: {llm_client.anthropic_model})",
                    "provider": "anthropic",
                    "mode": "api"
                }
            elif llm_client.provider == "bedrock":
                health_status["components"]["llm"] = {
                    "status": "healthy",
                    "message": f"Bedrock connected with valid credentials (model: {llm_client.bedrock_model_id})",
                    "provider": "bedrock",
                    "mode": "api"
                }
        else:
            health_status["components"]["llm"] = {
                "status": "degraded",
                "message": f"Running in mock mode (provider '{llm_client.provider}' credentials not configured)",
                "provider": llm_client.provider,
                "mode": "mock"
            }
            if health_status["status"] == "healthy":
                health_status["status"] = "degraded"
    except Exception as e:
        health_status["components"]["llm"] = {
            "status": "unhealthy",
            "message": f"LLM client failed: {str(e)}",
            "provider": "unknown",
            "mode": "unknown"
        }
        health_status["status"] = "unhealthy"

    return health_status


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_plan(request: AnalyzeRequest):
    """
    Analyze a Terraform plan JSON for security risks and generate explanation.

    This endpoint:
    1. Parses the Terraform plan JSON
    2. Extracts a minimal diff skeleton
    3. Runs deterministic risk rules
    4. Sanitizes data for Bedrock
    5. Generates plain-English explanation via Bedrock
    """
    try:
        logger.info("Received plan analysis request")

        # Step 1: Parse Terraform plan JSON
        logger.info("Parsing Terraform plan JSON")
        parsed_plan = plan_parser.parse(request.plan_json)

        # Step 2: Extract diff skeleton (minimized representation)
        logger.info("Extracting diff skeleton")
        diff_skeleton = plan_parser.extract_diff_skeleton(parsed_plan)

        # Step 3: Run risk engine
        logger.info("Running risk analysis")
        risk_findings = risk_engine.analyze(
            parsed_plan,
            diff_skeleton,
            max_findings=request.options.max_findings if request.options else 50
        )

        # Step 4: Generate summary stats
        summary = plan_parser.generate_summary(parsed_plan)

        # Step 5: Create sanitized payload for Bedrock
        logger.info("Creating sanitized payload for Bedrock")
        sanitized_payload = {
            "summary": summary.dict(),
            "diff_skeleton": [item.dict() for item in diff_skeleton],
            "risk_findings": [finding.dict() for finding in risk_findings],
        }

        # Step 6: Call LLM for plain-English explanation
        logger.info(f"Calling LLM ({llm_client.provider}) for explanation")
        llm_response = await llm_client.generate_explanation(sanitized_payload)

        # Step 7: Build response
        response = AnalyzeResponse(
            summary=summary,
            diff_skeleton=diff_skeleton,
            risk_findings=risk_findings,
            explanation=llm_response["explanation"],
            pr_comment=llm_response["pr_comment"]
        )

        # Step 8: Save to session store and add session_id
        session_id = session_store.save(response)
        response.session_id = session_id

        logger.info(f"Analysis complete. Found {len(risk_findings)} risks. Session ID: {session_id}")
        return response

    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Invalid plan format: {str(e)}")
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.get("/results/{session_id}", response_model=AnalyzeResponse)
async def get_results(session_id: str):
    """
    Retrieve a stored analysis result by session ID.

    Allows CLI users to share results and view full analysis in the web UI.
    Sessions are stored in-memory for 24 hours.
    """
    try:
        logger.info(f"Retrieving session: {session_id}")
        analysis = session_store.get(session_id)

        if analysis is None:
            logger.warning(f"Session not found or expired: {session_id}")
            raise HTTPException(
                status_code=404,
                detail="Session not found or expired. Sessions expire after 24 hours."
            )

        logger.info(f"Session retrieved successfully: {session_id}")
        return analysis

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve session: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to retrieve session: {str(e)}")


@app.get("/sessions/stats")
async def get_session_stats():
    """
    Get session storage statistics and application uptime.
    Useful for monitoring and debugging.
    """
    stats = session_store.stats()
    uptime = datetime.utcnow() - START_TIME
    stats["uptime_seconds"] = int(uptime.total_seconds())
    return stats


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
