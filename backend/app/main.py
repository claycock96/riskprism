from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
import logging
from datetime import datetime
from contextlib import asynccontextmanager

from app.parser import TerraformPlanParser
from app.risk_engine import RiskEngine
from app.llm_client import LLMClient
from app.models import AnalyzeRequest, AnalyzeResponse
from app.session_store import session_store
from app.database import init_db

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Track application start time
START_TIME = datetime.utcnow()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize database
    logger.info("Initializing database...")
    await init_db()
    yield
    # Shutdown: Cleanup if needed
    pass

app = FastAPI(
    title="Terraform Plan Analyzer",
    description="Analyzes Terraform plans for security risks and generates explanations",
    version="0.1.0",
    lifespan=lifespan
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
    """
    health_status = {
        "status": "healthy",
        "components": {
            "parser": {"status": "healthy", "message": "Initialized"},
            "risk_engine": {"status": "healthy", "message": f"{len(risk_engine.rules)} rules loaded"},
            "llm": {"status": "healthy", "message": "Unknown status"}
        },
        "version": "0.1.0"
    }
    
    # Check LLM
    if llm_client.credentials_valid:
        health_status["components"]["llm"]["status"] = "healthy"
        health_status["components"]["llm"]["message"] = "Credentials valid"
        health_status["components"]["llm"]["provider"] = llm_client.provider
        health_status["components"]["llm"]["mode"] = "live"
    else:
        health_status["components"]["llm"]["status"] = "degraded"
        health_status["components"]["llm"]["message"] = "No credentials, operating in mock mode"
        health_status["components"]["llm"]["provider"] = llm_client.provider
        health_status["components"]["llm"]["mode"] = "mock"
        health_status["status"] = "degraded"

    return health_status


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_plan(request: Request, analyze_request: AnalyzeRequest):
    """
    Analyze a Terraform plan JSON for security risks and generate explanation.
    """
    try:
        logger.info(f"Received plan analysis request from {request.client.host}")

        # Step 1: Parse Terraform plan JSON
        logger.info("Parsing Terraform plan JSON")
        parsed_plan = plan_parser.parse(analyze_request.plan_json)

        # Step 2: Extract diff skeleton
        logger.info("Extracting diff skeleton")
        diff_skeleton = plan_parser.extract_diff_skeleton(parsed_plan)

        # Step 3: Run risk engine
        logger.info("Running risk analysis")
        risk_findings = risk_engine.analyze(
            parsed_plan,
            diff_skeleton,
            max_findings=analyze_request.options.max_findings if analyze_request.options else 50
        )

        # Step 4: Generate summary stats
        summary = plan_parser.generate_summary(parsed_plan)

        # Step 5: Create sanitized payload for LLM
        logger.info("Creating sanitized payload for LLM")
        sanitized_payload = {
            "summary": summary.model_dump(),
            "diff_skeleton": [item.model_dump() for item in diff_skeleton],
            "risk_findings": [finding.model_dump() for finding in risk_findings],
        }

        # Step 6: Call LLM
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

        # Step 8: Save to database with audit metadata
        user_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "unknown")
        
        session_id = await session_store.save(
            response,
            user_ip=user_ip,
            user_agent=user_agent
        )
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
    """Retrieve stored analysis result by session ID."""
    try:
        logger.info(f"Retrieving session: {session_id}")
        analysis = await session_store.get(session_id)

        if analysis is None:
            logger.warning(f"Session not found or expired: {session_id}")
            raise HTTPException(
                status_code=404,
                detail="Session not found or expired. Sessions expire after 24 hours."
            )

        return analysis
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve session: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to retrieve session: {str(e)}")


@app.get("/history", response_model=List[AnalyzeResponse])
async def get_history(limit: int = 20):
    """Retrieve recent analysis results."""
    return await session_store.get_all(limit=limit)


@app.get("/sessions/stats")
async def get_session_stats():
    """Get session storage statistics and application uptime."""
    stats = await session_store.stats()
    uptime = datetime.utcnow() - START_TIME
    stats["uptime_seconds"] = int(uptime.total_seconds())
    return stats


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
