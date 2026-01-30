import logging
import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from app.database import init_db
from app.llm_client import LLMClient
from app.models import AnalyzeRequest, AnalyzeResponse
from app.parser import TerraformPlanParser
from app.risk_engine import RiskEngine
from app.session_store import session_store

# Rate Limiter Setup
limiter = Limiter(key_func=get_remote_address)

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Track application start time
START_TIME = datetime.now(UTC)

# Security: Internal Access Code
INTERNAL_ACCESS_CODE = os.getenv("INTERNAL_ACCESS_CODE")

# Configurable settings via environment variables
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
RATE_LIMIT_ANALYZE = os.getenv("RATE_LIMIT_ANALYZE", "10/minute")
RATE_LIMIT_AUTH = os.getenv("RATE_LIMIT_AUTH", "5/minute")
MAX_PAYLOAD_SIZE_MB = int(os.getenv("MAX_PAYLOAD_SIZE_MB", "10"))


async def verify_internal_code(x_internal_code: str | None = Header(None)):
    """
    Dependency to verify the internal access code.
    Note: INTERNAL_ACCESS_CODE is validated at startup - if we reach here, it's configured.
    """
    if x_internal_code != INTERNAL_ACCESS_CODE:
        logger.warning("Unauthorized access attempt with invalid code")
        raise HTTPException(
            status_code=401, detail="Invalid or missing access code. Please enter the team access code."
        )
    return True


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Validate required configuration
    if not INTERNAL_ACCESS_CODE:
        logger.critical("FATAL: INTERNAL_ACCESS_CODE environment variable is not set!")
        logger.critical("Set INTERNAL_ACCESS_CODE to a secure random string (min 32 chars).")
        logger.critical("Generate with: openssl rand -base64 32")
        raise RuntimeError("INTERNAL_ACCESS_CODE must be configured before starting the server")

    if len(INTERNAL_ACCESS_CODE) < 16:
        logger.warning(
            "SECURITY WARNING: INTERNAL_ACCESS_CODE is less than 16 characters. Consider using a longer, random value."
        )

    # Startup: Initialize database
    logger.info("Initializing database...")
    await init_db()
    yield
    # Shutdown: Cleanup if needed
    pass


app = FastAPI(
    title="Security Analysis Platform",
    description="Multi-analyzer security platform: Terraform Plans, IAM Policies, and more",
    version="0.2.0",
    lifespan=lifespan,
)

# Initialize Rate Limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# CORS configuration (configurable via CORS_ORIGINS env var)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
plan_parser = TerraformPlanParser()
risk_engine = RiskEngine()
llm_client = LLMClient()


@app.get("/auth/validate", dependencies=[Depends(verify_internal_code)])
@limiter.limit(RATE_LIMIT_AUTH)
async def validate_auth(request: Request):
    """
    Simple endpoint to verify if the provided access code is valid.
    Returns 200 if valid, otherwise the dependency raises 401.
    """
    return {"status": "valid"}


@app.get("/")
async def root():
    """Health check endpoint"""
    return {"status": "healthy", "service": "terraform-plan-analyzer", "version": "0.1.0"}


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
            "llm": {"status": "healthy", "message": "Unknown status"},
        },
        "version": "0.1.0",
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


@app.post("/analyze", response_model=AnalyzeResponse, dependencies=[Depends(verify_internal_code)])
@app.post("/analyze/terraform", response_model=AnalyzeResponse, dependencies=[Depends(verify_internal_code)])
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_terraform_plan(request: Request, analyze_request: AnalyzeRequest):
    """
    Analyze a Terraform plan JSON for security risks and generate explanation.

    Endpoints:
    - POST /analyze (backward compatible)
    - POST /analyze/terraform (preferred)
    """
    try:
        # Security: payload size check
        content_length = request.headers.get("content-length")
        max_size = MAX_PAYLOAD_SIZE_MB * 1024 * 1024
        if content_length:
            try:
                if int(content_length) > max_size:
                    raise HTTPException(
                        status_code=413, detail=f"Payload too large. Maximum size is {MAX_PAYLOAD_SIZE_MB}MB."
                    )
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid Content-Length header")

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
            max_findings=analyze_request.options.max_findings if analyze_request.options else 50,
        )

        # Step 4: Generate summary stats
        summary = plan_parser.generate_summary(parsed_plan)

        # Step 5: Check Cache (Plan Fingerprinting)
        plan_hash = plan_parser.calculate_plan_hash(diff_skeleton)
        cached_analysis = await session_store.get_by_plan_hash(plan_hash)

        if cached_analysis:
            logger.info(f"CACHE HIT: Serving cached analysis for plan hash {plan_hash}")

            # Respect strict_no_store if specified in request
            no_store = analyze_request.options.strict_no_store if analyze_request.options else False

            if not no_store:
                # Ensure session ID is updated for this new 'request' even if data is cached
                user_ip = request.client.host if request.client else "unknown"
                user_agent = request.headers.get("user-agent", "unknown")

                # Save a new session record (shared analysis, new trace)
                try:
                    session_id = await session_store.save(cached_analysis, user_ip=user_ip, user_agent=user_agent)
                    cached_analysis.session_id = session_id
                except Exception as e:
                    logger.warning(f"Failed to save cached analysis trace: {e}")
            else:
                logger.info("strict_no_store: skipping session trace for cache hit")
                cached_analysis.session_id = None

            return cached_analysis

        # Step 6: Create sanitized payload for LLM
        logger.info("Creating sanitized payload for LLM")
        sanitized_payload = {
            "summary": summary.model_dump(),
            "diff_skeleton": [item.model_dump() for item in diff_skeleton],
            "risk_findings": [finding.model_dump() for finding in risk_findings],
        }

        # Step 7: Call LLM
        logger.info(f"Calling LLM ({llm_client.provider}) for explanation")
        llm_response = await llm_client.generate_explanation(sanitized_payload)

        # Step 8: Build response
        response = AnalyzeResponse(
            summary=summary,
            diff_skeleton=diff_skeleton,
            risk_findings=risk_findings,
            explanation=llm_response["explanation"],
            pr_comment=llm_response["pr_comment"],
            plan_hash=plan_hash,
            cached=False,
        )

        # Step 9: Save to database with audit metadata (unless no_store)
        no_store = analyze_request.options.strict_no_store if analyze_request.options else False

        if not no_store:
            user_ip = request.client.host if request.client else "unknown"
            user_agent = request.headers.get("user-agent", "unknown")
            session_id = await session_store.save(response, user_ip=user_ip, user_agent=user_agent)
            response.session_id = session_id
        else:
            logger.info("strict_no_store: skipping session storage")
            session_id = None
            response.session_id = None

        logger.info(f"Analysis complete. Found {len(risk_findings)} risks. Session ID: {session_id or 'NONE'}")
        return response

    except HTTPException:
        raise
    except ValueError as e:
        logger.error(f"Validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Invalid plan format: {str(e)}")
    except Exception as e:
        logger.error(f"Analysis failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


# ============================================================================
# Example Generation Endpoints
# ============================================================================


@app.post("/generate/terraform", dependencies=[Depends(verify_internal_code)])
@limiter.limit(RATE_LIMIT_ANALYZE)
async def generate_terraform_example(request: Request):
    """
    Generate an example Terraform plan JSON with intentional security issues.

    Uses LLM to generate varied examples, falls back to static example in mock mode.
    """
    try:
        logger.info(f"Generating Terraform example for {request.client.host}")
        result = await llm_client.generate_terraform_example()
        logger.info(f"Generated Terraform example (LLM: {result.get('generated', False)})")
        return result

    except Exception as e:
        logger.error(f"Failed to generate Terraform example: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to generate example: {str(e)}")


@app.post("/generate/iam", dependencies=[Depends(verify_internal_code)])
@limiter.limit(RATE_LIMIT_ANALYZE)
async def generate_iam_example(request: Request):
    """
    Generate an example IAM policy JSON with intentional security issues.

    Uses LLM to generate varied examples, falls back to static example in mock mode.
    """
    try:
        logger.info(f"Generating IAM example for {request.client.host}")
        result = await llm_client.generate_iam_example()
        logger.info(f"Generated IAM example (LLM: {result.get('generated', False)})")
        return result

    except Exception as e:
        logger.error(f"Failed to generate IAM example: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to generate example: {str(e)}")


# ============================================================================
# IAM Policy Analysis Endpoint
# ============================================================================

from app.analyzers import IAMPolicyAnalyzer
from app.models import IAMAnalyzeRequest

# Initialize IAM analyzer
iam_analyzer = IAMPolicyAnalyzer()


@app.post("/analyze/iam", response_model=AnalyzeResponse, dependencies=[Depends(verify_internal_code)])
@limiter.limit(RATE_LIMIT_ANALYZE)
async def analyze_iam_policy(request: Request, analyze_request: IAMAnalyzeRequest):
    """
    Analyze an IAM Policy JSON for security risks.

    Supports:
    - Standard IAM policy documents: {"Version": "...", "Statement": [...]}
    - Wrapped formats: {"policy": {...}} or {"Policy": {...}}

    Returns AnalyzeResponse with session persistence (same format as Terraform).
    """
    try:
        # Security: payload size check
        content_length = request.headers.get("content-length")
        max_size = MAX_PAYLOAD_SIZE_MB * 1024 * 1024
        if content_length:
            try:
                if int(content_length) > max_size:
                    raise HTTPException(
                        status_code=413, detail=f"Payload too large. Maximum size is {MAX_PAYLOAD_SIZE_MB}MB."
                    )
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid Content-Length header")

        logger.info(f"Received IAM policy analysis request from {request.client.host}")

        # Step 1: Parse IAM policy
        logger.info("Parsing IAM policy")
        parsed_policy = iam_analyzer.parse(analyze_request.policy)

        # Step 2: Calculate policy hash for caching
        policy_hash = iam_analyzer.calculate_policy_hash()
        cached_analysis = await session_store.get_by_plan_hash(policy_hash)

        if cached_analysis:
            logger.info(f"CACHE HIT: Serving cached IAM analysis for policy hash {policy_hash}")

            no_store = analyze_request.options.strict_no_store if analyze_request.options else False

            if not no_store:
                # Create new session for this cached result
                user_ip = request.client.host if request.client else "unknown"
                user_agent = request.headers.get("user-agent", "unknown")

                try:
                    session_id = await session_store.save(cached_analysis, user_ip=user_ip, user_agent=user_agent)
                    cached_analysis.session_id = session_id
                except Exception as e:
                    logger.warning(f"Failed to save cached analysis trace: {e}")
            else:
                logger.info("strict_no_store: skipping IAM session trace for cache hit")
                cached_analysis.session_id = None

            return cached_analysis

        # Step 3: Run IAM security rules
        logger.info("Running IAM risk analysis")
        max_findings = analyze_request.options.max_findings if analyze_request.options else 50
        risk_findings = iam_analyzer.analyze(parsed_policy, max_findings=max_findings)

        # Step 4: Generate summary (IAM format)
        summary_dict = iam_analyzer.generate_summary(parsed_policy)

        # Step 5: Create sanitized payload for LLM
        logger.info("Creating sanitized payload for LLM")
        sanitized_payload = iam_analyzer.sanitize_for_llm(parsed_policy, risk_findings)

        # Step 6: Call LLM
        logger.info(f"Calling LLM ({llm_client.provider}) for IAM explanation")
        llm_response = await llm_client.generate_explanation(sanitized_payload)

        # Step 7: Adapt to AnalyzeResponse format (match frontend adaptation)
        from app.models import PlanSummary

        adapted_summary = PlanSummary(
            total_changes=summary_dict["total_statements"],
            creates=summary_dict["allow_statements"],
            updates=0,
            deletes=summary_dict["deny_statements"],
            replaces=0,
            terraform_version=f"IAM Policy v{summary_dict['policy_version']}",
        )

        response = AnalyzeResponse(
            summary=adapted_summary,
            diff_skeleton=[],  # IAM has no resource changes
            risk_findings=risk_findings,
            explanation=llm_response["explanation"],
            pr_comment=llm_response["pr_comment"],
            plan_hash=policy_hash,
            cached=False,
            analyzer_type="iam",
        )

        # Step 8: Save to session store (unless no_store)
        no_store = analyze_request.options.strict_no_store if analyze_request.options else False

        if not no_store:
            user_ip = request.client.host if request.client else "unknown"
            user_agent = request.headers.get("user-agent", "unknown")

            session_id = await session_store.save(response, user_ip=user_ip, user_agent=user_agent)
            response.session_id = session_id
        else:
            logger.info("strict_no_store: skipping IAM session storage")
            session_id = None
            response.session_id = None

        logger.info(f"IAM analysis complete. Found {len(risk_findings)} risks. Session ID: {session_id or 'NONE'}")
        return response

    except HTTPException:
        raise
    except ValueError as e:
        logger.error(f"IAM validation error: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Invalid IAM policy format: {str(e)}")
    except Exception as e:
        logger.error(f"IAM analysis failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"IAM analysis failed: {str(e)}")


@app.get("/results/{session_id}", response_model=AnalyzeResponse, dependencies=[Depends(verify_internal_code)])
async def get_results(session_id: str):
    """Retrieve stored analysis result by session ID."""
    try:
        logger.info(f"Retrieving session: {session_id}")
        analysis = await session_store.get(session_id)

        if analysis is None:
            logger.warning(f"Session not found or expired: {session_id}")
            raise HTTPException(status_code=404, detail="Session not found or expired. Sessions expire after 24 hours.")

        return analysis
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to retrieve session: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to retrieve session: {str(e)}")


@app.get("/history", response_model=list[AnalyzeResponse], dependencies=[Depends(verify_internal_code)])
async def get_history(limit: int = 20):
    """Retrieve recent analysis results."""
    return await session_store.get_all(limit=limit)


@app.get("/sessions/stats", dependencies=[Depends(verify_internal_code)])
async def get_session_stats():
    """Get session storage statistics and application uptime."""
    stats = await session_store.stats()
    uptime = datetime.now(UTC) - START_TIME
    stats["uptime_seconds"] = int(uptime.total_seconds())
    return stats


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
