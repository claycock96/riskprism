# Detailed Architecture: Secure AI Analysis Pipeline

This document provides a deep dive into how the **RiskPrism** processes your data, detects security risks, and leverages AI—all while ensuring your sensitive infrastructure details never leave your environment.

## 1. System Overview

### Core Architecture
The system follows a modular "Multi-Analyzer" pattern where a shared backend framework supports pluggable analysis engines (Terraform Plans, IAM Policies, etc.).

**High-Level Components:**
1.  **Frontend (Next.js)**: Context-aware UI that switches input forms and result visualizations based on the selected analyzer.
2.  **Backend (FastAPI)**: REST API with a shared `BaseAnalyzer` abstraction.
3.  **Analyzers**:
    *   **TerraformAnalyzer**: Parses JSON plans, extracts resource diffs.
    *   **IAMPolicyAnalyzer**: Parses policy documents, normalizes statements.
4.  **Risk Engine**: Deterministic rule evaluation logic (specific to each analyzer).
5.  **LLM Integration**: Provider-agnostic client (Bedrock/Anthropic) for generating "Why this matters" explanations.

### Privacy Model
- **Hashing**: All identifiers (Resource Names, ARNs, Account IDs) are hashed locally or on the server before LLM processing.
- **Sanitization**: Values are stripped. Only metadata (keys, actions) is preserved.

---

## 2. Component Design

### 2.1 Backend Class Structure (Multi-Analyzer)

```mermaid
classDiagram
    class BaseAnalyzer {
        +parse(input_data)
        +analyze(parsed_data)
        +sanitize_for_llm(parsed_data)
        +generate_summary(parsed_data)
    }

    class TerraformAnalyzer {
        +extract_diff_skeleton()
        +risk_engine
    }

    class IAMPolicyAnalyzer {
        +normalize_statements()
        +hash_arns()
    }

    class LLMClient {
        +generate_explanation(sanitized_payload)
    }

    BaseAnalyzer <|-- TerraformAnalyzer
    BaseAnalyzer <|-- IAMPolicyAnalyzer
    TerraformAnalyzer ..> LLMClient : sends context
    IAMPolicyAnalyzer ..> LLMClient : sends context
```

### 2.2 Data Flow & Privacy

#### Terraform Flow
1.  **Upload**: User sends Terraform JSON.
2.  **Parse**: `TerraformAnalyzer` extracts resource types, names, and changed attributes.
3.  **Sanitize**: Values are stripped. Resource addresses are hashed (`aws_s3_bucket.main` -> `res_7f8a9b`).
4.  **Analyze**: Rule engine scans for known risks (e.g., `SG-OPEN-INGRESS`).
5.  **Explain**: LLM receives *only* hashed skeleton + risk identifiers.
6.  **Resolve**: Frontend maps `res_7f8a9b` back to `aws_s3_bucket.main` for display.

#### IAM Flow (New)
1.  **Input**: User pastes Policy JSON.
2.  **Parse**: `IAMPolicyAnalyzer` normalizes statements (Actions to lists).
3.  **Sanitize**: ARNs and Account IDs are hashed (`123456789012` -> `acct_a1b2c3`).
4.  **Analyze**: Rule engine checks permissions (e.g., `IAM-ADMIN-STAR`).
5.  **Explain**: LLM explains risks using sanitized/hashed context.

### Layer 3: Intelligence Cache & Persistence (New)
The backend leverages an asynchronous **SQLite** layer and SHA-256 fingerprinting:
- **Fingerprinting**: Every unique plan generates a signature based on its semantic changes.
- **Cost Skip**: If a fingerprint match is found, the backend skips the LLM call entirely and serves the cached reasoning in milliseconds.
- **Audit Trails**: Even on a cache hit, a new Session ID is generated to maintain a traceable paper trail of who requested the analysis.

### Layer 3.5: Concurrency Hardening (Scale)
To handle 20+ simultaneous users without blocking:
- **Async LLM Calls**: We use `AsyncAnthropic` and thread-pooled Bedrock clients so waiting for AI (30s+) never freezes the API.
- **SQLite WAL Mode**: We use Write-Ahead Logging to allow simultaneous reads and writes, preventing "Database is locked" errors under load.
- **Multi-Worker Node**: The container runs 4 Uvicorn workers to parse complex plans in parallel.

### Layer 4: AI Interpretation (LLM)
The LLM (Claude 3.5 Sonnet) receives only the **Sanitized Payload**. It uses its reasoning capabilities to turn raw security findings into a cohesive narrative and PR comment.

### Layer 5: Frontend Re-Mapping
The frontend maintains a local mapping of `Hash -> Original Name`. When the AI refers to `res_9f31a02c1b`, the UI displays `aws_db_instance (prod_db)`. This ensures readability for you without exposing names to the AI.

### Security layer: Team Access (New)
A pre-request validation layer ensures that only clients with the correct `X-Internal-Code` can interact with the API or view stored results.

---

## 🛡️ Data Privacy Proof

We can prove that sensitive information is never sent to the LLM through three methods:

### 1. Automatic Secret Redaction
The parser's denylist automatically strips values for any keys matching sensitive patterns:
- `password`, `secret`, `token`, `apikey`, `private_key`, `user_data`, and more.

### 2. Command: Inspecting the Internal Payload
You can verify the exact payload sent to the LLM by enabling `DEBUG` logs in the backend.

**Run this command to see the size and structure of what goes to the AI:**
```bash
# Check the container logs for the 'Sanitized payload' log line
docker logs terraform-webapp-backend-1 | grep "Sanitized payload size"
```

### 3. Comparison View: Raw vs. Sanitized
Here is what the transformation looks like in practice for a database update:

| Feature | Raw Plan (Internal Only) | Sanitized AI Payload (Leaves Env) |
| :--- | :--- | :--- |
| **Resource Name** | `aws_db_instance.production_customer_data` | `res_a9f31b2c1d` |
| **Engine** | `postgres` | `postgres` (safe classification) |
| **Public IP** | `0.0.0.0/0` | `public_access: true` (boolean token) |
| **Password** | `"P@ssw0rd123!"` | **[DELETED]** (Key excluded by denylist) |
| **Tags** | `Owner: "Chris", Project: "Secret-X"` | **[DELETED]** (Metadata excluded) |

---

## How to Verify Locally
To see the hashing in action without calling the real AI, you can run the backend in **Mock Mode** (by unsetting credentials) and look at the `test_response.json`:

```bash
# Analyze a plan
./test_api.sh

# Inspect the hashed resource references in the findings
jq '.risk_findings[].resource_ref' test_response.json
```

Output will look like:
`"res_7b2e1a4d9c"`
`"res_f3a1d9e2b0"`

_This proves that the IDs seen by the AI (and stored in the session) are disconnected from your actual resource names._
