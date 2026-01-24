# Detailed Architecture: Secure AI Analysis Pipeline

This document provides a deep dive into how the **Terraform Plan Analyzer** processes your data, detects security risks, and leverages AI—all while ensuring your sensitive infrastructure details never leave your environment.

## The 4-Layer Pipeline

The application follows a "Safe-by-Design" architecture that separates data extraction from AI interpretation.

```mermaid
graph TD
    subgraph Backend
        E["Parse & Validate"] --> F["Deterministic Risk Engine"]
        F --> G["Data Sanitization & Hashing"]
        G --> H["Plan Fingerprinting (SHA-256)"]
        H -- "Cache Hit" --> I["Retrieve Cached Result"]
        H -- "Cache Miss" --> J["LLM Reasoning"]
        I --> K["Persistence (SQLite)"]
        J --> K
    end

    subgraph Browser
        A["Upload Plan JSON"] --> B["Map Hashes to Names"]
        B --> C["Display Secure UI"]
    end
    
    K --> B
```

---

## Layer-by-Layer Deep Dive

### Layer 1: Deterministic Risk Engine
Before the AI is involved, the backend executes a suite of Python-based security rules. These rules are **deterministic**—the same plan always produces the same findings.

- **Logic**: Iterates through resource changes using `risk_engine.py`.
- **Extraction**: Instead of raw values, it identifies **Evidence Tokens**.
    - *Raw*: `cidr_block: "0.0.0.0/0"`
    - *Finding*: `{"public_cidr": true}`

### Layer 2: The Parser & Sanitizer
The `parser.py` performs two critical tasks:
1.  **Diff Skeleton**: It identifies *which* fields changed (keys) but ignores the *values*.
2.  **Resource Hashing**: It replaces identifiable resource addresses with 10-character SHA-256 hashes.
    - `aws_db_instance.prod_db` → `res_9f31a02c1b`

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
