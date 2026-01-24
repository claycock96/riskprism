# Terraform Plan Explainer + Risk Gate — Design Doc (design.md)

Owner: Chris  
Audience: DevOps / Cloud Engineering team  
Status: Draft (MVP-focused)

---

## 1) Problem Statement

Terraform plans are hard to review quickly and consistently across a multi-account AWS environment. Reviewers must:
- Understand *what* is changing (creates/updates/deletes/replacements)
- Assess *risk* (public exposure, IAM privilege expansion, encryption removal, destructive ops)
- Produce consistent review notes for PRs / change boards

We want a web app that:
1) Ingests a Terraform plan (preferably JSON),
2) Generates a deterministic risk assessment (“risk gate”),
3) Produces a plain-English explanation using Bedrock,
4) Ensures no sensitive data is sent to Bedrock via sanitization/minimization.

---

## 2) Goals / Non-Goals

### Goals
- **Safe-by-design**: raw plan should not be sent to Bedrock.
- **Deterministic risk detection** with explainable evidence.
- **Useful output formats**: on-screen report + “PR comment” text.
- **Fast MVP**: single-page upload + results.

### Non-Goals (MVP)
- Full Terraform state analysis
- Live AWS account connectivity
- Real-time drift detection
- Comprehensive policy evaluation engine equivalent to IAM Access Analyzer

---

## 3) High-Level Approach

**Core principle:** Prefer *feature extraction* over *full text redaction*.

We will:
1) Parse Terraform plan JSON locally on backend (or in browser).
2) Extract a **minimal semantic summary** of changes (“Diff Skeleton”).
3) Run a deterministic **risk rule engine** on the parsed plan.
4) Produce a **sanitized payload** (summary + risk findings + safe metadata) for Bedrock.
5) Use Bedrock to generate a polished plain-English narrative, review questions, and recommended next steps.

---

## 4) Inputs & Supported Formats

### Supported (MVP)
- `terraform show -json tfplan` output (Plan JSON)

### Optional (later)
- Raw `terraform plan` text (convert to JSON server-side by calling `terraform show -json` if terraform binary is available)
- OPA/Rego integration for policy-as-code

---

## 5) Architecture

### Components
- **Frontend (Next.js)**
  - Upload/paste plan JSON
  - Display summary, risks, explanation, PR comment
  - Optional: client-side sanitization mode (raw plan never leaves browser)

- **API Backend (FastAPI or Next.js API routes)**
  - `POST /analyze` accepts plan JSON (or already-extracted features)
  - Parses plan JSON
  - Runs risk rules
  - Builds sanitized payload for Bedrock
  - Calls Bedrock, returns explanation

- **Storage (optional for MVP)**
  - DynamoDB for saved analyses (sanitized only)
  - S3 for uploads (only if allowed; prefer not storing raw plan)

### Data Flow (recommended)
1) Browser uploads plan JSON to backend over TLS
2) Backend:
   - Parses
   - Extracts features
   - Runs rule engine
   - Discards raw plan (or holds only in-memory)
   - Calls Bedrock with sanitized payload
3) Backend returns:
   - Summary
   - Risks
   - LLM explanation + PR comment

### "Strict Mode" (best story)
- Browser performs initial sanitization + extraction
- Backend receives **only extracted features** (no raw plan)
- Backend runs LLM and returns narrative

### Deployment & Local Development
- **Containerization**: All components (frontend, backend/API) will be dockerized
- **Local development**: Docker Compose for running full stack on macOS (Apple Silicon + Intel compatible)
- **Build & test workflow**: Docker-based build ensures consistency across environments
- **Container structure**:
  - Frontend container: Next.js app with production build
  - Backend/API container (if separate): Python FastAPI or Next.js API routes
  - Local AWS credential mounting for Bedrock access during development
- **Benefits**: Reproducible builds, easy CI/CD integration, simplified deployment to ECS/EKS/App Runner

---

## 6) Security & Data Handling Requirements

### Must
- Never send raw plan JSON to Bedrock.
- Denylist sensitive keys and redact likely secrets.
- Avoid storing raw plans at rest (MVP).
- Log only non-sensitive metadata (request id, counts, timings).

### Nice-to-have
- Client-side extraction/sanitization option toggle
- Configurable org policy: “no persistence” vs “store sanitized report”

---

## 7) Plan Parsing and “Diff Skeleton” Feature Extraction

### Terraform Plan JSON fields of interest (typical)
- `resource_changes[]`
  - `address`, `mode`, `type`, `name`
  - `change.actions` (create/update/delete/replace/no-op)
  - `change.before` / `change.after` / `change.after_unknown`
  - `change.before_sensitive` / `change.after_sensitive` (if present)
- `configuration` (optional; may include values and references)
- `planned_values` (optional)

### Diff Skeleton: Minimal representation
For each resource change:
- `resource_type`: e.g., `aws_security_group`
- `action`: create/update/delete/replace
- `changed_paths`: list of attribute paths that changed (names only)
- `safety_tags`: derived classifications (e.g., public exposure, encryption off)
- `resource_id_hash`: stable hash of `address` for correlation without disclosure

#### Changed-path extraction
Compute changed paths by recursively comparing `before` and `after` objects:
- Record only keys/paths, not values.
- For arrays of objects (e.g., SG rules), record the container key (e.g., `ingress`) and optionally normalized sub-keys (e.g., `ingress[].cidr_blocks`).

---

## 8) Sanitization Spec

We use two layers:

### Layer A: Minimization (preferred)
Send only:
- Plan summary counts
- Diff skeleton (types, actions, changed_paths, hashes)
- Deterministic risk findings with non-sensitive evidence tokens
- Optional: “safe” resource metadata (region classification, public/private booleans)

### Layer B: Redaction (for any residual strings included)
If any string fields must be sent, apply:
- **Denylist key removal**
- **Regex redaction** of identifiers
- **Value hashing** for names/addresses if needed

#### 8.1 Denylist Keys (drop entirely)
Drop any attribute key matching (case-insensitive):
- `password`, `passwd`, `secret`, `token`, `apikey`, `api_key`, `access_key`, `secret_key`
- `private_key`, `client_secret`, `certificate`, `cert`, `key_material`
- `user_data`, `bootstrap`, `connection`, `provisioner`
- `kms_key_id` (keep only classification: custom vs aws-managed if you can infer safely)
- `tags` (keep only tag *keys* if needed; drop values)

#### 8.2 Allowlist Keys (safe to keep if needed)
Prefer keeping only:
- `type`, `actions`, `changed_paths`, `severity`, `risk_id`
- Booleans or enums like `is_public_cidr`, `encryption_removed`
- Counts: `num_changes`, `num_creates`, etc.

#### 8.3 Regex Redaction (strings)
Replace matches with placeholders:

- AWS Account IDs: `\b\d{12}\b` → `<REDACTED:ACCOUNT>`
- ARNs: `\barn:aws[a-z-]*:[^:\s]+:[^:\s]*:\d{12}:[^\s]+\b` → `<REDACTED:ARN>`
- IPv4: `\b(?:\d{1,3}\.){3}\d{1,3}\b` → `<REDACTED:IP>`
- CIDR: `\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b` → `<REDACTED:CIDR>`
- Emails: `\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b` (i) → `<REDACTED:EMAIL>`
- UUID: `\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b` → `<REDACTED:UUID>`
- Hostnames (basic): `\b[a-zA-Z0-9.-]+\.(internal|local|corp|com|net|org)\b` → `<REDACTED:HOST>`

#### 8.4 Stable Hashing
Hash these fields if you need correlation:
- resource `address`
- resource names
- ARNs (after redaction, hash placeholder context if needed)

Example: `sha256(value)[:10]` → `res_9f31a02c1b`

---

## 9) Risk Engine

### Output shape
Each risk finding:
- `risk_id`: stable id
- `title`
- `severity`: info/low/medium/high/critical
- `resource_type` (optional)
- `resource_ref` (hashed)
- `evidence`: safe tokens only (no raw names/ids)
- `recommendation`: deterministic guidance
- `changed_paths` (optional)

### Severity guidelines
- **Critical**: direct public exposure of sensitive services, admin-level IAM, disabling encryption on sensitive data stores
- **High**: broad network access, wildcard permissions, destructive ops on shared infra
- **Medium**: security hardening removed, logging disabled, missing encryption at rest
- **Low/Info**: hygiene warnings, best-practice suggestions

---

## 10) Initial Risk Rules (MVP Set: 20)

> Rules use the parsed plan JSON. Evidence must be *classified* not literal (e.g., `public_cidr=true`, `ports=[22]`).

### Networking / Exposure
1. **SG-OPEN-INGRESS**
   - Trigger: `aws_security_group` / `aws_security_group_rule` ingress includes public cidr (0.0.0.0/0 or ::/0)
   - Severity: High/Critical (Critical if ports include 22, 3389, 5432, 3306)
   - Evidence: `public_cidr=true`, `ports=[...]`
   - Recommendation: restrict CIDRs, use SSM/bastion, tighten ports.

2. **NACL-ALLOW-ALL**
   - Trigger: `aws_network_acl_rule` allows 0.0.0.0/0 with wide ports or protocol -1
   - Severity: High
   - Evidence: `public_cidr=true`, `protocol=all`
   - Recommendation: narrow rules, prefer SG controls.

3. **LB-INTERNET-FACING**
   - Trigger: `aws_lb` with `internal=false` (internet-facing)
   - Severity: Medium/High (High if paired with open SG or sensitive ports)
   - Evidence: `internet_facing=true`
   - Recommendation: confirm intended; restrict SG and listener ports; WAF.

4. **CF-ORIGIN-PUBLIC**
S3/ALB**
   - Trigger: CloudFront origin points to a resource that is also public (detect via other flags)
   - Severity: Medium
   - Evidence: `origin_exposure_risk=true`
   - Recommendation: ensure origin is private behind OAC/OAI or internal ALB.

### IAM / Privilege
5. **IAM-ADMIN-WILDCARD**
   - Trigger: policy statements add `Action: "*"`, or service wildcard like `iam:*`, `kms:*`, `s3:*` without tight conditions/resources
   - Severity: Critical
   - Evidence: `action_wildcard=true`, `service_wildcard=iam`
   - Recommendation: scope actions/resources; add conditions; separate break-glass.

6. **IAM-PASSROLE-BROAD**
   - Trigger: `iam:PassRole` added with wildcard resource or without `iam:PassedToService` constraint
   - Severity: High/Critical
   - Evidence: `passrole=true`, `resource_wildcard=true`, `passed_to_service_constraint=false`
   - Recommendation: restrict role ARNs and use `iam:PassedToService`.

7. **STS-ASSUMEROLE-WILDCARD**
   - Trigger: `sts:AssumeRole` on `Resource: "*"` or broadly across org without conditions
   - Severity: High
   - Evidence: `assumerole=true`, `resource_wildcard=true`
   - Recommendation: scope by role ARN patterns + externalId/session tags.

8. **KMS-DECRYPT-BROAD**
   - Trigger: `kms:Decrypt` added without key scoping or encryption context constraints
   - Severity: High
   - Evidence: `kms_decrypt=true`, `constraints=false`
   - Recommendation: restrict KMS keys; require encryption context / via-service.

### S3 / Storage
9. **S3-PUBLIC-ACL-OR-POLICY**
   - Trigger: S3 bucket policy/ACL becomes public or allows `Principal: "*"` with s3:GetObject
   - Severity: Critical
   - Evidence: `principal_star=true`, `public_read=true`
   - Recommendation: block public access; restrict principals.

10. **S3-PAB-REMOVED**
   - Trigger: `aws_s3_bucket_public_access_block` removed or set to false values
   - Severity: High
   - Evidence: `pab_disabled=true`
   - Recommendation: keep PAB on except explicitly approved.

11. **S3-ENCRYPTION-REMOVED**
   - Trigger: bucket server-side encryption configuration removed/disabled
   - Severity: High
   - Evidence: `sse_removed=true`
   - Recommendation: enable SSE (SSE-KMS where required).

### Datastores / Encryption
12. **RDS-PUBLICLY-ACCESSIBLE**
   - Trigger: `aws_db_instance publicly_accessible=true`
   - Severity: Critical
   - Evidence: `publicly_accessible=true`
   - Recommendation: keep private; use VPC access + SG controls.

13. **RDS-ENCRYPTION-OFF**
   - Trigger: `storage_encrypted` false or encryption removed
   - Severity: High
   - Evidence: `encryption_removed=true`
   - Recommendation: enable encryption; evaluate snapshot/restore path.

14. **EBS-ENCRYPTION-OFF**
   - Trigger: `aws_ebs_volume encrypted=false` or encryption removed
   - Severity: High
   - Evidence: `encrypted=false`
   - Recommendation: enable default EBS encryption or per-volume.

### Logging / Monitoring
15. **CT-LOGGING-DISABLED**
   - Trigger: `aws_cloudtrail` set to not logging / trail removed
   - Severity: Critical
   - Evidence: `cloudtrail_removed_or_disabled=true`
   - Recommendation: maintain org trails; verify logging.

16. **CW-LOG-RETENTION-LOW**
   - Trigger: log group retention reduced below threshold (e.g., < 30/90 days depending standard)
   - Severity: Medium
   - Evidence: `retention_days=<N>`
   - Recommendation: meet retention policy.

### Compute / Containers
17. **LAMBDA-INTERNET-EGRESS-RISK**
   - Trigger: Lambda moves out of VPC or adds open egress; or adds env vars changes flagged as sensitive
   - Severity: Medium/High
   - Evidence: `vpc_removed=true` or `egress_open=true`
   - Recommendation: confirm networking intent; add VPC endpoints.

18. **ECS-TASK-PRIVILEGED**
   - Trigger: ECS task definition sets `privileged=true` or mounts host volumes
   - Severity: High
   - Evidence: `privileged=true` or `host_mount=true`
   - Recommendation: avoid privileged; least privilege; isolate.

### Destructive / Blast Radius
19. **DESTRUCTIVE-REPLACE-SHARED-INFRA**
   - Trigger: replace/delete on known shared types (TGW, VPC, subnets used widely, KMS keys, org policies)
   - Severity: High/Critical
   - Evidence: `action=replace`, `shared_type=tgw`
   - Recommendation: require staged rollout, maintenance window, explicit approval.

20. **ORG-GUARDRAIL-CHANGE**
   - Trigger: changes to SCP/Organizations policies/attachments
   - Severity: High
   - Evidence: `org_policy_change=true`
   - Recommendation: review effective impact; test in sandbox OU first.

> Config: provide rule thresholds (ports list, retention days, sensitive resource types) in a YAML config file.

---

## 11) Bedrock Prompting

### Inputs to Bedrock (sanitized)
- `summary`
- `diff_skeleton` (resource types, actions, changed_paths, hashed refs)
- `risk_findings` (ids, severity, evidence tokens, recommendations)
- `organization_standards` (optional small policy snippet: retention threshold, approved patterns)

### Output from Bedrock
- `executive_summary` (2–5 bullets)
- `plain_english_changes` (grouped by resource type/action)
- `top_risks_explained` (map to deterministic findings, no new sensitive inference)
- `review_questions` (what to double-check)
- `suggested_pr_comment` (copy/paste)

### Prompt template (high level)
System:
- You are an AWS/IaC reviewer assistant.
- Do not invent resource names/ids.
- Use only provided sanitized facts.
- If information is missing, say so and ask a reviewer question.

User:
- Provide JSON payload.
- Ask for structured markdown output.

---

## 12) API Design

### `POST /analyze`
Request (Option A: raw plan JSON to backend):
```json
{
  "plan_json": { ... },
  "mode": "backend_extract",
  "options": {
    "strict_no_store": true,
    "max_findings": 50
  }
}
