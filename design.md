# Terraform Plan Explainer + Risk Gate — Design Doc (design.md)

Owner: Chris
Audience: DevOps / Cloud Engineering team
Status: MVP Implemented (v1.0)
Last Updated: 2026-01-24 (Multi-Analyzer Update)

---

## 1) Problem Statement

Terraform plans are hard to review quickly and consistently across a multi-account AWS environment. Reviewers must:
- Understand *what* is changing (creates/updates/deletes/replacements)
- Assess *risk* (public exposure, IAM privilege expansion, encryption removal, destructive ops)
- Produce consistent review notes for PRs / change boards

We want a web app that:
1) Ingests a Terraform plan or IAM Policy JSON,
2) Generates a deterministic risk assessment using pluggable analyzer engines,
3) Produces a context-aware plain-English explanation using AI (Bedrock/Anthropic),
4) Ensures no sensitive data (ARNs, Account IDs, secrets) is sent to AI via hashing and minimization.

---

## 2) Implementation Status (v1.0)

### ✅ Completed

**Backend (Python FastAPI)**
- **Multi-Analyzer Architecture**: Modular `BaseAnalyzer` framework supporting pluggable engines.
- **Terraform Analyzer**: Plan JSON parser with recursive attribute extraction and hashing.
- **IAM Policy Analyzer**: Normalizes policy statements and hashes ARNs/Account IDs for privacy.
- **24+ security rules** (14 Terraform, 10+ IAM) in high-concurrency risk engine.
- **SQLAlchemy + SQLite persistence layer** for session storage and SHA-256 fingerprinting.
- **Audit Logging (Paper Trail)**: Tracks IP and User-Agent per analysis.
- **Shared Access Code Authentication** via secure headers.
- AWS Bedrock (Claude 3.5 Sonnet) & Anthropic API integrations with context-aware prompts.

**Frontend (Next.js 14 + TypeScript)**
- **Analyzer Switcher**: Tabbed interface to toggle between Terraform and IAM modes.
- **Full Dark Mode Support**: Modern dark/light theme integration across all components.
- **Revamped Resource Diff**: Table-based visualization of attribute changes with old/new values.
- **Visual Risk Dashboard**: Context-aware summary stats (e.g., Allow/Deny for IAM).
- Frontend-only resource mapping (hash → readable names) preserved across analyzers.

**Infrastructure & Deployment**
- Docker Compose with **persistent volume bind-mounts**
- Terraform IaC for AWS EC2 (t4g.small/ARM) deployment
- Private subnet deployment with VPC-only access
- Automated SSH key management in Secrets Manager

### 🚧 In Progress / Planned
- CI/CD Integration (GitHub Action & GitLab CI)
- Multi-cloud risk rule expansion (Azure/GCP)
- Team-based SSO integration (Okta/Google)

---

## 3) Goals / Non-Goals

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

## 4) High-Level Approach

**Core principle:** Prefer *feature extraction* over *full text redaction*.

Implementation:
1) Parse Terraform plan JSON on backend (FastAPI)
2) Extract a **minimal semantic summary** of changes ("Diff Skeleton")
3) Run a deterministic **risk rule engine** on the parsed plan
4) Produce a **sanitized payload** (summary + risk findings + safe metadata) for LLM
5) Use AWS Bedrock or Anthropic API to generate polished plain-English narrative
6) Frontend maps hashed resource IDs back to readable names for display

---

## 5) Inputs & Supported Formats

### Supported (Implemented)
- `terraform show -json tfplan` output (Plan JSON)
- File upload via web interface
- Drag-and-drop support

### Future Enhancements
- Raw `terraform plan` text (convert to JSON server-side by calling `terraform show -json` if terraform binary is available)
- OPA/Rego integration for policy-as-code
- Multi-file analysis

---

## 6) Architecture

### Components (Implemented)

**Frontend (Next.js 14 + TypeScript)**
- File upload interface with drag-and-drop
- Real-time progress indication
- Summary dashboard with hover tooltips
- Interactive risk findings with expandable evidence
- AI explanation display with resource name mapping
- Copy-to-clipboard PR comment
- Inline security documentation
- **Key Feature**: Frontend-only hash-to-name mapping (privacy + readability)

**API Backend (Python FastAPI)**
- `POST /analyze/terraform`: Dedicated endpoint for plan analysis (with `/analyze` alias).
- `POST /analyze/iam`: New dedicated endpoint for IAM Policy analysis.
- Shared logic via `BaseAnalyzer` abstraction:
  - `parse()`: Validation and normalization.
  - `analyze()`: Deterministic rule execution.
  - `sanitize_for_llm()`: Privacy extraction.
  - `generate_summary()`: Context-aware statistics.
- Returns structured analysis response with hashed identifying information.

**Persistent Storage Layer**
- SQLite database (`sessions.db`) stores sanitized analysis results
- Managed via SQLAlchemy with asynchronous operations
- Survives container restarts and backend redeployments
- Automatically rotates oldest reports after 1,000 sessions or 30 days

### Data Flow (Implemented)

1) User uploads plan JSON via browser (HTTPS)
2) Frontend sends to backend API
3) Backend:
   - Parses and extracts features
   - Hashes resource addresses (SHA-256, 10-char prefix)
   - Filters sensitive attributes
   - Runs risk detection rules
   - Discards raw plan from memory
   - Calls LLM with sanitized payload only
   - Returns analysis with hashed resource IDs
4) Frontend:
   - Receives analysis from backend
   - Creates hash→address mapping from diff_skeleton
   - Displays readable resource names in UI
   - **User sees**: `aws_security_group (web_server)`
   - **AI saw**: `res_abc123def4`

### Deployment Options (Implemented)

**Local Development**
- Docker Compose orchestration
- Frontend container (Next.js) on port 3000
- Backend container (FastAPI) on port 8000
- Hot reload support
- AWS credential mounting via `~/.aws` volume

**AWS Deployment**
- Terraform IaC for EC2 deployment
- t4g.small instance (ARM Graviton)
- Amazon Linux 2023
- Docker + Docker Compose
- IAM role with Bedrock permissions
- SSH key auto-generated and stored in Secrets Manager
- Private subnet deployment (VPC-only access)
- Security group: inbound from VPC CIDR only

---

## 7) Security & Data Handling (Implemented)

### Requirements Met ✅
- ✅ Never send raw plan JSON to LLM
- ✅ Denylist sensitive keys and filter secrets
- ✅ No raw plan storage (stateless processing)
- ✅ Log only non-sensitive metadata

### Implementation Details

**Resource Hashing** (Backend)
```python
# SHA-256 hash of resource address, 10-char prefix
resource_id_hash = hashlib.sha256(address.encode()).hexdigest()[:10]
# Example: aws_security_group.web_server → res_abc123def4
```

**Sensitive Key Filtering** (Backend)
Attributes matching these patterns are completely excluded:
- `password`, `passwd`, `secret`, `token`, `apikey`, `api_key`
- `access_key`, `secret_key`, `private_key`, `client_secret`
- `certificate`, `cert`, `key_material`, `user_data`

**Frontend-Only Name Mapping** (New Feature)
```typescript
// Backend includes resource_address in diff_skeleton
// Frontend creates mapping: hash → original address
const resourceMapping = createResourceMapping(diffSkeleton, riskFindings)

// Text enhancement replaces hashes with readable names
enhanceTextWithResourceNames(aiText, resourceMapping)
// "res_abc123def4" → "aws_security_group (web_server)"
```

**What AI Sees vs. User Sees**
- AI input: `res_abc123def4`, type=`aws_security_group`, action=`update`, paths=`[ingress]`
- User output: `aws_security_group (web_server)` with full context

### Future Enhancements
- Configurable org policy: "no persistence" vs "store sanitized report"
- Optional client-side extraction mode

---

## 8) Plan Parsing and "Diff Skeleton" Feature Extraction

### Terraform Plan JSON fields of interest (implemented)
- `resource_changes[]`
  - `address`, `mode`, `type`, `name`
  - `change.actions` (create/update/delete/replace/no-op)
  - `change.before` / `change.after` / `change.after_unknown`
  - `change.before_sensitive` / `change.after_sensitive` (if present)

### Diff Skeleton: Minimal representation (implemented)
For each resource change:
- `resource_type`: e.g., `aws_security_group`
- `action`: create/update/delete/replace
- `changed_paths`: list of attribute paths that changed (names only)
- `resource_id_hash`: stable hash of `address` for correlation
- `resource_address`: original address (sent to frontend, NOT to LLM)

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

## 10) Risk Rules (9 Implemented, 11 Planned)

> Rules use the parsed plan JSON. Evidence must be *classified* not literal (e.g., `public_cidr=true`, `ports=[22]`).

### ✅ Implemented Rules (v1.0)

**Networking / Exposure**
1. **SG-OPEN-INGRESS** ✅
   - Trigger: `aws_security_group` / `aws_security_group_rule` ingress includes public cidr (0.0.0.0/0 or ::/0)
   - Severity: High/Critical (Critical if ports include 22, 3389, 5432, 3306)
   - Evidence: `public_cidr=true`, `ports=[...]`
   - Recommendation: restrict CIDRs, use SSM/bastion, tighten ports.

**IAM / Privilege**
2. **IAM-ADMIN-WILDCARD** ✅
   - Trigger: IAM inline policy statements add `Action: "*"`, or service wildcard like `iam:*` without tight conditions/resources
   - Severity: Critical
   - Evidence: `action_wildcard=true`, `admin_risk=true`
   - Recommendation: scope actions/resources; add conditions; separate break-glass.
   - Resources: `aws_iam_policy`, `aws_iam_role_policy`, `aws_iam_user_policy`

3. **IAM-MANAGED-POLICY** ✅ **(New in v1.0)**
   - Trigger: Attachment of dangerous AWS managed policies
   - Severity: Critical/High/Medium (depends on policy)
   - Evidence: `policy_arn`, `policy_name`, `description`
   - Flags:
     - AdministratorAccess (Critical)
     - IAMFullAccess (Critical)
     - PowerUserAccess (High)
     - SystemAdministrator (Medium)
     - SecurityAudit (Medium)
   - Recommendation: Use custom policies with least-privilege permissions. For break-glass admin access, use separate role with MFA.
   - Resources: `aws_iam_role_policy_attachment`, `aws_iam_user_policy_attachment`, `aws_iam_group_policy_attachment`

**S3 / Storage**
4. **S3-PUBLIC-ACL-OR-POLICY** ✅
   - Trigger: S3 bucket policy/ACL becomes public or allows `Principal: "*"` with s3:GetObject
   - Severity: Critical
   - Evidence: `principal_star=true`, `public_read=true`
   - Recommendation: block public access; restrict principals.

5. **S3-PAB-REMOVED** ✅
   - Trigger: `aws_s3_bucket_public_access_block` removed or set to false values
   - Severity: High
   - Evidence: `pab_disabled=true`
   - Recommendation: keep PAB on except explicitly approved.

6. **S3-ENCRYPTION-REMOVED** ✅
   - Trigger: bucket server-side encryption configuration removed/disabled
   - Severity: High
   - Evidence: `sse_removed=true`
   - Recommendation: enable SSE (SSE-KMS where required).

**Datastores / Encryption**
7. **RDS-PUBLICLY-ACCESSIBLE** ✅
   - Trigger: `aws_db_instance publicly_accessible=true`
   - Severity: Critical
   - Evidence: `publicly_accessible=true`
   - Recommendation: keep private; use VPC access + SG controls.

8. **RDS-ENCRYPTION-OFF** ✅
   - Trigger: `storage_encrypted` false or encryption removed
   - Severity: High
   - Evidence: `encryption_removed=true`
   - Recommendation: enable encryption; evaluate snapshot/restore path.

**Logging / Monitoring**
9. **CT-LOGGING-DISABLED** ✅
   - Trigger: `aws_cloudtrail` set to not logging / trail removed
   - Severity: Critical
   - Evidence: `cloudtrail_removed_or_disabled=true`
   - Recommendation: maintain org trails; verify logging.

### 🚧 Planned Rules

**Networking / Exposure**
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

4. **CF-ORIGIN-PUBLIC-S3/ALB**
   - Trigger: CloudFront origin points to a resource that is also public (detect via other flags)
   - Severity: Medium
   - Evidence: `origin_exposure_risk=true`
   - Recommendation: ensure origin is private behind OAC/OAI or internal ALB.

**IAM / Privilege**
5. **IAM-PASSROLE-BROAD**
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


---

## Changelog

### v1.0 (2026-01-24) - MVP Release

**Frontend Implementation**
- ✅ Next.js 14 web application with TypeScript
- ✅ File upload interface with drag-and-drop
- ✅ Interactive UI with hover tooltips on resource statistics
- ✅ Frontend-only resource name mapping (privacy + readability)
- ✅ Expandable evidence sections in risk findings
- ✅ Inline security documentation ("How is data sanitized?")
- ✅ Copy-to-clipboard PR comment output
- ✅ Responsive design with Tailwind CSS

**Backend Enhancements**
- ✅ Resource address hashing (SHA-256, 10-char prefix)
- ✅ New security rule: IAM-MANAGED-POLICY (detects dangerous AWS managed policy attachments)
- ✅ Enhanced diff_skeleton to include resource_address (for frontend mapping only)
- ✅ Dual LLM provider support (AWS Bedrock + Anthropic API)

**Infrastructure**
- ✅ Docker Compose multi-container orchestration
- ✅ Terraform IaC for AWS EC2 deployment
- ✅ Auto-generated SSH keys with Secrets Manager storage
- ✅ IAM role with Bedrock permissions
- ✅ Interactive deployment script with plan review

**Security Features**
- ✅ Resource names hashed before LLM submission
- ✅ Metadata-only extraction (no values sent to AI)
- ✅ Sensitive attribute filtering
- ✅ Frontend hash-to-name translation
- ✅ AI sees: `res_abc123def4` → User sees: `aws_security_group (web_server)`

**Risk Rules**: 9 production-ready, 11 planned

---

*End of Design Document*
