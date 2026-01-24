export interface PlanSummary {
  total_changes: number
  creates: number
  updates: number
  deletes: number
  replaces: number
  no_ops?: number
  terraform_version?: string
}

export interface AttributeDiff {
  path: string
  before: any
  after: any
}

export interface ResourceChange {
  action: string
  resource_type: string
  resource_id_hash: string
  changed_paths: string[]
  attribute_diffs: AttributeDiff[]
  resource_address?: string
}

export interface RiskFinding {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  title: string
  resource_type: string
  resource_ref: string
  evidence: Record<string, any>
  recommendation: string
  suggested_fix?: string
}

export interface BedrockExplanation {
  executive_summary: string[]
  plain_english_changes: string
  top_risks_explained: string
  review_questions: string[]
}

export interface AnalyzeResponse {
  summary: PlanSummary
  diff_skeleton: ResourceChange[]
  risk_findings: RiskFinding[]
  explanation: BedrockExplanation
  pr_comment: string
  session_id?: string
  cached?: boolean
  analyzer_type?: 'terraform' | 'iam'
}

export interface SessionStats {
  total_sessions: number
  max_size: number
  ttl_hours: number
  oldest_age_hours: number
  uptime_seconds: number
}
