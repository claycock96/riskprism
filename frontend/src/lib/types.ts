export interface PlanSummary {
  total_changes: number
  creates: number
  updates: number
  deletes: number
  replaces: number
  no_ops: number
}

export interface ResourceChange {
  action: string
  resource_type: string
  resource_id_hash: string
  changed_paths: string[]
  resource_address?: string
}

export interface RiskFinding {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  title: string
  resource_type: string
  resource_ref: string
  evidence: Record<string, any>
  recommendation: string
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
}
