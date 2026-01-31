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
  resource_ref: string
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

export interface ResourceCost {
  resource_ref: string
  resource_type: string
  resource_address?: string
  monthly_cost: number
  hourly_cost?: number
  confidence: 'high' | 'medium' | 'low'
  pricing_unit: string
  notes?: string
  action: string
}

export interface CostEstimate {
  total_monthly_cost: number
  previous_monthly_cost?: number
  net_change?: number
  percent_change?: number
  resource_costs: ResourceCost[]
  currency: string
  estimation_method: string
  pricing_region: string
  last_pricing_update: string
  resources_estimated: number
  resources_unknown: number
}

export interface AnalyzeResponse {
  summary: PlanSummary
  diff_skeleton: ResourceChange[]
  risk_findings: RiskFinding[]
  explanation: BedrockExplanation
  pr_comment: string
  cost_estimate?: CostEstimate
  session_id?: string
  cached?: boolean
  analyzer_type?: 'terraform' | 'iam'
  created_at?: string
}

export interface SessionStats {
  total_sessions: number
  max_size: number
  ttl_hours: number
  oldest_age_hours: number
  uptime_seconds: number
}
