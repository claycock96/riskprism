'use client'

import { RiskFinding, ResourceChange } from '@/lib/types'
import { createResourceMapping, extractResourceName, enhanceTextWithResourceNames } from '@/lib/resourceMapping'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

interface RiskFindingsProps {
  findings: RiskFinding[]
  diffSkeleton?: ResourceChange[]
  aiRisksNarrative?: string
  isIAM?: boolean
}

function getSeverityBadge(severity: string) {
  const badges = {
    critical: 'badge badge-critical',
    high: 'badge badge-high',
    medium: 'badge badge-medium',
    low: 'badge badge-low',
    info: 'badge badge-info',
  }
  return badges[severity as keyof typeof badges] || badges.info
}

function getSeverityGlow(severity: string) {
  const glows = {
    critical: 'border-red-500/30 shadow-glow-critical',
    high: 'border-orange-500/30 shadow-glow-high',
    medium: 'border-yellow-500/20',
    low: 'border-blue-500/20',
    info: 'border-slate-500/20',
  }
  return glows[severity as keyof typeof glows] || glows.info
}

export default function RiskFindings({ findings, diffSkeleton = [], aiRisksNarrative, isIAM = false }: RiskFindingsProps) {
  if (findings.length === 0) {
    return null
  }

  // Create resource mapping
  const resourceMapping = createResourceMapping(diffSkeleton, findings)

  // Get readable resource name from hash
  const getResourceName = (hash: string, type: string) => {
    const resource = resourceMapping[hash]
    if (resource && resource.address) {
      return extractResourceName(resource.address)
    }
    return hash
  }

  // Enhance text with resource names
  const enhancedRisks = aiRisksNarrative ? enhanceTextWithResourceNames(aiRisksNarrative, resourceMapping) : null

  // Group findings by severity
  const groupedFindings = findings.reduce((acc, finding) => {
    if (!acc[finding.severity]) {
      acc[finding.severity] = []
    }
    acc[finding.severity].push(finding)
    return acc
  }, {} as Record<string, RiskFinding[]>)

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info']
  const sortedSeverities = severityOrder.filter(s => groupedFindings[s])

  return (
    <div className="glass-panel p-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-red-500 to-orange-500 flex items-center justify-center">
            <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
          </div>
          <h3 className="text-lg font-bold text-white">Security Findings</h3>
        </div>
        <span className="text-xs font-medium text-slate-400 bg-slate-800 px-3 py-1.5 rounded-lg">
          Deterministic Rule Engine
        </span>
      </div>

      {/* AI Risk Reasoning Section */}
      {enhancedRisks && (
        <div className="mb-8 pb-6 border-b border-white/10">
          <div className="flex items-center gap-2 mb-4 p-3 rounded-xl bg-gradient-to-r from-violet-500/10 to-fuchsia-500/10 border border-violet-500/20">
            <svg className="w-5 h-5 text-violet-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            </svg>
            <span className="font-bold text-violet-300 text-sm">AI RISK REASONING & ATTACK SCENARIOS</span>
          </div>
          <div className="prose prose-sm prose-invert max-w-none prose-headings:text-white prose-p:text-slate-300 prose-strong:text-white prose-code:text-violet-300 prose-code:bg-slate-800 prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded">
            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              components={{
                h3: ({ node, ...props }) => (
                  <div className="mt-6 mb-3 first:mt-0 pt-4 first:pt-0 border-t first:border-t-0 border-white/10">
                    <h3 className="text-sm font-bold text-white flex items-center" {...props} />
                  </div>
                ),
                p: ({ node, ...props }) => (
                  <p className="text-sm text-slate-300 leading-relaxed mb-3" {...props} />
                ),
                strong: ({ node, ...props }) => {
                  const text = props.children?.toString() || ''
                  const isLabel = ['Risk:', 'Why This Matters:', 'Attack Scenario:', 'Impact:'].includes(text)
                  return (
                    <strong
                      className={isLabel ? "text-violet-400 font-bold block mb-1 text-xs uppercase tracking-tight" : "text-white font-semibold"}
                      {...props}
                    />
                  )
                }
              }}
            >
              {enhancedRisks}
            </ReactMarkdown>
          </div>
        </div>
      )}

      {/* Detailed Findings Header */}
      <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-6">Detailed Findings</h4>

      {/* Findings by Severity */}
      <div className="space-y-6">
        {sortedSeverities.map((severity) => (
          <div key={severity}>
            <h4 className="text-sm font-semibold text-slate-300 mb-4 flex items-center">
              <span className={`w-2 h-2 rounded-full mr-2 ${severity === 'critical' ? 'bg-red-500' :
                  severity === 'high' ? 'bg-orange-500' :
                    severity === 'medium' ? 'bg-yellow-500' :
                      severity === 'low' ? 'bg-blue-500' : 'bg-slate-500'
                }`} />
              {severity.charAt(0).toUpperCase() + severity.slice(1)}
              <span className="ml-2 text-slate-500">({groupedFindings[severity].length})</span>
            </h4>

            <div className="space-y-4">
              {groupedFindings[severity].map((finding, idx) => (
                <div
                  key={idx}
                  className={`rounded-xl p-5 bg-slate-900/50 border-l-4 border ${getSeverityGlow(finding.severity)} transition-all duration-300 hover:bg-slate-800/50`}
                >
                  {/* Finding Header */}
                  <div className="flex items-start justify-between mb-3">
                    <h5 className="text-base font-semibold text-white">{finding.title}</h5>
                    <span className={getSeverityBadge(finding.severity)}>
                      {finding.severity.toUpperCase()}
                    </span>
                  </div>

                  {/* Resource Info */}
                  <div className="flex flex-wrap items-center gap-2 text-sm text-slate-400 mb-4">
                    <span className="font-medium text-slate-300">Resource:</span>
                    <code className="px-2 py-0.5 rounded bg-slate-800 text-xs text-slate-300 font-mono">
                      {finding.resource_type}
                    </code>
                    <span className="text-slate-600">/</span>
                    <a
                      href={`#resource-${finding.resource_ref}`}
                      className="px-2 py-0.5 rounded bg-violet-500/10 text-xs text-violet-300 font-medium hover:bg-violet-500/20 transition-colors border border-violet-500/20"
                      onClick={(e) => {
                        e.preventDefault();
                        const el = document.getElementById(`resource-${finding.resource_ref}`);
                        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
                      }}
                    >
                      {getResourceName(finding.resource_ref, finding.resource_type)}
                      <span className="ml-1 opacity-50">#</span>
                    </a>
                  </div>

                  {/* Evidence */}
                  {finding.evidence && Object.keys(finding.evidence).length > 0 && (
                    <div className="mb-4">
                      <details className="group">
                        <summary className="cursor-pointer text-sm text-violet-400 hover:text-violet-300 font-medium flex items-center gap-1">
                          <svg className="w-4 h-4 transition-transform group-open:rotate-90" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                          </svg>
                          View Evidence
                        </summary>
                        <div className="mt-3 p-3 rounded-lg bg-slate-800/50 border border-white/5">
                          <pre className="text-xs text-slate-300 font-mono overflow-x-auto">
                            {JSON.stringify(finding.evidence, null, 2)}
                          </pre>
                        </div>
                      </details>
                    </div>
                  )}

                  {/* Recommendation */}
                  {finding.recommendation && (
                    <div className="p-4 rounded-lg bg-blue-500/10 border-l-2 border-blue-500">
                      <p className="text-sm text-blue-200">
                        <span className="font-semibold text-blue-300">Recommendation:</span> {finding.recommendation}
                      </p>
                    </div>
                  )}

                  {/* Suggested Fix */}
                  {finding.suggested_fix && (
                    <div className="mt-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Suggested Fix (HCL)</span>
                        <button
                          onClick={() => navigator.clipboard.writeText(finding.suggested_fix || '')}
                          className="text-xs text-violet-400 hover:text-violet-300 font-medium flex items-center gap-1 transition-colors"
                        >
                          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                          </svg>
                          Copy
                        </button>
                      </div>
                      <div className="p-4 rounded-lg bg-slate-950 border border-white/5 overflow-x-auto">
                        <pre className="text-xs text-emerald-400 font-mono">
                          {finding.suggested_fix}
                        </pre>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
