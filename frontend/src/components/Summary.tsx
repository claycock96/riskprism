'use client'

import { useState } from 'react'
import { PlanSummary, RiskFinding, ResourceChange } from '@/lib/types'

interface SummaryProps {
  summary: PlanSummary
  riskFindings: RiskFinding[]
  diffSkeleton?: ResourceChange[]
  cached?: boolean
  isIAM?: boolean
}

export default function Summary({ summary, riskFindings, diffSkeleton = [], cached = false, isIAM = false }: SummaryProps) {
  const [hoveredStat, setHoveredStat] = useState<string | null>(null)

  // Count findings by severity
  const severityCounts = riskFindings.reduce((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] || 0) + 1
    return acc
  }, {} as Record<string, number>)

  // Group resources by action type (Terraform only)
  const getResourcesByAction = (action: string) => {
    if (!diffSkeleton || diffSkeleton.length === 0) return []

    const actionMap: Record<string, string[]> = {
      'Creates': ['create'],
      'Updates': ['update'],
      'Deletes': ['delete'],
      'Replaces': ['replace'],
    }

    const actions = actionMap[action] || []
    return diffSkeleton.filter(resource =>
      actions.some(a => resource.action.includes(a))
    )
  }

  // Terraform-specific stats
  const terraformStats = [
    {
      label: 'Total',
      value: summary.total_changes,
      gradient: 'from-slate-500 to-slate-600',
      glowColor: 'rgba(100, 116, 139, 0.3)',
      resources: diffSkeleton,
    },
    {
      label: 'Creates',
      value: summary.creates,
      gradient: 'from-emerald-500 to-green-500',
      glowColor: 'rgba(16, 185, 129, 0.3)',
      resources: getResourcesByAction('Creates'),
    },
    {
      label: 'Updates',
      value: summary.updates,
      gradient: 'from-blue-500 to-cyan-500',
      glowColor: 'rgba(59, 130, 246, 0.3)',
      resources: getResourcesByAction('Updates'),
    },
    {
      label: 'Deletes',
      value: summary.deletes,
      gradient: 'from-red-500 to-rose-500',
      glowColor: 'rgba(239, 68, 68, 0.3)',
      resources: getResourcesByAction('Deletes'),
    },
    {
      label: 'Replaces',
      value: summary.replaces,
      gradient: 'from-orange-500 to-amber-500',
      glowColor: 'rgba(249, 115, 22, 0.3)',
      resources: getResourcesByAction('Replaces'),
    },
  ]

  // IAM-specific stats
  const iamStats = [
    {
      label: 'Statements',
      value: summary.total_changes,
      gradient: 'from-slate-500 to-slate-600',
      icon: (
        <svg className="w-6 h-6 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
      ),
    },
    {
      label: 'Allow',
      value: summary.creates,
      gradient: 'from-emerald-500 to-green-500',
      icon: (
        <svg className="w-6 h-6 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
      ),
    },
    {
      label: 'Deny',
      value: summary.deletes,
      gradient: 'from-red-500 to-rose-500',
      icon: (
        <svg className="w-6 h-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
        </svg>
      ),
    },
  ]

  const riskStats = [
    {
      label: 'Critical',
      value: severityCounts.critical || 0,
      gradient: 'from-red-500 to-rose-600',
      glowColor: 'rgba(239, 68, 68, 0.4)',
      pulse: true,
      findings: riskFindings.filter(f => f.severity === 'critical'),
    },
    {
      label: 'High',
      value: severityCounts.high || 0,
      gradient: 'from-orange-500 to-amber-500',
      glowColor: 'rgba(249, 115, 22, 0.3)',
      pulse: false,
      findings: riskFindings.filter(f => f.severity === 'high'),
    },
    {
      label: 'Medium',
      value: severityCounts.medium || 0,
      gradient: 'from-yellow-500 to-amber-400',
      glowColor: 'rgba(234, 179, 8, 0.3)',
      pulse: false,
      findings: riskFindings.filter(f => f.severity === 'medium'),
    },
    {
      label: 'Low',
      value: severityCounts.low || 0,
      gradient: 'from-blue-500 to-cyan-500',
      glowColor: 'rgba(59, 130, 246, 0.3)',
      pulse: false,
      findings: riskFindings.filter(f => f.severity === 'low'),
    },
  ]

  const criticalCount = severityCounts.critical || 0
  const highCount = severityCounts.high || 0
  const hasHighRisks = criticalCount > 0 || highCount > 0

  return (
    <div className="glass-panel p-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500 to-fuchsia-500 flex items-center justify-center">
            <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
            </svg>
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">{isIAM ? 'Policy Summary' : 'Plan Summary'}</h3>
            {cached && (
              <span className="inline-flex items-center text-xs text-yellow-400">
                <svg className="w-3 h-3 mr-1" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M11.3 1.046A1 1 0 0112 2v5h4a1 1 0 01.82 1.573l-7 10A1 1 0 018 18v-5H4a1 1 0 01-.82-1.573l7-10a1 1 0 011.12-.38z" clipRule="evenodd" />
                </svg>
                Cached
              </span>
            )}
          </div>
        </div>

        {hasHighRisks && (
          <div className="flex items-center gap-2 px-4 py-2 rounded-xl bg-red-500/10 border border-red-500/30 animate-pulse">
            <svg className="w-5 h-5 text-red-400" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
            </svg>
            <span className="text-sm font-semibold text-red-300">Requires Review</span>
          </div>
        )}
      </div>

      {/* IAM Policy Stats */}
      {isIAM && (
        <div className="mb-6">
          <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-4">Policy Structure</h4>
          <div className="grid grid-cols-3 gap-4">
            {iamStats.map((stat) => (
              <div
                key={stat.label}
                className="stat-card group"
              >
                <div className="flex items-center gap-3">
                  <span className="text-2xl">{stat.icon}</span>
                  <div>
                    <div className={`text-3xl font-bold bg-gradient-to-r ${stat.gradient} bg-clip-text text-transparent`}>
                      {stat.value}
                    </div>
                    <div className="text-sm text-slate-400">{stat.label}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Terraform Resource Changes */}
      {!isIAM && (
        <div className="mb-6">
          <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-4">Resource Changes</h4>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {terraformStats.map((stat) => (
              <div
                key={stat.label}
                className="stat-card group cursor-help relative"
                style={{ boxShadow: stat.value > 0 ? `0 0 20px -5px ${stat.glowColor}` : undefined }}
                onMouseEnter={() => stat.value > 0 && setHoveredStat(stat.label)}
                onMouseLeave={() => setHoveredStat(null)}
              >
                <div className={`text-3xl font-bold bg-gradient-to-r ${stat.gradient} bg-clip-text text-transparent`}>
                  {stat.value}
                </div>
                <div className="text-sm text-slate-400 mt-1">{stat.label}</div>

                {/* Tooltip */}
                {hoveredStat === stat.label && stat.resources.length > 0 && (
                  <div className="tooltip-glass absolute z-50 bottom-full left-1/2 transform -translate-x-1/2 mb-3 w-80 animate-fade-in">
                    <div className="font-semibold text-white text-sm mb-2">{stat.label}:</div>
                    <div className="max-h-48 overflow-y-auto space-y-1">
                      {stat.resources.slice(0, 15).map((resource, idx) => (
                        <div key={idx} className="text-xs font-mono text-slate-300">
                          {resource.resource_address ? (
                            <span>
                              <span className="text-slate-500">{resource.resource_type}.</span>
                              <span className="text-white">{resource.resource_address.split('.').slice(1).join('.')}</span>
                            </span>
                          ) : (
                            <span>{resource.resource_type}</span>
                          )}
                        </div>
                      ))}
                      {stat.resources.length > 15 && (
                        <div className="text-xs text-slate-500 italic mt-2">
                          +{stat.resources.length - 15} more
                        </div>
                      )}
                    </div>
                    {/* Arrow */}
                    <div className="absolute top-full left-1/2 transform -translate-x-1/2 -mt-1">
                      <div className="border-8 border-transparent border-t-slate-900/95" />
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Security Findings */}
      <div>
        <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-4">Security Findings</h4>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {riskStats.map((stat) => (
            <div
              key={stat.label}
              className={`stat-card ${stat.pulse && stat.value > 0 ? 'animate-pulse' : ''} cursor-help relative`}
              style={{ boxShadow: stat.value > 0 ? `0 0 20px -5px ${stat.glowColor}` : undefined }}
              onMouseEnter={() => stat.value > 0 && setHoveredStat(`risk-${stat.label}`)}
              onMouseLeave={() => setHoveredStat(null)}
            >
              <div className={`text-3xl font-bold bg-gradient-to-r ${stat.gradient} bg-clip-text text-transparent`}>
                {stat.value}
              </div>
              <div className="text-sm text-slate-400 mt-1">{stat.label}</div>

              {/* Tooltip */}
              {hoveredStat === `risk-${stat.label}` && stat.findings.length > 0 && (
                <div className="tooltip-glass absolute z-50 bottom-full left-1/2 transform -translate-x-1/2 mb-3 w-80 animate-fade-in">
                  <div className="font-semibold text-white text-sm mb-2">{stat.label} Severity Findings:</div>
                  <div className="max-h-48 overflow-y-auto space-y-2">
                    {stat.findings.slice(0, 10).map((finding, idx) => (
                      <div key={idx} className="text-xs">
                        <div className="font-medium text-slate-200">{finding.title}</div>
                        {finding.resource_type && (
                          <div className="text-slate-400 font-mono">{finding.resource_type}</div>
                        )}
                      </div>
                    ))}
                    {stat.findings.length > 10 && (
                      <div className="text-xs text-slate-500 italic mt-2">
                        +{stat.findings.length - 10} more
                      </div>
                    )}
                  </div>
                  {/* Arrow */}
                  <div className="absolute top-full left-1/2 transform -translate-x-1/2 -mt-1">
                    <div className="border-8 border-transparent border-t-slate-900/95" />
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {riskFindings.length === 0 && (
        <div className="mt-6 p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/20 flex items-center justify-center">
              <svg className="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
            </div>
            <p className="text-sm font-medium text-emerald-300">No security issues detected</p>
          </div>
        </div>
      )}
    </div>
  )
}
