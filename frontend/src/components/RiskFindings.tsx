'use client'

import { RiskFinding, ResourceChange } from '@/lib/types'
import { createResourceMapping, extractResourceName } from '@/lib/resourceMapping'

interface RiskFindingsProps {
  findings: RiskFinding[]
  diffSkeleton?: ResourceChange[]
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

function getSeverityIcon(severity: string) {
  const icons = {
    critical: '🔴',
    high: '🟠',
    medium: '🟡',
    low: '🔵',
    info: 'ℹ️',
  }
  return icons[severity as keyof typeof icons] || icons.info
}

export default function RiskFindings({ findings, diffSkeleton = [] }: RiskFindingsProps) {
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
    <div className="card">
      <h3 className="text-lg font-semibold text-gray-900 mb-6">Detailed Findings</h3>

      <div className="space-y-6">
        {sortedSeverities.map((severity) => (
          <div key={severity}>
            <h4 className="text-sm font-medium text-gray-700 mb-3 flex items-center">
              <span className="mr-2">{getSeverityIcon(severity)}</span>
              {severity.charAt(0).toUpperCase() + severity.slice(1)} Severity
              <span className="ml-2 text-gray-500">({groupedFindings[severity].length})</span>
            </h4>

            <div className="space-y-4">
              {groupedFindings[severity].map((finding, idx) => (
                <div
                  key={idx}
                  className="border border-gray-200 rounded-lg p-4 hover:shadow-md transition-shadow"
                >
                  <div className="flex items-start justify-between mb-2">
                    <h5 className="text-base font-medium text-gray-900">{finding.title}</h5>
                    <span className={getSeverityBadge(finding.severity)}>
                      {finding.severity.toUpperCase()}
                    </span>
                  </div>

                  <div className="text-sm text-gray-600 mb-3">
                    <span className="font-medium">Resource:</span>{' '}
                    <code className="bg-gray-100 px-1.5 py-0.5 rounded text-xs">
                      {finding.resource_type}
                    </code>
                    {' / '}
                    <code className="bg-blue-50 px-1.5 py-0.5 rounded text-xs text-blue-700 font-medium">
                      {getResourceName(finding.resource_ref, finding.resource_type)}
                    </code>
                  </div>

                  {finding.evidence && Object.keys(finding.evidence).length > 0 && (
                    <div className="mb-3">
                      <details className="group">
                        <summary className="cursor-pointer text-sm text-blue-600 hover:text-blue-800 font-medium">
                          View Evidence
                        </summary>
                        <div className="mt-2 bg-gray-50 rounded p-3">
                          <pre className="text-xs text-gray-700 overflow-x-auto">
                            {JSON.stringify(finding.evidence, null, 2)}
                          </pre>
                        </div>
                      </details>
                    </div>
                  )}

                  {finding.recommendation && (
                    <div className="bg-blue-50 border-l-4 border-blue-400 p-3 mb-3">
                      <p className="text-sm text-blue-900">
                        <span className="font-medium">Recommendation:</span> {finding.recommendation}
                      </p>
                    </div>
                  )}

                  {finding.suggested_fix && (
                    <div className="mt-4">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-bold text-gray-500 uppercase tracking-wider">Suggested Fix (HCL)</span>
                        <button
                          onClick={() => navigator.clipboard.writeText(finding.suggested_fix || '')}
                          className="text-xs text-blue-600 hover:text-blue-800 font-medium flex items-center"
                        >
                          <span className="mr-1">📋</span> Copy Fix
                        </button>
                      </div>
                      <div className="bg-gray-900 rounded-md p-3 overflow-x-auto border border-gray-800">
                        <pre className="text-xs text-green-400 font-mono">
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
