'use client'

import { useState } from 'react'
import { PlanSummary, RiskFinding, ResourceChange } from '@/lib/types'

interface SummaryProps {
  summary: PlanSummary
  riskFindings: RiskFinding[]
  diffSkeleton?: ResourceChange[]
}

export default function Summary({ summary, riskFindings, diffSkeleton = [] }: SummaryProps) {
  const [hoveredStat, setHoveredStat] = useState<string | null>(null)

  // Count findings by severity
  const severityCounts = riskFindings.reduce((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] || 0) + 1
    return acc
  }, {} as Record<string, number>)

  // Group resources by action type
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

  const stats = [
    {
      label: 'Total Changes',
      value: summary.total_changes,
      color: 'text-gray-900',
      bgColor: 'bg-gray-100',
      resources: diffSkeleton,
    },
    {
      label: 'Creates',
      value: summary.creates,
      color: 'text-green-700',
      bgColor: 'bg-green-100',
      resources: getResourcesByAction('Creates'),
    },
    {
      label: 'Updates',
      value: summary.updates,
      color: 'text-blue-700',
      bgColor: 'bg-blue-100',
      resources: getResourcesByAction('Updates'),
    },
    {
      label: 'Deletes',
      value: summary.deletes,
      color: 'text-red-700',
      bgColor: 'bg-red-100',
      resources: getResourcesByAction('Deletes'),
    },
    {
      label: 'Replaces',
      value: summary.replaces,
      color: 'text-orange-700',
      bgColor: 'bg-orange-100',
      resources: getResourcesByAction('Replaces'),
    },
  ]

  const riskStats = [
    {
      label: 'Critical',
      value: severityCounts.critical || 0,
      color: 'text-red-700',
      bgColor: 'bg-red-100',
      icon: '🔴',
    },
    {
      label: 'High',
      value: severityCounts.high || 0,
      color: 'text-orange-700',
      bgColor: 'bg-orange-100',
      icon: '🟠',
    },
    {
      label: 'Medium',
      value: severityCounts.medium || 0,
      color: 'text-yellow-700',
      bgColor: 'bg-yellow-100',
      icon: '🟡',
    },
    {
      label: 'Low',
      value: severityCounts.low || 0,
      color: 'text-blue-700',
      bgColor: 'bg-blue-100',
      icon: '🔵',
    },
  ]

  const criticalCount = severityCounts.critical || 0
  const highCount = severityCounts.high || 0
  const hasHighRisks = criticalCount > 0 || highCount > 0

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-6">
        <h3 className="text-lg font-semibold text-gray-900">Plan Summary</h3>
        {hasHighRisks && (
          <span className="inline-flex items-center px-3 py-1 rounded-full text-sm font-medium bg-red-100 text-red-800">
            <svg className="w-4 h-4 mr-1.5" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
            </svg>
            Requires Review
          </span>
        )}
      </div>

      {/* Resource Changes */}
      <div className="mb-6">
        <h4 className="text-sm font-medium text-gray-700 mb-3">Resource Changes</h4>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {stats.map((stat) => (
            <div
              key={stat.label}
              className={`${stat.bgColor} rounded-lg p-4 relative ${stat.value > 0 ? 'cursor-help' : ''}`}
              onMouseEnter={() => stat.value > 0 && setHoveredStat(stat.label)}
              onMouseLeave={() => setHoveredStat(null)}
            >
              <div className={`text-2xl font-bold ${stat.color}`}>{stat.value}</div>
              <div className="text-sm text-gray-600 mt-1">{stat.label}</div>

              {/* Tooltip */}
              {hoveredStat === stat.label && stat.resources.length > 0 && (
                <div className="absolute z-10 bottom-full left-1/2 transform -translate-x-1/2 mb-2 w-80">
                  <div className="bg-gray-900 text-white text-xs rounded-lg py-2 px-3 shadow-lg">
                    <div className="font-semibold mb-1">{stat.label}:</div>
                    <div className="max-h-48 overflow-y-auto">
                      {stat.resources.slice(0, 20).map((resource, idx) => (
                        <div key={idx} className="py-0.5">
                          <div className="font-mono text-xs">
                            {resource.resource_address ? (
                              <span>
                                <span className="text-gray-400">{resource.resource_type}</span>
                                <span className="text-white"> ({resource.resource_address.split('.').slice(1).join('.')})</span>
                              </span>
                            ) : (
                              <span className="text-white">{resource.resource_type}</span>
                            )}
                          </div>
                        </div>
                      ))}
                      {stat.resources.length > 20 && (
                        <div className="text-gray-400 italic mt-1">
                          ... and {stat.resources.length - 20} more
                        </div>
                      )}
                    </div>
                    {/* Arrow */}
                    <div className="absolute top-full left-1/2 transform -translate-x-1/2 -mt-1">
                      <div className="border-4 border-transparent border-t-gray-900"></div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Security Findings */}
      <div>
        <h4 className="text-sm font-medium text-gray-700 mb-3">Security Findings</h4>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {riskStats.map((stat) => (
            <div key={stat.label} className={`${stat.bgColor} rounded-lg p-4`}>
              <div className="flex items-center">
                <span className="text-xl mr-2">{stat.icon}</span>
                <div>
                  <div className={`text-2xl font-bold ${stat.color}`}>{stat.value}</div>
                  <div className="text-sm text-gray-600">{stat.label}</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {riskFindings.length === 0 && (
        <div className="mt-6 rounded-md bg-green-50 p-4">
          <div className="flex">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-green-400" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3">
              <p className="text-sm font-medium text-green-800">
                No security issues detected
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
