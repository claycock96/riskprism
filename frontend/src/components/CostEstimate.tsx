'use client'

import { useState } from 'react'
import { CostEstimate as CostEstimateType, ResourceCost } from '@/lib/types'
import { extractResourceName } from '@/lib/resourceMapping'

interface CostEstimateProps {
    estimate: CostEstimateType
}

export default function CostEstimate({ estimate }: CostEstimateProps) {
    const [expanded, setExpanded] = useState(false)
    const [hoveredResource, setHoveredResource] = useState<string | null>(null)

    // Format currency
    const formatCurrency = (amount: number) => {
        return new Intl.NumberFormat('en-US', {
            style: 'currency',
            currency: estimate.currency,
            minimumFractionDigits: 2,
            maximumFractionDigits: 2,
        }).format(amount)
    }

    // Format percent change
    const formatPercentChange = (change: number | undefined) => {
        if (change === undefined || change === null) return null
        const sign = change >= 0 ? '+' : ''
        return `${sign}${change.toFixed(1)}%`
    }

    // Get confidence badge styles - labels indicate pricing accuracy, not cost level
    const getConfidenceBadge = (confidence: string) => {
        switch (confidence) {
            case 'high':
                return {
                    bg: 'bg-emerald-500/20',
                    text: 'text-emerald-300',
                    label: 'exact',
                    icon: (
                        <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                            <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                        </svg>
                    ),
                }
            case 'medium':
                return {
                    bg: 'bg-amber-500/20',
                    text: 'text-amber-300',
                    label: 'estimated',
                    icon: (
                        <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                        </svg>
                    ),
                }
            default:
                return {
                    bg: 'bg-slate-500/20',
                    text: 'text-slate-400',
                    label: 'unknown',
                    icon: (
                        <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-8-3a1 1 0 00-.867.5 1 1 0 11-1.731-1A3 3 0 0113 8a3.001 3.001 0 01-2 2.83V11a1 1 0 11-2 0v-1a1 1 0 011-1 1 1 0 100-2zm0 8a1 1 0 100-2 1 1 0 000 2z" clipRule="evenodd" />
                        </svg>
                    ),
                }
        }
    }

    // Get action styles
    const getActionStyle = (action: string) => {
        switch (action) {
            case 'create':
                return 'text-emerald-400'
            case 'delete':
                return 'text-red-400'
            case 'update':
                return 'text-blue-400'
            case 'replace':
                return 'text-orange-400'
            default:
                return 'text-slate-400'
        }
    }

    // Group costs by resource type
    const costsByType = estimate.resource_costs.reduce((acc, cost) => {
        if (!acc[cost.resource_type]) {
            acc[cost.resource_type] = { total: 0, count: 0, resources: [] as ResourceCost[] }
        }
        acc[cost.resource_type].total += cost.monthly_cost
        acc[cost.resource_type].count += 1
        acc[cost.resource_type].resources.push(cost)
        return acc
    }, {} as Record<string, { total: number; count: number; resources: ResourceCost[] }>)

    // Sort by cost descending
    const sortedTypes = Object.entries(costsByType)
        .sort(([, a], [, b]) => b.total - a.total)
        .filter(([, data]) => data.total > 0)

    // Get truly unknown resources (pricing_unit === 'unknown' means we couldn't estimate)
    const unknownResources = estimate.resource_costs.filter(rc => rc.pricing_unit === 'unknown')

    // Calculate change indicator
    const isIncrease = estimate.net_change && estimate.net_change > 0
    const isDecrease = estimate.net_change && estimate.net_change < 0

    return (
        <div className="glass-panel p-6 animate-fade-in">
            {/* Header Section */}
            <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-green-500 to-emerald-500 flex items-center justify-center">
                        <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                    </div>
                    <div>
                        <h3 className="text-lg font-bold text-white">Cost Estimate</h3>
                        <div className="flex items-center gap-2 text-xs text-slate-400">
                            <span>Pricing: {estimate.pricing_region}</span>
                            <span className="text-slate-600">•</span>
                            <span>Updated: {estimate.last_pricing_update}</span>
                        </div>
                    </div>
                </div>

                {/* Method Badge */}
                <div className="flex items-center gap-2">
                    <span className={`px-2 py-1 rounded-lg text-xs font-medium ${estimate.estimation_method === 'lookup'
                        ? 'bg-emerald-500/20 text-emerald-300'
                        : 'bg-amber-500/20 text-amber-300'
                        }`}>
                        {estimate.estimation_method === 'lookup' ? 'Database Lookup' : 'Hybrid Estimate'}
                    </span>
                </div>
            </div>

            {/* Main Cost Display */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                {/* Total Monthly Cost */}
                <div className="stat-card bg-gradient-to-br from-green-500/10 to-emerald-500/10 border border-green-500/30">
                    <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
                        Estimated Monthly Cost
                    </div>
                    <div className="text-3xl font-bold bg-gradient-to-r from-green-400 to-emerald-400 bg-clip-text text-transparent">
                        {formatCurrency(estimate.total_monthly_cost)}
                    </div>
                    <div className="text-xs text-slate-500 mt-1">
                        {estimate.resources_estimated} resources estimated
                    </div>
                </div>

                {/* Previous Cost (if applicable) */}
                {estimate.previous_monthly_cost && estimate.previous_monthly_cost > 0 && (
                    <div className="stat-card">
                        <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
                            Previous Cost
                        </div>
                        <div className="text-2xl font-bold text-slate-300">
                            {formatCurrency(estimate.previous_monthly_cost)}
                        </div>
                        <div className="text-xs text-slate-500 mt-1">
                            Before this plan
                        </div>
                    </div>
                )}

                {/* Change Indicator */}
                {estimate.percent_change !== undefined && estimate.percent_change !== null && (
                    <div className={`stat-card ${isIncrease ? 'border-red-500/30 bg-red-500/5' :
                        isDecrease ? 'border-emerald-500/30 bg-emerald-500/5' :
                            'border-slate-500/30'
                        }`}>
                        <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">
                            Cost Change
                        </div>
                        <div className={`text-2xl font-bold flex items-center gap-2 ${isIncrease ? 'text-red-400' : isDecrease ? 'text-emerald-400' : 'text-slate-400'
                            }`}>
                            {isIncrease && (
                                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                                    <path fillRule="evenodd" d="M5.293 9.707a1 1 0 010-1.414l4-4a1 1 0 011.414 0l4 4a1 1 0 01-1.414 1.414L11 7.414V15a1 1 0 11-2 0V7.414L6.707 9.707a1 1 0 01-1.414 0z" clipRule="evenodd" />
                                </svg>
                            )}
                            {isDecrease && (
                                <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                                    <path fillRule="evenodd" d="M14.707 10.293a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 111.414-1.414L9 12.586V5a1 1 0 012 0v7.586l2.293-2.293a1 1 0 011.414 0z" clipRule="evenodd" />
                                </svg>
                            )}
                            {formatPercentChange(estimate.percent_change)}
                        </div>
                        <div className="text-xs text-slate-500 mt-1">
                            {estimate.net_change !== undefined && (
                                <span className={isIncrease ? 'text-red-400' : 'text-emerald-400'}>
                                    {isIncrease ? '+' : ''}{formatCurrency(estimate.net_change)} /month
                                </span>
                            )}
                        </div>
                    </div>
                )}
            </div>

            {/* Unknown Resources Warning */}
            {estimate.resources_unknown > 0 && (
                <div className="mb-4 p-3 rounded-xl bg-amber-500/10 border border-amber-500/30">
                    <div className="flex items-start gap-2 text-sm text-amber-300">
                        <svg className="w-4 h-4 mt-0.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                            <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                        </svg>
                        <div>
                            <div className="font-medium">
                                {estimate.resources_unknown} resource{estimate.resources_unknown > 1 ? 's' : ''} could not be estimated:
                            </div>
                            <ul className="mt-1 text-xs text-amber-200/80 space-y-0.5">
                                {unknownResources.map((rc, idx) => (
                                    <li key={idx} className="font-mono">
                                        • {rc.resource_address || rc.resource_type} ({rc.resource_type})
                                    </li>
                                ))}
                            </ul>
                        </div>
                    </div>
                </div>
            )}

            {/* Cost Breakdown by Type */}
            {sortedTypes.length > 0 && (
                <div className="mb-4">
                    <button
                        onClick={() => setExpanded(!expanded)}
                        className="flex items-center gap-2 text-sm font-semibold text-slate-300 hover:text-white transition-colors"
                    >
                        <svg
                            className={`w-4 h-4 transform transition-transform ${expanded ? 'rotate-90' : ''}`}
                            fill="currentColor"
                            viewBox="0 0 20 20"
                        >
                            <path fillRule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clipRule="evenodd" />
                        </svg>
                        Cost Breakdown ({sortedTypes.length} resource types)
                    </button>

                    {expanded && (
                        <div className="mt-4 space-y-3 animate-fade-in">
                            {sortedTypes.map(([resourceType, data]) => (
                                <div
                                    key={resourceType}
                                    className="rounded-lg bg-slate-900/50 border border-white/5 overflow-hidden"
                                >
                                    <div
                                        className="flex items-center justify-between px-4 py-3 cursor-pointer hover:bg-white/5 transition-colors"
                                        onClick={() => setHoveredResource(hoveredResource === resourceType ? null : resourceType)}
                                    >
                                        <div className="flex items-center gap-3">
                                            <span className="font-mono text-sm text-slate-300">{resourceType}</span>
                                            <span className="text-xs text-slate-500">× {data.count}</span>
                                        </div>
                                        <div className="flex items-center gap-3">
                                            <span className="font-semibold text-slate-200">
                                                {formatCurrency(data.total)}/mo
                                            </span>
                                            <svg
                                                className={`w-4 h-4 text-slate-500 transform transition-transform ${hoveredResource === resourceType ? 'rotate-180' : ''
                                                    }`}
                                                fill="currentColor"
                                                viewBox="0 0 20 20"
                                            >
                                                <path fillRule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clipRule="evenodd" />
                                            </svg>
                                        </div>
                                    </div>

                                    {/* Per-resource details */}
                                    {hoveredResource === resourceType && (
                                        <div className="border-t border-white/5 bg-slate-900/30">
                                            {data.resources.map((cost, idx) => {
                                                const confidenceStyle = getConfidenceBadge(cost.confidence)
                                                return (
                                                    <div
                                                        key={idx}
                                                        className="flex items-center justify-between px-4 py-2 text-sm border-b border-white/5 last:border-0"
                                                    >
                                                        <div className="flex items-center gap-3">
                                                            <span className={`text-xs font-semibold uppercase ${getActionStyle(cost.action)}`}>
                                                                {cost.action}
                                                            </span>
                                                            <span className="font-mono text-slate-400">
                                                                {cost.resource_address
                                                                    ? extractResourceName(cost.resource_address)
                                                                    : cost.resource_ref.slice(0, 10)}
                                                            </span>
                                                        </div>
                                                        <div className="flex items-center gap-3">
                                                            <span className={`flex items-center gap-1 px-2 py-0.5 rounded text-xs ${confidenceStyle.bg} ${confidenceStyle.text}`}>
                                                                {confidenceStyle.icon}
                                                                {confidenceStyle.label}
                                                            </span>
                                                            <span className="text-slate-300 font-medium">
                                                                {formatCurrency(cost.monthly_cost)}
                                                            </span>
                                                        </div>
                                                    </div>
                                                )
                                            })}
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            )}

            {/* Footer - Disclaimer */}
            <div className="pt-4 border-t border-white/5">
                <p className="text-xs text-slate-500 italic">
                    Estimates based on {estimate.pricing_region} on-demand pricing. Actual costs may vary based on reserved
                    instances, savings plans, data transfer, and usage patterns.
                </p>
            </div>
        </div>
    )
}
