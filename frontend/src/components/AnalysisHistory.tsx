'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { AnalyzeResponse } from '@/lib/types'
import { extractResourceName } from '@/lib/resourceMapping'

import { authenticatedFetch } from '@/lib/api'

export default function AnalysisHistory() {
    const [history, setHistory] = useState<AnalyzeResponse[]>([])
    const [loading, setLoading] = useState(true)

    useEffect(() => {
        const fetchHistory = async () => {
            try {
                const response = await authenticatedFetch(`${process.env.NEXT_PUBLIC_API_URL}/history`)
                if (response.ok) {
                    const data = await response.json()
                    setHistory(data)
                }
            } catch (error) {
                console.error('Failed to fetch history:', error)
            } finally {
                setLoading(false)
            }
        }

        fetchHistory()
    }, [])

    if (loading) {
        return (
            <div className="flex justify-center py-16">
                <div className="relative w-12 h-12">
                    <div className="absolute inset-0 rounded-full border-2 border-violet-500/30 animate-pulse" />
                    <div className="absolute inset-1 rounded-full border-2 border-transparent border-t-violet-500 animate-spin" />
                </div>
            </div>
        )
    }

    if (history.length === 0) {
        return (
            <div className="glass-panel p-12 text-center">
                <div className="w-16 h-16 mx-auto mb-6 rounded-2xl bg-slate-800 flex items-center justify-center">
                    <svg className="w-8 h-8 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                </div>
                <p className="text-slate-400 mb-4">No analysis history found</p>
                <Link href="/" className="btn-primary inline-flex items-center gap-2">
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                    </svg>
                    <span className="relative z-10">Analyze a Plan</span>
                </Link>
            </div>
        )
    }

    return (
        <div className="space-y-4">
            {history.map((item) => {
                const criticalCount = item.risk_findings.filter(f => f.severity === 'critical').length
                const highCount = item.risk_findings.filter(f => f.severity === 'high').length
                const hasCritical = criticalCount > 0
                const hasHigh = highCount > 0

                return (
                    <Link
                        key={item.session_id}
                        href={`/results/${item.session_id}`}
                        className={`block glass-panel-hover p-5 ${hasCritical ? 'border-red-500/30' : hasHigh ? 'border-orange-500/20' : ''}`}
                    >
                        <div className="flex items-center justify-between">
                            <div className="flex items-center gap-4">
                                <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${hasCritical ? 'bg-red-500/20' : hasHigh ? 'bg-orange-500/20' : 'bg-violet-500/20'
                                    }`}>
                                    <svg className={`w-5 h-5 ${hasCritical ? 'text-red-400' : hasHigh ? 'text-orange-400' : 'text-violet-400'
                                        }`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                    </svg>
                                </div>
                                <div>
                                    <div className="flex items-center gap-2">
                                        <p className="font-medium text-white">
                                            Report {item.session_id?.slice(0, 8)}...
                                        </p>
                                        <span className="text-xs text-slate-500">
                                            {item.created_at ? new Date(item.created_at).toLocaleDateString() : ''}
                                        </span>
                                    </div>
                                    <div className="flex items-center gap-3 mt-1 text-sm text-slate-400">
                                        <span>{item.summary.total_changes} changes</span>
                                        <span className="text-slate-600">•</span>
                                        <span>{item.risk_findings.length} findings</span>
                                    </div>
                                </div>
                            </div>

                            <div className="flex items-center gap-3">
                                {hasCritical && (
                                    <span className="badge badge-critical">{criticalCount} Critical</span>
                                )}
                                {hasHigh && (
                                    <span className="badge badge-high">{highCount} High</span>
                                )}
                                <svg className="w-5 h-5 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                </svg>
                            </div>
                        </div>
                    </Link>
                )
            })}
        </div>
    )
}
