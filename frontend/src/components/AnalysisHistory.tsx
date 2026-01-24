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
            <div className="flex justify-center py-12">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
            </div>
        )
    }

    if (history.length === 0) {
        return (
            <div className="text-center py-12 bg-gray-50 rounded-lg border-2 border-dashed border-gray-200">
                <p className="text-gray-500 italic">No analysis history found. Upload a plan to get started!</p>
                <Link href="/" className="mt-4 inline-block text-blue-600 hover:underline font-medium">
                    Analyze a plan →
                </Link>
            </div>
        )
    }

    return (
        <div className="space-y-4">
            <div className="overflow-hidden bg-white shadow sm:rounded-md border border-gray-200">
                <ul role="list" className="divide-y divide-gray-200">
                    {history.map((item) => (
                        <li key={item.session_id}>
                            <Link href={`/results/${item.session_id}`} className="block hover:bg-gray-50">
                                <div className="px-4 py-4 sm:px-6">
                                    <div className="flex items-center justify-between">
                                        <p className="truncate text-sm font-medium text-blue-600">
                                            Analysis Report {item.session_id?.slice(0, 8)}...
                                        </p>
                                        <div className="ml-2 flex flex-shrink-0">
                                            <p className="inline-flex rounded-full bg-blue-100 px-2 text-xs font-semibold leading-5 text-blue-800">
                                                {item.summary.total_changes} Changes
                                            </p>
                                        </div>
                                    </div>
                                    <div className="mt-2 sm:flex sm:justify-between">
                                        <div className="sm:flex">
                                            <p className="flex items-center text-sm text-gray-500">
                                                <span className="mr-2">🛡️</span>
                                                {item.risk_findings.length} Security findings
                                            </p>
                                        </div>
                                        <div className="mt-2 flex items-center text-sm text-gray-500 sm:mt-0 italic">
                                            View full report →
                                        </div>
                                    </div>
                                </div>
                            </Link>
                        </li>
                    ))}
                </ul>
            </div>
        </div>
    )
}
