'use client'

import Link from 'next/link'
import AnalysisHistory from '@/components/AnalysisHistory'

export default function HistoryPage() {
    return (
        <div className="max-w-4xl mx-auto space-y-8">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold text-white">Analysis History</h2>
                    <p className="text-slate-400 mt-1">Review your past security analysis reports</p>
                </div>
                <Link
                    href="/"
                    className="btn-secondary flex items-center gap-2"
                >
                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                    </svg>
                    New Analysis
                </Link>
            </div>

            <AnalysisHistory />
        </div>
    )
}
