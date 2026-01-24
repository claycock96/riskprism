'use client'

import Link from 'next/link'
import AnalysisHistory from '@/components/AnalysisHistory'

export default function HistoryPage() {
    return (
        <div className="max-w-4xl mx-auto space-y-8">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold text-gray-900">Analysis History</h2>
                    <p className="text-gray-600">Review your past Terraform plan reports</p>
                </div>
                <Link
                    href="/"
                    className="btn btn-secondary text-sm"
                >
                    ← Analyze New Plan
                </Link>
            </div>

            <div className="card">
                <AnalysisHistory />
            </div>
        </div>
    )
}
