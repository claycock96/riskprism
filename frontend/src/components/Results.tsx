'use client'

import { AnalyzeResponse } from '@/lib/types'
import Summary from './Summary'
import RiskFindings from './RiskFindings'
import AIExplanation from './AIExplanation'
import PRComment from './PRComment'

interface ResultsProps {
  results: AnalyzeResponse
  onReset: () => void
}

export default function Results({ results, onReset }: ResultsProps) {
  const handleSavePDF = () => {
    window.print()
  }

  return (
    <div className="space-y-6">
      {/* Header with Reset Button */}
      <div className="flex items-center justify-between print:hidden">
        <h2 className="text-2xl font-bold text-gray-900">Analysis Results</h2>
        <div className="flex gap-3">
          <button
            onClick={handleSavePDF}
            className="px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 flex items-center"
          >
            <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Save as PDF
          </button>
          <button
            onClick={onReset}
            className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
          >
            Analyze Another Plan
          </button>
        </div>
      </div>

      {/* Print-only header */}
      <div className="hidden print:block mb-6">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Terraform Plan Security Analysis</h1>
        <p className="text-sm text-gray-600">Generated: {new Date().toLocaleString()}</p>
      </div>

      {/* Summary Section */}
      <Summary
        summary={results.summary}
        riskFindings={results.risk_findings}
        diffSkeleton={results.diff_skeleton}
      />

      {/* AI Explanation Section */}
      <AIExplanation
        explanation={results.explanation}
        diffSkeleton={results.diff_skeleton}
        riskFindings={results.risk_findings}
      />

      {/* Risk Findings Section */}
      <RiskFindings
        findings={results.risk_findings}
        diffSkeleton={results.diff_skeleton}
      />

      {/* PR Comment Section */}
      <PRComment comment={results.pr_comment} />
    </div>
  )
}
