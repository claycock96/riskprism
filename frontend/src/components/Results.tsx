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
  return (
    <div className="space-y-6">
      {/* Header with Reset Button */}
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-gray-900">Analysis Results</h2>
        <button
          onClick={onReset}
          className="px-4 py-2 text-sm font-medium text-gray-700 bg-white border border-gray-300 rounded-md hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
        >
          Analyze Another Plan
        </button>
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
