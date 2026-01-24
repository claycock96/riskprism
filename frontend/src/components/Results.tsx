'use client'

import { useState } from 'react'
import { AnalyzeResponse } from '@/lib/types'
import Summary from './Summary'
import RiskFindings from './RiskFindings'
import AIExplanation from './AIExplanation'
import PRComment from './PRComment'
import ResourceChanges from './ResourceChanges'

interface ResultsProps {
  results: AnalyzeResponse
  onReset: () => void
}

export default function Results({ results, onReset }: ResultsProps) {
  const [copied, setCopied] = useState(false)

  const handleSavePDF = () => {
    window.print()
  }

  const handleShare = async () => {
    try {
      await navigator.clipboard.writeText(window.location.href)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      console.error('Failed to copy URL:', err)
    }
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
            onClick={handleShare}
            className={`px-4 py-2 text-sm font-medium rounded-md border transition-all flex items-center ${copied ? 'bg-green-50 text-green-700 border-green-200' : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-50'}`}
          >
            <svg className={`w-4 h-4 mr-2 ${copied ? 'text-green-600' : 'text-gray-400'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              {copied ? (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              ) : (
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z" />
              )}
            </svg>
            {copied ? 'Link Copied!' : 'Share Results'}
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

      {/* AI Explanation Section - Top level summary */}
      <AIExplanation
        explanation={results.explanation}
        diffSkeleton={results.diff_skeleton}
        riskFindings={results.risk_findings}
      />

      {/* Summary Section */}
      <Summary
        summary={results.summary}
        riskFindings={results.risk_findings}
        diffSkeleton={results.diff_skeleton}
        cached={results.cached}
      />

      {/* Resource Changes Section */}
      <ResourceChanges
        diffSkeleton={results.diff_skeleton}
      />

      {/* Risk Findings Section - Merged with AI reasoning */}
      <RiskFindings
        findings={results.risk_findings}
        diffSkeleton={results.diff_skeleton}
        aiRisksNarrative={results.explanation.top_risks_explained}
      />

      {/* PR Comment Section */}
      <PRComment comment={results.pr_comment} />
    </div>
  )
}
