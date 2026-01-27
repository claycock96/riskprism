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

  // Detect analyzer type from results
  const isIAM = results.analyzer_type === 'iam' ||
    results.summary.terraform_version?.startsWith('IAM Policy') ||
    results.diff_skeleton.length === 0

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
      {/* Header with Actions */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 print:hidden">
        <div>
          <h2 className="text-2xl font-bold text-white">
            {isIAM ? 'IAM Policy Analysis' : 'Terraform Plan Analysis'}
          </h2>
          <p className="text-sm text-slate-400 mt-1">Security assessment complete</p>
        </div>

        <div className="flex flex-wrap gap-3">
          {/* Save PDF Button */}
          <button
            onClick={handleSavePDF}
            className="btn-primary flex items-center gap-2"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            <span className="relative z-10">Save PDF</span>
          </button>

          {/* Share Button */}
          <button
            onClick={handleShare}
            className={`btn-secondary flex items-center gap-2 ${copied ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-300' : ''
              }`}
          >
            {copied ? (
              <>
                <svg className="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                </svg>
                Link Copied!
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z" />
                </svg>
                Share
              </>
            )}
          </button>

          {/* Analyze Another Button */}
          <button
            onClick={onReset}
            className="btn-secondary flex items-center gap-2"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            {isIAM ? 'New Policy' : 'New Plan'}
          </button>
        </div>
      </div>

      {/* Print-only header */}
      <div className="hidden print:block mb-6">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">
          {isIAM ? 'IAM Policy Security Analysis' : 'Terraform Plan Security Analysis'}
        </h1>
        <p className="text-sm text-gray-600">Generated: {new Date().toLocaleString()}</p>
      </div>

      {/* AI Explanation Section */}
      <AIExplanation
        explanation={results.explanation}
        diffSkeleton={results.diff_skeleton}
        riskFindings={results.risk_findings}
        isIAM={isIAM}
      />

      {/* Summary Section */}
      <Summary
        summary={results.summary}
        riskFindings={results.risk_findings}
        diffSkeleton={results.diff_skeleton}
        cached={results.cached}
        isIAM={isIAM}
      />

      {/* Resource Changes Section - Only show for Terraform */}
      {!isIAM && results.diff_skeleton.length > 0 && (
        <ResourceChanges
          diffSkeleton={results.diff_skeleton}
        />
      )}

      {/* Risk Findings Section */}
      <RiskFindings
        findings={results.risk_findings}
        diffSkeleton={results.diff_skeleton}
        aiRisksNarrative={results.explanation.top_risks_explained}
        isIAM={isIAM}
      />

      {/* PR Comment Section */}
      <PRComment comment={results.pr_comment} />
    </div>
  )
}
