'use client'

import { BedrockExplanation, ResourceChange, RiskFinding } from '@/lib/types'
import { createResourceMapping, enhanceTextWithResourceNames } from '@/lib/resourceMapping'

interface AIExplanationProps {
  explanation: BedrockExplanation
  diffSkeleton?: ResourceChange[]
  riskFindings?: RiskFinding[]
}

export default function AIExplanation({ explanation, diffSkeleton = [], riskFindings = [] }: AIExplanationProps) {
  // Create resource mapping for hash-to-name translation
  const resourceMapping = createResourceMapping(diffSkeleton, riskFindings)

  // Enhance text with resource names
  const enhancedChanges = enhanceTextWithResourceNames(explanation.plain_english_changes, resourceMapping)
  const enhancedRisks = enhanceTextWithResourceNames(explanation.top_risks_explained, resourceMapping)

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center">
          <svg className="w-6 h-6 text-blue-600 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
          </svg>
          <h3 className="text-lg font-semibold text-gray-900">AI Analysis</h3>
        </div>
        <details className="group">
          <summary className="cursor-pointer text-xs text-gray-500 hover:text-gray-700 flex items-center">
            <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            How is data sanitized?
          </summary>
          <div className="absolute z-10 right-0 mt-2 w-96 bg-white border border-gray-200 rounded-lg shadow-lg p-4">
            <h4 className="text-sm font-semibold text-gray-900 mb-2">Data Sanitization Process</h4>
            <div className="text-xs text-gray-600 space-y-2">
              <div>
                <strong className="text-gray-700">1. Resource Hashing</strong>
                <p className="ml-3 mt-1">Resource addresses like <code className="bg-gray-100 px-1 rounded">aws_db_instance.prod-database</code> are converted to hashes like <code className="bg-gray-100 px-1 rounded">res_abc123def4</code> before being sent to the AI.</p>
              </div>
              <div>
                <strong className="text-gray-700">2. Metadata Only</strong>
                <p className="ml-3 mt-1">The AI receives only resource types, actions (create/update/delete), and changed attribute paths—never the actual values.</p>
              </div>
              <div>
                <strong className="text-gray-700">3. Sensitive Keys Blocked</strong>
                <p className="ml-3 mt-1">Attributes like passwords, tokens, API keys, and secrets are completely filtered out during parsing.</p>
              </div>
              <div>
                <strong className="text-gray-700">4. Frontend Enhancement</strong>
                <p className="ml-3 mt-1">This interface automatically replaces hashes with your original resource names for readability, but the AI never sees them.</p>
              </div>
            </div>
            <div className="mt-3 pt-3 border-t border-gray-200">
              <p className="text-xs text-gray-500">
                <strong>Result:</strong> The AI can provide security insights without access to potentially sensitive infrastructure naming conventions or configuration values.
              </p>
            </div>
          </div>
        </details>
      </div>

      {/* Executive Summary */}
      {explanation.executive_summary && explanation.executive_summary.length > 0 && (
        <div className="mb-6">
          <h4 className="text-sm font-medium text-gray-700 mb-3">Executive Summary</h4>
          <ul className="space-y-2">
            {explanation.executive_summary.map((item, idx) => (
              <li key={idx} className="flex items-start">
                <span className="flex-shrink-0 w-1.5 h-1.5 rounded-full bg-blue-600 mt-2 mr-3"></span>
                <span className="text-gray-700">{item}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Plain English Changes */}
      {enhancedChanges && (
        <div className="mb-6">
          <h4 className="text-sm font-medium text-gray-700 mb-3">What's Changing</h4>
          <div className="prose prose-sm max-w-none">
            <div className="text-gray-700 whitespace-pre-wrap">
              {enhancedChanges}
            </div>
          </div>
        </div>
      )}

      {/* Top Risks Explained */}
      {enhancedRisks && (
        <div className="mb-6">
          <h4 className="text-sm font-medium text-gray-700 mb-3">Top Security Risks</h4>
          <div className="prose prose-sm max-w-none bg-red-50 border border-red-200 rounded-lg p-4">
            <div className="text-gray-700 whitespace-pre-wrap">
              {enhancedRisks}
            </div>
          </div>
        </div>
      )}

      {/* Review Questions */}
      {explanation.review_questions && explanation.review_questions.length > 0 && (
        <div>
          <h4 className="text-sm font-medium text-gray-700 mb-3">Review Checklist</h4>
          <ul className="space-y-2">
            {explanation.review_questions.map((question, idx) => (
              <li key={idx} className="flex items-start">
                <input
                  type="checkbox"
                  className="mt-1 mr-3 h-4 w-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                />
                <label className="text-sm text-gray-700">{question}</label>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}
