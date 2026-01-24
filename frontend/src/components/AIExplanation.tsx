'use client'

import { useState, useEffect } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { BedrockExplanation, ResourceChange, RiskFinding } from '@/lib/types'
import { createResourceMapping, enhanceTextWithResourceNames } from '@/lib/resourceMapping'

interface AIExplanationProps {
  explanation: BedrockExplanation
  diffSkeleton?: ResourceChange[]
  riskFindings?: RiskFinding[]
  isIAM?: boolean
}

export default function AIExplanation({ explanation, diffSkeleton = [], riskFindings = [], isIAM = false }: AIExplanationProps) {
  const [expandedSection, setExpandedSection] = useState<string | null>('summary')

  // Expand all sections when printing
  useEffect(() => {
    const handleBeforePrint = () => {
      // Store current state
      const currentSection = expandedSection
      // Expand all by setting to null (we'll modify the render logic)
      setExpandedSection('print-all')
    }

    const handleAfterPrint = () => {
      setExpandedSection('summary')
    }

    window.addEventListener('beforeprint', handleBeforePrint)
    window.addEventListener('afterprint', handleAfterPrint)

    return () => {
      window.removeEventListener('beforeprint', handleBeforePrint)
      window.removeEventListener('afterprint', handleAfterPrint)
    }
  }, [expandedSection])

  // Create resource mapping for hash-to-name translation
  const resourceMapping = createResourceMapping(diffSkeleton, riskFindings)

  // Enhance text with resource names
  const enhancedChanges = enhanceTextWithResourceNames(explanation.plain_english_changes, resourceMapping)
  const enhancedRisks = enhanceTextWithResourceNames(explanation.top_risks_explained, resourceMapping)

  const toggleSection = (section: string) => {
    setExpandedSection(expandedSection === section ? null : section)
  }

  const SectionHeader = ({
    id,
    title,
    icon,
    badge
  }: {
    id: string
    title: string
    icon: React.ReactNode
    badge?: string
  }) => {
    const isExpanded = expandedSection === id
    return (
      <button
        onClick={() => toggleSection(id)}
        className="w-full flex items-center justify-between p-4 hover:bg-gray-50 transition-colors rounded-lg"
      >
        <div className="flex items-center">
          <div className="flex-shrink-0 mr-3">
            {icon}
          </div>
          <div className="flex items-center">
            <h3 className="text-base font-semibold text-gray-900">{title}</h3>
            {badge && (
              <span className="ml-2 px-2 py-0.5 text-xs font-medium bg-blue-100 text-blue-800 rounded-full">
                {badge}
              </span>
            )}
          </div>
        </div>
        <svg
          className={`w-5 h-5 text-gray-500 transition-transform ${isExpanded ? 'rotate-180' : ''}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
    )
  }

  return (
    <div className="card space-y-1">
      {/* Header */}
      <div className="flex items-center justify-between mb-4 pb-4 border-b border-gray-200">
        <div className="flex items-center">
          <svg className="w-6 h-6 text-blue-600 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
          </svg>
          <h2 className="text-xl font-bold text-gray-900">AI Analysis</h2>
        </div>
        <details className="group relative">
          <summary className="cursor-pointer text-xs text-gray-500 hover:text-gray-700 flex items-center list-none">
            <svg className="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            How is data sanitized?
          </summary>
          <div className="hidden group-open:block absolute z-10 right-0 mt-2 w-96 bg-white border border-gray-200 rounded-lg shadow-xl p-4">
            <h4 className="text-sm font-semibold text-gray-900 mb-2">Data Sanitization Process</h4>
            <div className="text-xs text-gray-600 space-y-2">
              <div>
                <strong className="text-gray-700">1. {isIAM ? 'Identity Hashing' : 'Resource Hashing'}</strong>
                <p className="ml-3 mt-1">
                  {isIAM
                    ? <span>Account IDs like <code className="bg-gray-100 px-1 rounded">123456789012</code> and ARNs are converted to secure hashes like <code className="bg-gray-100 px-1 rounded">acct_abc123</code>.</span>
                    : <span>Resource addresses like <code className="bg-gray-100 px-1 rounded">aws_db_instance.prod-database</code> are converted to hashes.</span>
                  }
                </p>
              </div>
              <div>
                <strong className="text-gray-700">2. Metadata Only</strong>
                <p className="ml-3 mt-1">The AI receives only {isIAM ? 'actions and resource patterns' : 'resource types and attribute paths'}—never raw {isIAM ? 'policy values' : 'configuration values'}.</p>
              </div>
              <div>
                <strong className="text-gray-700">3. Frontend Enhancement</strong>
                <p className="ml-3 mt-1">This interface automatically replaces hashes with your original names for readability, but the AI never sees them.</p>
              </div>
            </div>
          </div>
        </details>
      </div>

      {/* Executive Summary - Always visible */}
      {explanation.executive_summary && explanation.executive_summary.length > 0 && (
        <div className="mb-2">
          <SectionHeader
            id="summary"
            title="Executive Summary"
            icon={
              <svg className="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
            }
          />
          {(expandedSection === 'summary' || expandedSection === 'print-all') && (
            <div className="px-4 pb-4 pt-2">
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
                <ul className="space-y-3">
                  {explanation.executive_summary.map((item, idx) => (
                    <li key={idx} className="flex items-start">
                      <span className="flex-shrink-0 w-2 h-2 rounded-full bg-blue-600 mt-1.5 mr-3"></span>
                      <span className="text-sm text-gray-800 leading-relaxed">{item}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </div>
      )}

      {/* What's Changing / Policy Overview */}
      {enhancedChanges && (
        <div className="mb-2">
          <SectionHeader
            id="changes"
            title={isIAM ? "Policy Overview" : "What's Changing"}
            icon={
              <svg className="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
              </svg>
            }
          />
          {(expandedSection === 'changes' || expandedSection === 'print-all') && (
            <div className="px-4 pb-4 pt-2">
              <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
                <div className="prose prose-sm max-w-none prose-headings:text-gray-900 prose-headings:font-semibold prose-p:text-gray-700 prose-strong:text-gray-900 prose-ul:text-gray-700 prose-li:text-gray-700">
                  <ReactMarkdown remarkPlugins={[remarkGfm]}>
                    {enhancedChanges}
                  </ReactMarkdown>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Review Checklist */}
      {explanation.review_questions && explanation.review_questions.length > 0 && (
        <div className="mb-2">
          <SectionHeader
            id="checklist"
            title="Review Checklist"
            icon={
              <svg className="w-5 h-5 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
              </svg>
            }
            badge={`${explanation.review_questions.length} items`}
          />
          {(expandedSection === 'checklist' || expandedSection === 'print-all') && (
            <div className="px-4 pb-4 pt-2">
              <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
                <ul className="space-y-3">
                  {explanation.review_questions.map((question, idx) => (
                    <li key={idx} className="flex items-start group hover:bg-white rounded p-2 transition-colors">
                      <input
                        type="checkbox"
                        id={`question-${idx}`}
                        className="mt-1 mr-3 h-4 w-4 text-purple-600 border-gray-300 rounded focus:ring-purple-500 cursor-pointer"
                      />
                      <label
                        htmlFor={`question-${idx}`}
                        className="text-sm text-gray-700 leading-relaxed cursor-pointer"
                      >
                        {question}
                      </label>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
