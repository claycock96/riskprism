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

  const sections = [
    {
      id: 'summary',
      title: 'Executive Summary',
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
      ),
      gradient: 'from-blue-500 to-cyan-500',
      content: explanation.executive_summary,
      type: 'bullets' as const,
    },
    {
      id: 'changes',
      title: isIAM ? 'Policy Overview' : "What's Changing",
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
        </svg>
      ),
      gradient: 'from-emerald-500 to-green-500',
      content: enhancedChanges,
      type: 'markdown' as const,
    },
    {
      id: 'checklist',
      title: 'Review Checklist',
      icon: (
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
        </svg>
      ),
      gradient: 'from-purple-500 to-violet-500',
      content: explanation.review_questions,
      type: 'checklist' as const,
    },
  ]

  return (
    <div className="glass-panel p-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between mb-6 pb-4 border-b border-white/10">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500 to-fuchsia-500 flex items-center justify-center shadow-glow-md">
            <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            </svg>
          </div>
          <h2 className="text-xl font-bold text-white">AI Analysis</h2>
        </div>

        {/* Data Sanitization Info */}
        <details className="group relative">
          <summary className="cursor-pointer text-xs text-slate-400 hover:text-slate-300 flex items-center gap-1 list-none">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Data Privacy
          </summary>
          <div className="tooltip-glass absolute z-50 right-0 mt-3 w-80 animate-fade-in">
            <h4 className="text-sm font-semibold text-white mb-3">Data Sanitization</h4>
            <div className="space-y-3 text-xs text-slate-400">
              <div>
                <strong className="text-slate-300 block mb-1">1. {isIAM ? 'Identity Hashing' : 'Resource Hashing'}</strong>
                {isIAM
                  ? 'Account IDs and ARNs are converted to secure hashes.'
                  : 'Resource addresses are converted to secure hashes.'}
              </div>
              <div>
                <strong className="text-slate-300 block mb-1">2. Metadata Only</strong>
                The AI receives only {isIAM ? 'actions and patterns' : 'resource types and paths'}—never raw values.
              </div>
              <div>
                <strong className="text-slate-300 block mb-1">3. Frontend Enhancement</strong>
                Hashes are replaced with original names for readability here only.
              </div>
            </div>
          </div>
        </details>
      </div>

      {/* Accordion Sections */}
      <div className="space-y-2">
        {sections.map((section) => {
          if (!section.content || (Array.isArray(section.content) && section.content.length === 0)) {
            return null
          }

          const isExpanded = expandedSection === section.id || expandedSection === 'print-all'

          return (
            <div key={section.id} className="rounded-xl overflow-hidden border border-white/5">
              {/* Section Header */}
              <button
                onClick={() => toggleSection(section.id)}
                className="w-full flex items-center justify-between p-4 hover:bg-white/5 transition-colors"
              >
                <div className="flex items-center gap-3">
                  <div className={`w-8 h-8 rounded-lg bg-gradient-to-br ${section.gradient} flex items-center justify-center text-white`}>
                    {section.icon}
                  </div>
                  <span className="font-semibold text-white">{section.title}</span>
                  {section.type === 'checklist' && Array.isArray(section.content) && (
                    <span className="px-2 py-0.5 text-xs font-medium bg-purple-500/20 text-purple-300 rounded-full border border-purple-500/30">
                      {section.content.length} items
                    </span>
                  )}
                </div>
                <svg
                  className={`w-5 h-5 text-slate-400 transition-transform duration-300 ${isExpanded ? 'rotate-180' : ''}`}
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>

              {/* Section Content */}
              {isExpanded && (
                <div className="px-4 pb-4 animate-fade-in">
                  {section.type === 'bullets' && Array.isArray(section.content) && (
                    <div className="p-4 rounded-lg bg-blue-500/5 border border-blue-500/20">
                      <ul className="space-y-3">
                        {section.content.map((item, idx) => (
                          <li key={idx} className="flex items-start">
                            <span className="flex-shrink-0 w-1.5 h-1.5 rounded-full bg-blue-400 mt-2 mr-3" />
                            <span className="text-sm text-slate-300 leading-relaxed">{item}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {section.type === 'markdown' && typeof section.content === 'string' && (
                    <div className="p-4 rounded-lg bg-slate-900/50 border border-white/5">
                      <div className="prose prose-sm prose-invert max-w-none prose-headings:text-white prose-p:text-slate-300 prose-strong:text-white prose-ul:text-slate-300 prose-li:text-slate-300">
                        <ReactMarkdown remarkPlugins={[remarkGfm]}>
                          {section.content}
                        </ReactMarkdown>
                      </div>
                    </div>
                  )}

                  {section.type === 'checklist' && Array.isArray(section.content) && (
                    <div className="p-4 rounded-lg bg-purple-500/5 border border-purple-500/20">
                      <ul className="space-y-3">
                        {section.content.map((question, idx) => (
                          <li key={idx} className="flex items-start group hover:bg-white/5 rounded-lg p-2 -m-2 transition-colors">
                            <input
                              type="checkbox"
                              id={`question-${idx}`}
                              className="mt-1 mr-3 h-4 w-4 rounded border-slate-600 bg-slate-800 text-purple-500 focus:ring-purple-500 focus:ring-offset-0 cursor-pointer"
                            />
                            <label
                              htmlFor={`question-${idx}`}
                              className="text-sm text-slate-300 leading-relaxed cursor-pointer"
                            >
                              {question}
                            </label>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
