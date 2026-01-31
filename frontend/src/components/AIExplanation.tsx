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

  // Parse **bold** text and render with styling
  const renderWithBold = (text: string) => {
    const parts = text.split(/(\*\*[^*]+\*\*)/)
    return parts.map((part, idx) => {
      if (part.startsWith('**') && part.endsWith('**')) {
        const boldText = part.slice(2, -2)
        return (
          <span key={idx} className="font-semibold text-white">
            {boldText}
          </span>
        )
      }
      return <span key={idx}>{part}</span>
    })
  }

  // Parse the changes content into structured cards
  const parseChangesContent = (content: string) => {
    const lines = content.split('\n').map(line => line.trim()).filter(line => line)
    type ParsedSection = {
      title: string
      type: 'resources' | 'callout'
      resources: { name: string; description: string; details: string[] }[]
      calloutItems?: string[]
    }
    const sections: ParsedSection[] = []
    let currentSection: ParsedSection | null = null
    let currentResource: { name: string; description: string; details: string[] } | null = null

    // Patterns for callout sections (rendered differently)
    const calloutPatterns = /^(Key Concerns|Summary|Important|Notes|Recommendations)/i

    for (const line of lines) {
      // Section headers: "Changes Overview", "Resources Being Created (4)", etc.
      if (line.match(/^(Changes Overview|Policy Overview|Resources Being (Created|Updated|Deleted|Replaced))/i)) {
        if (currentSection) sections.push(currentSection)
        currentSection = { title: line, type: 'resources', resources: [] }
        currentResource = null
      }
      // Callout section headers: "**Key Concerns**", etc.
      else if (line.match(/^\*\*[^*]+\*\*/) && line.match(calloutPatterns)) {
        if (currentSection) sections.push(currentSection)
        const match = line.match(/^\*\*([^*]+)\*\*/)
        currentSection = {
          title: match ? match[1] : 'Notes',
          type: 'callout',
          resources: [],
          calloutItems: []
        }
        currentResource = null
      }
      // Resource type headers: "**Security Group** (1 resource)" or "**Statement 1**: description"
      else if (line.match(/^\*\*[^*]+\*\*/)) {
        const match = line.match(/^\*\*([^*]+)\*\*\s*[:.]?\s*(.*)/)
        if (match) {
          // Create a default section if we haven't found one yet
          if (!currentSection) {
            currentSection = { title: isIAM ? 'Policy Overview' : 'Changes Overview', type: 'resources', resources: [] }
          }
          // If this is a callout section, add as callout item instead
          if (currentSection.type === 'callout') {
            currentSection.calloutItems?.push(line.replace(/^\*\*([^*]+)\*\*\s*[:.]?\s*/, '$1: '))
            continue
          }
          currentResource = { name: match[1], description: match[2] || '', details: [] }
          currentSection.resources.push(currentResource)
        }
      }
      // Detail lines starting with - (bullet points)
      else if (line.startsWith('-') && currentSection?.type === 'callout') {
        currentSection.calloutItems?.push(line.slice(1).trim())
      }
      // Detail lines
      else if (currentResource) {
        currentResource.details.push(line)
      }
      // Lines in callout section without bullet
      else if (currentSection?.type === 'callout') {
        currentSection.calloutItems?.push(line)
      }
    }
    if (currentSection) sections.push(currentSection)

    // Render the parsed structure
    return sections.map((section, sIdx) => (
      <div key={sIdx} className={sIdx > 0 ? 'mt-4' : ''}>
        {/* Section Header */}
        <div className="flex items-center gap-2 mb-3">
          <span className={`text-xs font-semibold uppercase tracking-wider ${
            section.title.includes('Created') ? 'text-emerald-400' :
            section.title.includes('Updated') ? 'text-blue-400' :
            section.title.includes('Deleted') ? 'text-red-400' :
            section.type === 'callout' ? 'text-amber-400' :
            'text-slate-400'
          }`}>
            {section.title}
          </span>
        </div>

        {/* Callout Box */}
        {section.type === 'callout' && section.calloutItems && (
          <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/30">
            <ul className="space-y-2">
              {section.calloutItems.map((item, idx) => (
                <li key={idx} className="flex items-start gap-2 text-sm text-slate-300">
                  <span className="text-amber-400 mt-0.5">•</span>
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Resource Cards */}
        {section.type === 'resources' && (
          <div className="grid gap-3">
            {section.resources.map((resource, rIdx) => (
              <div key={rIdx} className="p-3 rounded-lg bg-slate-800/50 border border-slate-700/50">
                <div className="flex items-start gap-2 mb-2">
                  <span className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${
                    section.title.includes('Created') ? 'bg-emerald-500' :
                    section.title.includes('Updated') ? 'bg-blue-500' :
                    section.title.includes('Deleted') ? 'bg-red-500' :
                    'bg-slate-500'
                  }`} />
                  <div className="flex-1 min-w-0">
                    <span className="font-medium text-white">{resource.name}</span>
                    {resource.description && (
                      <p className="text-sm text-slate-400 mt-1">{resource.description}</p>
                    )}
                  </div>
                </div>
                {resource.details.length > 0 && (
                  <ul className="space-y-1 pl-4 mt-2 border-l-2 border-slate-700 ml-1">
                    {resource.details.map((detail, dIdx) => (
                      <li key={dIdx} className="text-sm text-slate-400 pl-2">{detail}</li>
                    ))}
                  </ul>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    ))
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
                            <span className="text-sm text-slate-300 leading-relaxed">{renderWithBold(item)}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {section.type === 'markdown' && typeof section.content === 'string' && (
                    <div className="space-y-4">
                      {(() => {
                        const parsed = parseChangesContent(section.content)
                        // If parsing found structured content, use it; otherwise fall back to ReactMarkdown
                        if (parsed.length > 0) {
                          return parsed
                        }
                        return (
                          <div className="prose prose-invert prose-sm max-w-none">
                            <ReactMarkdown remarkPlugins={[remarkGfm]}>
                              {section.content}
                            </ReactMarkdown>
                          </div>
                        )
                      })()}
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
