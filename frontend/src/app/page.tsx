'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { AnalyzeResponse } from '@/lib/types'
import UploadForm from '@/components/UploadForm'
import IAMUploadForm from '@/components/IAMUploadForm'
import AnalyzerSwitcher, { AnalyzerType } from '@/components/AnalyzerSwitcher'
import Results from '@/components/Results'

import { authenticatedFetch } from '@/lib/api'

export default function Home() {
  const router = useRouter()
  const [analyzerType, setAnalyzerType] = useState<AnalyzerType>('terraform')
  const [results, setResults] = useState<AnalyzeResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [loadingStage, setLoadingStage] = useState<'parsing' | 'rules' | 'ai' | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleAnalyzeTerraform = async (planJson: any) => {
    setLoading(true)
    setError(null)
    setResults(null)
    setLoadingStage('parsing')

    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

      setTimeout(() => setLoadingStage('rules'), 800)

      const response = await authenticatedFetch(`${apiUrl}/analyze/terraform`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ plan_json: planJson }),
      })

      const aiStageTimer = setTimeout(() => setLoadingStage('ai'), 1500)

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: 'Unknown error' }))
        clearTimeout(aiStageTimer)
        throw new Error(errorData.detail || `HTTP ${response.status}`)
      }

      const data: AnalyzeResponse = await response.json()
      clearTimeout(aiStageTimer)

      if (data.session_id) {
        router.push(`/results/${data.session_id}`)
      } else {
        setResults(data)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to analyze plan')
    } finally {
      setLoading(false)
      setLoadingStage(null)
    }
  }

  const handleAnalyzeIAM = async (policy: any) => {
    setLoading(true)
    setError(null)
    setResults(null)
    setLoadingStage('parsing')

    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

      setTimeout(() => setLoadingStage('rules'), 500)

      const response = await authenticatedFetch(`${apiUrl}/analyze/iam`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ policy }),
      })

      const aiStageTimer = setTimeout(() => setLoadingStage('ai'), 1000)

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: 'Unknown error' }))
        clearTimeout(aiStageTimer)
        throw new Error(errorData.detail || `HTTP ${response.status}`)
      }

      const data = await response.json()
      clearTimeout(aiStageTimer)

      // For IAM, we don't have session persistence yet, so show inline
      // Transform IAM response to match AnalyzeResponse structure for Results component
      const adaptedResults: AnalyzeResponse = {
        summary: {
          total_changes: data.summary.total_statements,
          creates: data.summary.allow_statements,
          updates: 0,
          deletes: data.summary.deny_statements,
          replaces: 0,
          terraform_version: `IAM Policy v${data.summary.policy_version}`,
        },
        diff_skeleton: [],
        risk_findings: data.risk_findings,
        explanation: data.explanation,
        pr_comment: data.pr_comment,
        cached: data.cached,
      }
      setResults(adaptedResults)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to analyze IAM policy')
    } finally {
      setLoading(false)
      setLoadingStage(null)
    }
  }

  const handleReset = () => {
    setResults(null)
    setError(null)
  }

  const getLoadingLabels = () => {
    if (analyzerType === 'terraform') {
      return {
        step1: 'Synthesizing Terraform Plan',
        step2: 'Performing Safety Scan (14+ Rules)',
        step3: 'Consulting AI Security Expert',
      }
    }
    return {
      step1: 'Parsing IAM Policy',
      step2: 'Running Security Rules (10+ Checks)',
      step3: 'Consulting AI Security Expert',
    }
  }

  const labels = getLoadingLabels()
  const accentColor = analyzerType === 'terraform' ? 'blue' : 'purple'

  return (
    <div className="space-y-8">
      {/* Analyzer Switcher - Always visible when not loading */}
      {!loading && !results && (
        <AnalyzerSwitcher
          activeAnalyzer={analyzerType}
          onSwitch={setAnalyzerType}
          disabled={loading}
        />
      )}

      {/* Input Forms */}
      {!results && !loading && analyzerType === 'terraform' && (
        <UploadForm onAnalyze={handleAnalyzeTerraform} />
      )}

      {!results && !loading && analyzerType === 'iam' && (
        <IAMUploadForm onAnalyze={handleAnalyzeIAM} disabled={loading} />
      )}

      {/* Loading State */}
      {loading && (
        <div className="card">
          <div className="flex flex-col items-center justify-center py-12">
            <div className={`inline-block h-12 w-12 animate-spin rounded-full border-4 border-solid border-${accentColor}-600 border-r-transparent mb-8`}></div>

            <div className="w-full max-w-xs space-y-4">
              <div className={`flex items-center gap-3 transition-opacity ${loadingStage === 'parsing' ? `opacity-100 font-bold text-${accentColor}-600` : 'opacity-50'}`}>
                {loadingStage !== 'parsing' && <span className="text-green-500">✓</span>}
                {loadingStage === 'parsing' && <span className={`w-4 h-4 border-2 border-${accentColor}-600 border-t-transparent animate-spin rounded-full`}></span>}
                <p className="text-sm">{labels.step1}</p>
              </div>

              <div className={`flex items-center gap-3 transition-opacity ${(loadingStage === 'rules' || loadingStage === 'ai') ? 'opacity-100' : 'opacity-30'} ${loadingStage === 'rules' ? `font-bold text-${accentColor}-600` : ''}`}>
                {loadingStage === 'ai' ? <span className="text-green-500">✓</span> : <span className="w-4"></span>}
                {loadingStage === 'rules' && <span className={`w-4 h-4 border-2 border-${accentColor}-600 border-t-transparent animate-spin rounded-full`}></span>}
                <p className="text-sm">{labels.step2}</p>
              </div>

              <div className={`flex items-center gap-3 transition-opacity ${loadingStage === 'ai' ? `opacity-100 font-bold text-${accentColor}-600` : 'opacity-30'}`}>
                {loadingStage === 'ai' ? <span className={`w-4 h-4 border-2 border-${accentColor}-600 border-t-transparent animate-spin rounded-full`}></span> : <span className="w-4"></span>}
                <div>
                  <p className="text-sm">{labels.step3}</p>
                  {loadingStage === 'ai' && <p className="text-[10px] text-gray-500 mt-1 animate-pulse italic">Thinking hard about your {analyzerType === 'terraform' ? 'infrastructure' : 'permissions'}...</p>}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Error State */}
      {error && (
        <div className="card bg-red-50 dark:bg-red-900/30 border-red-200 dark:border-red-800">
          <div className="flex items-start">
            <div className="flex-shrink-0">
              <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800 dark:text-red-300">Error</h3>
              <div className="mt-2 text-sm text-red-700 dark:text-red-400">
                <p>{error}</p>
              </div>
              <div className="mt-4">
                <button
                  onClick={handleReset}
                  className="text-sm font-medium text-red-800 dark:text-red-300 hover:text-red-900 dark:hover:text-red-200"
                >
                  Try again →
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Results */}
      {results && (
        <Results results={results} onReset={handleReset} />
      )}
    </div>
  )
}
