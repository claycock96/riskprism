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
  const [error, setError] = useState<string | null>(null)

  const handleAnalyzeTerraform = async (planJson: any) => {
    setLoading(true)
    setError(null)
    setResults(null)

    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

      const response = await authenticatedFetch(`${apiUrl}/analyze/terraform`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ plan_json: planJson }),
      })

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: 'Unknown error' }))
        throw new Error(errorData.detail || `HTTP ${response.status}`)
      }

      const data: AnalyzeResponse = await response.json()

      // Always redirect to results page - session_id is guaranteed by default API behavior
      router.push(`/results/${data.session_id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to analyze plan')
    } finally {
      setLoading(false)
    }
  }

  const handleAnalyzeIAM = async (policy: any) => {
    setLoading(true)
    setError(null)
    setResults(null)

    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

      const response = await authenticatedFetch(`${apiUrl}/analyze/iam`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ policy }),
      })

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ detail: 'Unknown error' }))
        throw new Error(errorData.detail || `HTTP ${response.status}`)
      }

      const data: AnalyzeResponse = await response.json()

      // Always redirect to results page - session_id is guaranteed by default API behavior
      router.push(`/results/${data.session_id}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to analyze IAM policy')
    } finally {
      setLoading(false)
    }
  }

  const handleReset = () => {
    setResults(null)
    setError(null)
  }

  const getLoadingMessage = () => {
    if (analyzerType === 'terraform') {
      return 'Analyzing Terraform plan...'
    }
    return 'Analyzing IAM policy...'
  }

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
        <div className="glass-panel p-12 animate-fade-in">
          <div className="flex flex-col items-center justify-center">
            {/* Futuristic spinner */}
            <div className="relative w-20 h-20 mb-8">
              {/* Outer ring */}
              <div className="absolute inset-0 rounded-full border-2 border-violet-500/30 animate-pulse" />
              {/* Spinning gradient ring */}
              <div className="absolute inset-1 rounded-full border-2 border-transparent border-t-violet-500 border-r-fuchsia-500 animate-spin" />
              {/* Inner glow */}
              <div className="absolute inset-3 rounded-full bg-gradient-to-br from-violet-500/20 to-fuchsia-500/20 animate-pulse" />
              {/* Center icon */}
              <div className="absolute inset-0 flex items-center justify-center">
                <svg className="w-8 h-8 text-violet-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                </svg>
              </div>
            </div>

            <p className="text-lg font-semibold text-white mb-2">{getLoadingMessage()}</p>
            <p className="text-sm text-slate-400">Running security rules and consulting AI</p>

            {/* Progress indicators */}
            <div className="flex items-center gap-2 mt-6">
              <div className="w-2 h-2 rounded-full bg-violet-500 animate-pulse" />
              <div className="w-2 h-2 rounded-full bg-fuchsia-500 animate-pulse" style={{ animationDelay: '0.2s' }} />
              <div className="w-2 h-2 rounded-full bg-cyan-500 animate-pulse" style={{ animationDelay: '0.4s' }} />
            </div>
          </div>
        </div>
      )}

      {/* Error State */}
      {error && (
        <div className="glass-panel p-6 border-red-500/30 animate-fade-in">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-red-500/20 flex items-center justify-center flex-shrink-0">
              <svg className="w-6 h-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <div className="flex-1">
              <h3 className="text-lg font-semibold text-red-300 mb-1">Analysis Failed</h3>
              <p className="text-sm text-slate-400 mb-4">{error}</p>
              <button
                onClick={handleReset}
                className="text-sm font-medium text-red-400 hover:text-red-300 transition-colors flex items-center gap-1"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                </svg>
                Try again
              </button>
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
