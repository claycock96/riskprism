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
        <div className="card">
          <div className="flex flex-col items-center justify-center py-12">
            <div className="inline-block h-12 w-12 animate-spin rounded-full border-4 border-solid border-blue-600 border-r-transparent mb-6"></div>
            <p className="text-lg font-medium text-gray-900 dark:text-white">{getLoadingMessage()}</p>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-2">Running security rules and consulting AI</p>
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
