'use client'

import { useEffect, useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { authenticatedFetch } from '@/lib/api'
import Results from '@/components/Results'
import { AnalyzeResponse } from '@/lib/types'

export default function ResultsPage() {
  const params = useParams()
  const router = useRouter()
  const sessionId = params.id as string

  const [results, setResults] = useState<AnalyzeResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function fetchResults() {
      try {
        const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'
        const response = await authenticatedFetch(`${apiUrl}/results/${sessionId}`)

        if (!response.ok) {
          if (response.status === 404) {
            setError('Session not found or expired. Sessions are stored for 30 days.')
          } else {
            setError(`Failed to load results: ${response.statusText}`)
          }
          setLoading(false)
          return
        }

        const data = await response.json()
        setResults(data)
        setLoading(false)
      } catch (err) {
        console.error('Error fetching results:', err)
        setError('Failed to connect to the API server')
        setLoading(false)
      }
    }

    if (sessionId) {
      fetchResults()
    }
  }, [sessionId])

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50">
        <div className="container mx-auto px-4 py-8">
          <div className="flex flex-col items-center justify-center min-h-[60vh]">
            <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-blue-600 mb-4"></div>
            <p className="text-gray-600">Loading analysis results...</p>
            <p className="text-sm text-gray-500 mt-2">Session: {sessionId}</p>
          </div>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="min-h-screen bg-gray-50">
        <div className="container mx-auto px-4 py-8">
          <div className="max-w-2xl mx-auto">
            <div className="bg-white rounded-lg shadow p-8">
              <div className="flex items-center mb-4">
                <svg className="w-12 h-12 text-red-500 mr-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <div>
                  <h1 className="text-2xl font-bold text-gray-900">Session Not Found</h1>
                  <p className="text-gray-600 mt-1">{error}</p>
                </div>
              </div>

              <div className="mt-6 bg-gray-50 rounded p-4">
                <p className="text-sm text-gray-700 mb-2">
                  <strong>Session ID:</strong> <code className="bg-gray-200 px-2 py-1 rounded">{sessionId}</code>
                </p>
                <p className="text-sm text-gray-600">
                  Sessions are stored for 30 days. After that time, the oldest reports are automatically rotated out.
                </p>
              </div>

              <div className="mt-6 flex gap-4">
                <button
                  onClick={() => router.push('/')}
                  className="px-6 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
                >
                  Analyze New Plan
                </button>
                <button
                  onClick={() => router.back()}
                  className="px-6 py-2 bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300 transition-colors"
                >
                  Go Back
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    )
  }

  if (!results) {
    return null
  }

  const handleReset = () => {
    router.push('/')
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="container mx-auto px-4 py-8">
        {/* Header with share info */}
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
          <div className="flex items-start">
            <svg className="w-5 h-5 text-blue-600 mr-3 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <div>
              <p className="text-sm font-medium text-blue-900">
                Shared Analysis Result
              </p>
              <p className="text-xs text-blue-700 mt-1">
                This session is stored for 30 days. You can share this URL with your team.
              </p>
              <div className="mt-2 flex items-center gap-2">
                <code className="text-xs bg-blue-100 px-2 py-1 rounded text-blue-800">
                  {typeof window !== 'undefined' ? window.location.href : ''}
                </code>
                <button
                  onClick={() => {
                    if (typeof window !== 'undefined') {
                      navigator.clipboard.writeText(window.location.href)
                    }
                  }}
                  className="text-xs text-blue-600 hover:text-blue-800 font-medium"
                >
                  Copy Link
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Results */}
        <Results results={results} onReset={handleReset} />
      </div>
    </div>
  )
}
