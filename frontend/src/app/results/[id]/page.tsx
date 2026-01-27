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
  const [copied, setCopied] = useState(false)

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

  const handleCopyLink = async () => {
    try {
      await navigator.clipboard.writeText(window.location.href)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (err) {
      console.error('Failed to copy:', err)
    }
  }

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh]">
        <div className="relative w-16 h-16 mb-6">
          <div className="absolute inset-0 rounded-full border-2 border-violet-500/30 animate-pulse" />
          <div className="absolute inset-1 rounded-full border-2 border-transparent border-t-violet-500 border-r-fuchsia-500 animate-spin" />
          <div className="absolute inset-3 rounded-full bg-gradient-to-br from-violet-500/20 to-fuchsia-500/20 animate-pulse" />
        </div>
        <p className="text-slate-300 font-medium">Loading analysis results...</p>
        <p className="text-sm text-slate-500 mt-2 font-mono">Session: {sessionId.slice(0, 8)}...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="max-w-2xl mx-auto">
        <div className="glass-panel p-8">
          <div className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-xl bg-red-500/20 flex items-center justify-center flex-shrink-0">
              <svg className="w-6 h-6 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
            <div>
              <h1 className="text-xl font-bold text-white mb-1">Session Not Found</h1>
              <p className="text-slate-400">{error}</p>
            </div>
          </div>

          <div className="mt-6 p-4 rounded-xl bg-slate-900/50 border border-white/5">
            <p className="text-sm text-slate-300 mb-2">
              <span className="font-medium text-slate-200">Session ID:</span>{' '}
              <code className="px-2 py-1 rounded bg-slate-800 text-xs font-mono text-slate-400">{sessionId}</code>
            </p>
            <p className="text-sm text-slate-500">
              Sessions are stored for 30 days. After that time, the oldest reports are automatically rotated out.
            </p>
          </div>

          <div className="mt-6 flex gap-3">
            <button
              onClick={() => router.push('/')}
              className="btn-primary flex items-center gap-2"
            >
              <svg className="w-4 h-4 relative z-10" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              <span className="relative z-10">Analyze New Plan</span>
            </button>
            <button
              onClick={() => router.back()}
              className="btn-secondary"
            >
              Go Back
            </button>
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
    <div className="space-y-6">
      {/* Share info banner */}
      <div className="glass-panel p-4 border-violet-500/30">
        <div className="flex items-start gap-3">
          <div className="w-8 h-8 rounded-lg bg-violet-500/20 flex items-center justify-center flex-shrink-0">
            <svg className="w-4 h-4 text-violet-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z" />
            </svg>
          </div>
          <div className="flex-1">
            <p className="text-sm font-medium text-white">Shared Analysis Result</p>
            <p className="text-xs text-slate-400 mt-1">
              This session is stored for 30 days. Share this URL with your team.
            </p>
            <div className="mt-3 flex items-center gap-2">
              <code className="flex-1 text-xs bg-slate-900/50 px-3 py-2 rounded-lg text-slate-400 font-mono truncate border border-white/5">
                {typeof window !== 'undefined' ? window.location.href : ''}
              </code>
              <button
                onClick={handleCopyLink}
                className={`px-3 py-2 rounded-lg text-xs font-medium flex items-center gap-1 transition-all ${copied
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                    : 'bg-violet-500/20 text-violet-300 border border-violet-500/30 hover:bg-violet-500/30'
                  }`}
              >
                {copied ? (
                  <>
                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                    Copied!
                  </>
                ) : (
                  <>
                    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                    </svg>
                    Copy
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Results */}
      <Results results={results} onReset={handleReset} />
    </div>
  )
}
