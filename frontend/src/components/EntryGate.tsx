'use client'

import { useState } from 'react'

interface EntryGateProps {
    onUnlock: (code: string) => void
}

export default function EntryGate({ onUnlock }: EntryGateProps) {
    const [code, setCode] = useState('')
    const [error, setError] = useState(false)
    const [isLoading, setIsLoading] = useState(false)

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault()
        if (!code.trim()) return

        setIsLoading(true)
        setError(false)

        try {
            const apiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'
            const response = await fetch(`${apiUrl}/auth/validate`, {
                headers: {
                    'X-Internal-Code': code.trim(),
                },
            })

            if (response.ok) {
                onUnlock(code.trim())
            } else {
                setError(true)
            }
        } catch (err) {
            console.error('Auth validation failed:', err)
            setError(true)
        } finally {
            setIsLoading(false)
        }
    }

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            {/* Background with blur and gradient */}
            <div className="absolute inset-0 bg-slate-950/95 backdrop-blur-xl" />

            {/* Ambient glow effects */}
            <div className="absolute top-1/3 left-1/4 w-96 h-96 bg-violet-600/20 rounded-full blur-3xl" />
            <div className="absolute bottom-1/3 right-1/4 w-80 h-80 bg-fuchsia-600/20 rounded-full blur-3xl" />

            {/* Card */}
            <div className="relative w-full max-w-md glass-panel overflow-hidden animate-scale-in">
                {/* Header */}
                <div className="px-8 py-10 text-center bg-gradient-to-br from-violet-600/20 to-fuchsia-600/20 border-b border-white/10">
                    <div className="w-16 h-16 mx-auto mb-6 rounded-2xl bg-gradient-to-br from-violet-500 to-fuchsia-500 flex items-center justify-center shadow-glow-lg">
                        <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                        </svg>
                    </div>
                    <h2 className="text-2xl font-bold text-white">Team Access Required</h2>
                    <p className="text-slate-400 mt-2">
                        Enter the internal access code to use RiskPrism.
                    </p>
                </div>

                {/* Form */}
                <form onSubmit={handleSubmit} className="p-8">
                    <div className="space-y-6">
                        <div>
                            <label htmlFor="access-code" className="block text-sm font-medium text-slate-300 mb-2">
                                Access Code
                            </label>
                            <input
                                id="access-code"
                                type="password"
                                required
                                value={code}
                                onChange={(e) => {
                                    setCode(e.target.value)
                                    setError(false)
                                }}
                                className={`input-glass ${error ? 'border-red-500/50 ring-2 ring-red-500/20' : ''}`}
                                placeholder="••••••••"
                                autoFocus
                            />
                            {error && (
                                <div className="mt-3 flex items-center gap-2 text-sm text-red-400 animate-fade-in">
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                    </svg>
                                    Invalid access code. Please try again.
                                </div>
                            )}
                        </div>

                        <button
                            type="submit"
                            disabled={isLoading}
                            className={`w-full btn-primary py-4 flex items-center justify-center gap-2 ${isLoading ? 'opacity-70 cursor-wait' : ''}`}
                        >
                            {isLoading ? (
                                <>
                                    <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                                    <span className="relative z-10">Unlocking...</span>
                                </>
                            ) : (
                                <>
                                    <svg className="w-5 h-5 relative z-10" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z" />
                                    </svg>
                                    <span className="relative z-10">Unlock Application</span>
                                </>
                            )}
                        </button>
                    </div>

                    <div className="mt-8 text-center text-xs text-slate-500">
                        Internal Use Only • Unauthorized access is prohibited
                    </div>
                </form>
            </div>
        </div>
    )
}
