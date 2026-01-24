'use client'

import { useState, useEffect } from 'react'

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
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-gray-900 bg-opacity-95 backdrop-blur-sm p-4">
            <div className="max-w-md w-full bg-white rounded-xl shadow-2xl overflow-hidden animate-in fade-in zoom-in duration-300">
                <div className="bg-blue-600 px-6 py-8 text-white text-center">
                    <div className="text-4xl mb-4">🔐</div>
                    <h2 className="text-2xl font-bold">Team Access Required</h2>
                    <p className="text-blue-100 mt-2 opacity-90">
                        Please enter the internal access code to use the Terraform Plan Analyzer.
                    </p>
                </div>

                <form onSubmit={handleSubmit} className="p-8">
                    <div className="space-y-4">
                        <div>
                            <label htmlFor="access-code" className="block text-sm font-medium text-gray-700 mb-2">
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
                                className={`block w-full px-4 py-3 rounded-lg border ${error ? 'border-red-500 ring-red-100' : 'border-gray-300 focus:ring-blue-100 focus:border-blue-500'
                                    } shadow-sm transition-all focus:ring-4 outline-none`}
                                placeholder="••••••••"
                                autoFocus
                            />
                            {error && (
                                <p className="mt-2 text-sm text-red-600 flex items-center">
                                    <span className="mr-1">⚠️</span> Invalid access code. Please try again.
                                </p>
                            )}
                        </div>

                        <button
                            type="submit"
                            disabled={isLoading}
                            className={`w-full ${isLoading ? 'bg-blue-400' : 'bg-blue-600 hover:bg-blue-700'
                                } text-white font-bold py-3 px-4 rounded-lg transition-colors shadow-lg active:scale-[0.98] flex items-center justify-center`}
                        >
                            {isLoading ? (
                                <>
                                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                                    Unlocking...
                                </>
                            ) : (
                                'Unlock Application'
                            )}
                        </button>
                    </div>

                    <div className="mt-6 text-center text-xs text-gray-400">
                        Internal Use Only • Unauthorized access is prohibited
                    </div>
                </form>
            </div>
        </div>
    )
}
