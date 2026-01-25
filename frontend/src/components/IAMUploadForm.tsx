'use client'

import { useState } from 'react'
import SecurityBanner from './SecurityBanner'

interface IAMUploadFormProps {
    onAnalyze: (policy: any) => void
    disabled?: boolean
}

export default function IAMUploadForm({ onAnalyze, disabled = false }: IAMUploadFormProps) {
    const [policyText, setPolicyText] = useState('')
    const [error, setError] = useState<string | null>(null)

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault()
        setError(null)

        if (!policyText.trim()) {
            setError('Please paste an IAM policy JSON')
            return
        }

        try {
            const policy = JSON.parse(policyText)

            // Basic validation
            if (!policy.Statement && !policy.policy?.Statement && !policy.Policy?.Statement) {
                setError('Invalid IAM policy: missing Statement field')
                return
            }

            onAnalyze(policy)
        } catch (err) {
            setError('Invalid JSON format. Please check your policy syntax.')
        }
    }

    const loadExample = () => {
        const examplePolicy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AdminAccess",
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }
        setPolicyText(JSON.stringify(examplePolicy, null, 2))
    }

    return (
        <div className="card">
            <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                    RiskPrism: IAM
                </h2>
                <button
                    type="button"
                    onClick={loadExample}
                    className="text-sm font-medium text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300"
                >
                    Load Example
                </button>
            </div>

            <p className="text-sm text-gray-600 dark:text-gray-400 mb-6">
                Analyze an AWS IAM policy JSON for security risks and get AI-powered explanations.
                Paste your policy below or click &quot;Load Example&quot; to try it out.
            </p>

            <form onSubmit={handleSubmit} className="space-y-6">
                <div>
                    <label htmlFor="policy" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        IAM Policy JSON
                    </label>
                    <textarea
                        id="policy"
                        rows={12}
                        value={policyText}
                        onChange={(e) => setPolicyText(e.target.value)}
                        placeholder='Paste your IAM policy JSON here...'
                        className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 font-mono text-sm bg-white dark:bg-gray-900 text-gray-900 dark:text-gray-100"
                        disabled={disabled}
                    />
                </div>

                {error && (
                    <div className="rounded-md bg-red-50 dark:bg-red-900/20 p-4 border border-red-200 dark:border-red-800">
                        <div className="flex">
                            <div className="ml-3">
                                <p className="text-sm text-red-800 dark:text-red-300">{error}</p>
                            </div>
                        </div>
                    </div>
                )}

                <button
                    type="submit"
                    disabled={disabled || !policyText.trim()}
                    className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:bg-gray-300 disabled:cursor-not-allowed transition-colors"
                >
                    {disabled ? 'Analyzing...' : 'Analyze Policy'}
                </button>
            </form>

            {/* Security Banner */}
            <SecurityBanner type="iam" />
        </div>
    )
}
