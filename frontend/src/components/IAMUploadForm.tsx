'use client'

import { useState } from 'react'

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
            <div className="flex items-center justify-between mb-6">
                <h2 className="text-2xl font-bold text-slate-800 dark:text-white">
                    🔐 IAM Policy Analyzer
                </h2>
                <button
                    type="button"
                    onClick={loadExample}
                    className="text-sm text-purple-600 hover:text-purple-700 dark:text-purple-400"
                >
                    Load Example
                </button>
            </div>

            <p className="text-slate-600 dark:text-slate-300 mb-6">
                Paste your AWS IAM policy JSON below. We&apos;ll analyze it for security risks
                using 10+ deterministic rules covering privilege escalation, wildcard permissions,
                and missing conditions.
            </p>

            <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                    <label htmlFor="policy" className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                        IAM Policy JSON
                    </label>
                    <textarea
                        id="policy"
                        value={policyText}
                        onChange={(e) => setPolicyText(e.target.value)}
                        placeholder={`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}`}
                        className="w-full h-64 font-mono text-sm p-4 
                       border border-slate-300 dark:border-slate-600 
                       rounded-lg bg-slate-50 dark:bg-slate-800
                       text-slate-800 dark:text-slate-200
                       focus:ring-2 focus:ring-purple-500 focus:border-transparent
                       resize-none"
                        disabled={disabled}
                    />
                </div>

                {error && (
                    <div className="p-4 bg-red-50 dark:bg-red-900/30 border border-red-200 dark:border-red-800 rounded-lg">
                        <p className="text-red-600 dark:text-red-400 text-sm">{error}</p>
                    </div>
                )}

                <button
                    type="submit"
                    disabled={disabled || !policyText.trim()}
                    className={`
            w-full py-4 px-6 rounded-lg font-semibold text-white
            transition-all duration-200
            ${disabled || !policyText.trim()
                            ? 'bg-slate-400 cursor-not-allowed'
                            : 'bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-700 hover:to-indigo-700 shadow-lg hover:shadow-xl'
                        }
          `}
                >
                    {disabled ? 'Analyzing...' : 'Analyze IAM Policy'}
                </button>
            </form>

            <div className="mt-6 p-4 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
                <h3 className="font-semibold text-purple-800 dark:text-purple-300 mb-2">
                    🛡️ Privacy-First Analysis
                </h3>
                <p className="text-sm text-purple-700 dark:text-purple-400">
                    Your ARNs, account IDs, and resource names are hashed before any analysis.
                    The backend and AI never see your raw identifiers.
                </p>
            </div>
        </div>
    )
}
