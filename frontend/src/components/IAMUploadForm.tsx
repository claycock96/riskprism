'use client'

import { useState } from 'react'
import SecurityBanner from './SecurityBanner'

interface IAMUploadFormProps {
    onAnalyze: (policy: any) => void
    disabled?: boolean
}

export default function IAMUploadForm({ onAnalyze, disabled = false }: IAMUploadFormProps) {
    const [method, setMethod] = useState<'paste' | 'upload'>('paste')
    const [policyText, setPolicyText] = useState('')
    const [file, setFile] = useState<File | null>(null)
    const [error, setError] = useState<string | null>(null)

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault()
        setError(null)

        if (method === 'paste') {
            if (!policyText.trim()) {
                setError('Please paste an IAM policy JSON')
                return
            }

            try {
                const policy = JSON.parse(policyText)
                onAnalyze(policy)
            } catch (err) {
                setError('Invalid JSON format. Please check your policy syntax.')
            }
        } else if (file) {
            const reader = new FileReader()
            reader.onload = (event) => {
                try {
                    const parsed = JSON.parse(event.target?.result as string)
                    onAnalyze(parsed)
                } catch (err) {
                    setError('Invalid JSON file. Please check your file.')
                }
            }
            reader.readAsText(file)
        }
    }

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const selectedFile = e.target.files?.[0]
        if (selectedFile) {
            if (selectedFile.size > 10 * 1024 * 1024) { // 10MB limit
                setError('File size exceeds 10MB limit')
                return
            }
            setFile(selectedFile)
            setMethod('upload')
            setError(null)
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
        setMethod('paste')
        setPolicyText(JSON.stringify(examplePolicy, null, 2))
        setError(null)
    }

    const isValid = method === 'paste' ? policyText.trim().length > 0 : file !== null

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
                {/* Method Selection */}
                <div className="flex space-x-4 border-b border-gray-200 dark:border-gray-700">
                    <button
                        type="button"
                        onClick={() => setMethod('paste')}
                        className={`pb-2 px-1 font-medium text-sm border-b-2 transition-colors ${method === 'paste'
                            ? 'border-blue-600 text-blue-600 dark:text-blue-400'
                            : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'
                            }`}
                    >
                        Paste JSON
                    </button>
                    <button
                        type="button"
                        onClick={() => setMethod('upload')}
                        className={`pb-2 px-1 font-medium text-sm border-b-2 transition-colors ${method === 'upload'
                            ? 'border-blue-600 text-blue-600 dark:text-blue-400'
                            : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'
                            }`}
                    >
                        Upload File
                    </button>
                </div>

                {/* Input Area */}
                {method === 'paste' ? (
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
                ) : (
                    <div>
                        <label htmlFor="file-upload" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                            Select File
                        </label>
                        <div className="flex items-center justify-center w-full">
                            <label
                                htmlFor="file-upload"
                                className="flex flex-col items-center justify-center w-full h-32 border-2 border-gray-300 dark:border-gray-600 border-dashed rounded-lg cursor-pointer bg-gray-50 dark:bg-gray-900 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                            >
                                <div className="flex flex-col items-center justify-center pt-5 pb-6">
                                    <svg
                                        className="w-8 h-8 mb-3 text-gray-400"
                                        fill="none"
                                        stroke="currentColor"
                                        viewBox="0 0 24 24"
                                    >
                                        <path
                                            strokeLinecap="round"
                                            strokeLinejoin="round"
                                            strokeWidth={2}
                                            d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
                                        />
                                    </svg>
                                    {file ? (
                                        <p className="text-sm text-gray-600 dark:text-gray-400">
                                            <span className="font-semibold">{file.name}</span>
                                        </p>
                                    ) : (
                                        <>
                                            <p className="mb-2 text-sm text-gray-500 dark:text-gray-400">
                                                <span className="font-semibold">Click to upload</span> or drag and drop
                                            </p>
                                            <p className="text-xs text-gray-500 dark:text-gray-400">JSON policy file (max 10MB)</p>
                                        </>
                                    )}
                                </div>
                                <input
                                    id="file-upload"
                                    type="file"
                                    accept=".json,application/json"
                                    onChange={handleFileChange}
                                    className="hidden"
                                    disabled={disabled}
                                />
                            </label>
                        </div>
                    </div>
                )}

                {/* Validation Error */}
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
                    disabled={disabled || !isValid}
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
