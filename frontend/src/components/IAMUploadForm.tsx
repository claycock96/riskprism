'use client'

import { useState, useRef, useEffect } from 'react'
import SecurityBanner from './SecurityBanner'
import { authenticatedFetch } from '../lib/api'

interface IAMUploadFormProps {
    onAnalyze: (policy: any) => void
    disabled?: boolean
}

export default function IAMUploadForm({ onAnalyze, disabled }: IAMUploadFormProps) {
    const [method, setMethod] = useState<'paste' | 'upload'>('paste')
    const [jsonText, setJsonText] = useState('')
    const [file, setFile] = useState<File | null>(null)
    const [validationError, setValidationError] = useState<string | null>(null)
    const [isDragging, setIsDragging] = useState(false)
    const [isGenerating, setIsGenerating] = useState(false)
    const [showExampleMenu, setShowExampleMenu] = useState(false)
    const menuRef = useRef<HTMLDivElement>(null)

    // Close menu when clicking outside
    useEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
                setShowExampleMenu(false)
            }
        }
        document.addEventListener('mousedown', handleClickOutside)
        return () => document.removeEventListener('mousedown', handleClickOutside)
    }, [])

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault()
        setValidationError(null)

        if (method === 'paste') {
            try {
                const parsed = JSON.parse(jsonText)
                onAnalyze(parsed)
            } catch (err) {
                setValidationError('Invalid JSON format. Please check your input.')
            }
        } else if (file) {
            const reader = new FileReader()
            reader.onload = (event) => {
                try {
                    const parsed = JSON.parse(event.target?.result as string)
                    onAnalyze(parsed)
                } catch (err) {
                    setValidationError('Invalid JSON file. Please check your file.')
                }
            }
            reader.readAsText(file)
        }
    }

    const loadExample = async () => {
        setIsGenerating(true)
        setValidationError(null)

        try {
            const response = await authenticatedFetch(`${process.env.NEXT_PUBLIC_API_URL}/generate/iam`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
            })

            if (response.ok) {
                const data = await response.json()
                setMethod('paste')
                setJsonText(JSON.stringify(data.example, null, 2))
            } else {
                // Fall back to static example on error
                loadStaticExample()
            }
        } catch (error) {
            console.error('Failed to generate example:', error)
            // Fall back to static example
            loadStaticExample()
        } finally {
            setIsGenerating(false)
        }
    }

    const loadStaticExample = () => {
        const examplePolicy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                },
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject"
                    ],
                    "Resource": "arn:aws:s3:::my-bucket/*"
                }
            ]
        }
        setMethod('paste')
        setJsonText(JSON.stringify(examplePolicy, null, 2))
        setValidationError(null)
    }

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const selectedFile = e.target.files?.[0]
        if (selectedFile) {
            if (selectedFile.size > 10 * 1024 * 1024) {
                setValidationError('File size exceeds 10MB limit')
                return
            }
            setFile(selectedFile)
            setMethod('upload')
            setValidationError(null)
        }
    }

    const handleDrop = (e: React.DragEvent) => {
        e.preventDefault()
        setIsDragging(false)
        const droppedFile = e.dataTransfer.files?.[0]
        if (droppedFile) {
            if (droppedFile.size > 10 * 1024 * 1024) {
                setValidationError('File size exceeds 10MB limit')
                return
            }
            setFile(droppedFile)
            setMethod('upload')
            setValidationError(null)
        }
    }

    const isValid = method === 'paste' ? jsonText.trim().length > 0 : file !== null

    return (
        <div className="glass-panel p-6 animate-fade-in">
            {/* Header */}
            <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-500 flex items-center justify-center shadow-glow-cyan">
                        <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                        </svg>
                    </div>
                    <div>
                        <h2 className="text-xl font-bold text-white">IAM Policy Analyzer</h2>
                        <p className="text-sm text-slate-400">Analyze AWS IAM policies for security risks</p>
                    </div>
                </div>
                <div className="relative" ref={menuRef}>
                    <button
                        type="button"
                        onClick={() => setShowExampleMenu(!showExampleMenu)}
                        disabled={isGenerating}
                        className="text-sm font-medium text-cyan-400 hover:text-cyan-300 transition-colors flex items-center gap-1 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        {isGenerating ? (
                            <>
                                <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                </svg>
                                Generating...
                            </>
                        ) : (
                            <>
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                                </svg>
                                Load Example
                                <svg className="w-3 h-3 ml-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                </svg>
                            </>
                        )}
                    </button>

                    {/* Dropdown Menu */}
                    {showExampleMenu && (
                        <div className="absolute right-0 mt-2 w-64 rounded-xl bg-slate-800 border border-white/10 shadow-xl z-50 overflow-hidden">
                            <button
                                type="button"
                                onClick={() => {
                                    loadStaticExample()
                                    setShowExampleMenu(false)
                                }}
                                className="w-full px-4 py-3 text-left hover:bg-white/5 transition-colors border-b border-white/10"
                            >
                                <div className="flex items-center gap-2">
                                    <svg className="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                                    </svg>
                                    <span className="text-sm font-medium text-white">Basic Example</span>
                                </div>
                                <p className="text-xs text-slate-400 mt-1 ml-6">Static sample • Instant • Free</p>
                            </button>
                            <button
                                type="button"
                                onClick={() => {
                                    loadExample()
                                    setShowExampleMenu(false)
                                }}
                                className="w-full px-4 py-3 text-left hover:bg-white/5 transition-colors"
                            >
                                <div className="flex items-center gap-2">
                                    <svg className="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z" />
                                    </svg>
                                    <span className="text-sm font-medium text-white">AI Generated Example</span>
                                </div>
                                <p className="text-xs text-slate-400 mt-1 ml-6">Unique each time • <span className="text-amber-400">Uses AI credits</span></p>
                            </button>
                        </div>
                    )}
                </div>
            </div>

            {/* Info hint */}
            <div className="mb-6 p-3 rounded-xl bg-cyan-500/10 border border-cyan-500/20">
                <p className="text-sm text-slate-300">
                    Paste an IAM policy JSON document with <code className="px-2 py-1 rounded bg-slate-900 text-cyan-300 font-mono text-xs">Version</code> and <code className="px-2 py-1 rounded bg-slate-900 text-cyan-300 font-mono text-xs">Statement</code> fields.
                </p>
            </div>

            <form onSubmit={handleSubmit} className="space-y-6">
                {/* Method Selection Tabs */}
                <div className="flex border-b border-white/10">
                    <button
                        type="button"
                        onClick={() => setMethod('paste')}
                        className={`relative pb-3 px-4 font-medium text-sm transition-colors ${method === 'paste'
                            ? 'text-white'
                            : 'text-slate-400 hover:text-slate-200'
                            }`}
                    >
                        <span className="flex items-center gap-2">
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                            </svg>
                            Paste JSON
                        </span>
                        {method === 'paste' && (
                            <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-cyan-500 to-blue-500" />
                        )}
                    </button>
                    <button
                        type="button"
                        onClick={() => setMethod('upload')}
                        className={`relative pb-3 px-4 font-medium text-sm transition-colors ${method === 'upload'
                            ? 'text-white'
                            : 'text-slate-400 hover:text-slate-200'
                            }`}
                    >
                        <span className="flex items-center gap-2">
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                            </svg>
                            Upload File
                        </span>
                        {method === 'upload' && (
                            <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-gradient-to-r from-cyan-500 to-blue-500" />
                        )}
                    </button>
                </div>

                {/* Input Area */}
                {method === 'paste' ? (
                    <div>
                        <label htmlFor="iam-json-input" className="block text-sm font-medium text-slate-300 mb-2">
                            IAM Policy JSON
                        </label>
                        <textarea
                            id="iam-json-input"
                            rows={12}
                            value={jsonText}
                            onChange={(e) => setJsonText(e.target.value)}
                            placeholder='{"Version": "2012-10-17", "Statement": [...]}'
                            className="input-glass font-mono text-sm resize-none"
                            disabled={disabled}
                        />
                    </div>
                ) : (
                    <div>
                        <label htmlFor="iam-file-upload" className="block text-sm font-medium text-slate-300 mb-2">
                            Select File
                        </label>
                        <div
                            onDragOver={(e) => { e.preventDefault(); setIsDragging(true) }}
                            onDragLeave={() => setIsDragging(false)}
                            onDrop={handleDrop}
                            className={`relative flex flex-col items-center justify-center w-full h-40 border-2 border-dashed rounded-xl cursor-pointer transition-all duration-300 ${isDragging
                                ? 'border-cyan-500 bg-cyan-500/10'
                                : file
                                    ? 'border-emerald-500/50 bg-emerald-500/5'
                                    : 'border-white/20 bg-white/5 hover:border-cyan-500/50 hover:bg-cyan-500/5'
                                }`}
                        >
                            <input
                                id="iam-file-upload"
                                type="file"
                                accept=".json,application/json"
                                onChange={handleFileChange}
                                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                                disabled={disabled}
                            />
                            <div className="flex flex-col items-center justify-center">
                                {file ? (
                                    <>
                                        <div className="w-12 h-12 rounded-xl bg-emerald-500/20 flex items-center justify-center mb-3">
                                            <svg className="w-6 h-6 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                            </svg>
                                        </div>
                                        <p className="text-sm text-white font-medium">{file.name}</p>
                                        <p className="text-xs text-slate-400 mt-1">Click or drop to replace</p>
                                    </>
                                ) : (
                                    <>
                                        <div className={`w-12 h-12 rounded-xl flex items-center justify-center mb-3 transition-colors ${isDragging ? 'bg-cyan-500/20' : 'bg-white/10'
                                            }`}>
                                            <svg className={`w-6 h-6 transition-colors ${isDragging ? 'text-cyan-400' : 'text-slate-400'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                                            </svg>
                                        </div>
                                        <p className="text-sm text-slate-300">
                                            <span className="font-medium text-white">Click to upload</span> or drag and drop
                                        </p>
                                        <p className="text-xs text-slate-500 mt-1">JSON file (max 10MB)</p>
                                    </>
                                )}
                            </div>
                        </div>
                    </div>
                )}

                {/* Validation Error */}
                {validationError && (
                    <div className="rounded-xl p-4 bg-red-500/10 border border-red-500/30 animate-fade-in">
                        <div className="flex items-center gap-3">
                            <div className="w-8 h-8 rounded-lg bg-red-500/20 flex items-center justify-center flex-shrink-0">
                                <svg className="w-4 h-4 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                                </svg>
                            </div>
                            <p className="text-sm text-red-300">{validationError}</p>
                        </div>
                    </div>
                )}

                {/* Submit Button */}
                <button
                    type="submit"
                    disabled={!isValid || disabled}
                    className={`w-full py-4 rounded-xl font-semibold text-base transition-all duration-300 flex items-center justify-center gap-2 ${isValid && !disabled
                        ? 'bg-gradient-to-r from-cyan-500 to-blue-500 text-white shadow-glow-cyan hover:shadow-[0_0_30px_-5px_rgba(34,211,238,0.7)] hover:-translate-y-0.5'
                        : 'bg-slate-800 text-slate-500 cursor-not-allowed'
                        }`}
                >
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                    </svg>
                    Analyze Policy
                </button>
            </form>

            {/* Security Banner */}
            <SecurityBanner type="iam" />
        </div>
    )
}
