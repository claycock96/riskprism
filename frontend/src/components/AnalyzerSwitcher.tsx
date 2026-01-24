'use client'

import { useState } from 'react'

export type AnalyzerType = 'terraform' | 'iam'

interface AnalyzerSwitcherProps {
    activeAnalyzer: AnalyzerType
    onSwitch: (analyzer: AnalyzerType) => void
    disabled?: boolean
}

export default function AnalyzerSwitcher({
    activeAnalyzer,
    onSwitch,
    disabled = false
}: AnalyzerSwitcherProps) {
    return (
        <div className="flex justify-center mb-8">
            <div className="inline-flex rounded-lg bg-slate-100 dark:bg-slate-800 p-1">
                <button
                    onClick={() => onSwitch('terraform')}
                    disabled={disabled}
                    className={`
            px-6 py-3 rounded-lg font-medium text-sm transition-all duration-200
            ${activeAnalyzer === 'terraform'
                            ? 'bg-white dark:bg-slate-700 text-blue-600 shadow-md'
                            : 'text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
                        }
            ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
          `}
                >
                    <span className="flex items-center gap-2">
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                        </svg>
                        Terraform Plan
                    </span>
                </button>

                <button
                    onClick={() => onSwitch('iam')}
                    disabled={disabled}
                    className={`
            px-6 py-3 rounded-lg font-medium text-sm transition-all duration-200
            ${activeAnalyzer === 'iam'
                            ? 'bg-white dark:bg-slate-700 text-blue-600 shadow-md'
                            : 'text-slate-600 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200'
                        }
            ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
          `}
                >
                    <span className="flex items-center gap-2">
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                        </svg>
                        IAM Policy
                    </span>
                </button>
            </div>
        </div>
    )
}
