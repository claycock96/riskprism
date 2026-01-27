'use client'

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
            <div className="relative glass-panel p-1.5 flex gap-1">
                {/* Sliding indicator */}
                <div
                    className={`absolute top-1.5 h-[calc(100%-12px)] w-[calc(50%-4px)] rounded-xl bg-gradient-to-r from-violet-600 to-fuchsia-600 shadow-glow-md transition-all duration-300 ease-out ${activeAnalyzer === 'iam' ? 'translate-x-[calc(100%+4px)]' : 'translate-x-0'
                        }`}
                />

                {/* Terraform button */}
                <button
                    onClick={() => onSwitch('terraform')}
                    disabled={disabled}
                    className={`
                        relative z-10 px-6 py-3 rounded-xl font-medium text-sm transition-all duration-300 flex items-center gap-2
                        ${activeAnalyzer === 'terraform'
                            ? 'text-white'
                            : 'text-slate-400 hover:text-white'
                        }
                        ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
                    `}
                >
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                            d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                    Terraform Plan
                </button>

                {/* IAM button */}
                <button
                    onClick={() => onSwitch('iam')}
                    disabled={disabled}
                    className={`
                        relative z-10 px-6 py-3 rounded-xl font-medium text-sm transition-all duration-300 flex items-center gap-2
                        ${activeAnalyzer === 'iam'
                            ? 'text-white'
                            : 'text-slate-400 hover:text-white'
                        }
                        ${disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
                    `}
                >
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                            d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                    </svg>
                    IAM Policy
                </button>
            </div>
        </div>
    )
}
