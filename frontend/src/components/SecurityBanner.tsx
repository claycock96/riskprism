'use client'

interface SecurityBannerProps {
    type: 'terraform' | 'iam'
}

export default function SecurityBanner({ type }: SecurityBannerProps) {
    const config = {
        terraform: {
            title: 'Security-First Design',
            items: [
                'Your Terraform plan is analyzed locally first',
                'Resource names are hashed (SHA-256) before AI processing',
                'Only metadata and risk patterns reach the AI',
            ],
        },
        iam: {
            title: 'Privacy-First Analysis',
            items: [
                'Your IAM policy is analyzed locally first',
                'ARNs and Account IDs are hashed before AI processing',
                'Only permission patterns reach the AI—never raw values',
            ],
        },
    }

    const { title, items } = config[type]

    return (
        <div className="mt-6 p-4 rounded-xl bg-emerald-500/5 border border-emerald-500/20">
            <div className="flex items-start gap-3">
                <div className="w-8 h-8 rounded-lg bg-emerald-500/20 flex items-center justify-center flex-shrink-0">
                    <svg className="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                    </svg>
                </div>
                <div>
                    <h4 className="text-sm font-semibold text-emerald-300 mb-2">{title}</h4>
                    <ul className="space-y-1">
                        {items.map((item, idx) => (
                            <li key={idx} className="flex items-start text-xs text-slate-400">
                                <span className="w-1 h-1 rounded-full bg-emerald-500 mt-1.5 mr-2 flex-shrink-0" />
                                {item}
                            </li>
                        ))}
                    </ul>
                </div>
            </div>
        </div>
    )
}
