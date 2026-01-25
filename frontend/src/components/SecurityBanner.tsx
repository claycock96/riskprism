'use client'

interface SecurityBannerProps {
    type: 'terraform' | 'iam'
}

export default function SecurityBanner({ type }: SecurityBannerProps) {
    const isTerraform = type === 'terraform'

    return (
        <div className="mt-6 rounded-md bg-blue-50 dark:bg-blue-900/20 p-4 border border-blue-200 dark:border-blue-800">
            <div className="flex">
                <div className="flex-shrink-0">
                    <svg className="h-5 w-5 text-blue-400" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                    </svg>
                </div>
                <div className="ml-3 flex-1">
                    <h4 className="text-sm font-semibold text-blue-800 dark:text-blue-300 mb-1">
                        {isTerraform ? 'Security-First Design' : 'Privacy-First Analysis'}
                    </h4>
                    <p className="text-sm text-blue-700 dark:text-blue-400 mb-2">
                        Your {isTerraform ? 'Terraform plan' : 'IAM policy'} data is processed with security as the top priority.
                    </p>
                    <ul className="text-xs text-blue-600 dark:text-blue-400 space-y-1 list-disc list-inside">
                        <li>
                            <strong>{isTerraform ? 'Resource names' : 'ARNs and Account IDs'} are hashed</strong> before being sent to AI
                        </li>
                        <li>
                            <strong>Only metadata is shared</strong>: {isTerraform ? 'resource types, actions, and attribute paths' : 'actions, resources, and conditions structure'}
                        </li>
                        <li>
                            <strong>Sensitive values are stripped</strong>: {isTerraform ? 'passwords, tokens, keys, secrets' : 'credentials and secrets'} never leave your browser
                        </li>
                        <li>
                            <strong>Frontend shows real names</strong> by mapping hashes back to your original {isTerraform ? 'resource names' : 'identifiers'}
                        </li>
                    </ul>
                </div>
            </div>
        </div>
    )
}
