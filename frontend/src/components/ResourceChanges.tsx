'use client'

import { ResourceChange, AttributeDiff } from '@/lib/types'
import { extractResourceName } from '@/lib/resourceMapping'

interface ResourceChangesProps {
    diffSkeleton: ResourceChange[]
}

export default function ResourceChanges({ diffSkeleton }: ResourceChangesProps) {
    if (!diffSkeleton || diffSkeleton.length === 0) return null

    const getActionColor = (action: string) => {
        switch (action) {
            case 'create': return 'bg-green-100 text-green-800'
            case 'update': return 'bg-blue-100 text-blue-800'
            case 'delete': return 'bg-red-100 text-red-800'
            case 'replace': return 'bg-orange-100 text-orange-800'
            default: return 'bg-gray-100 text-gray-800'
        }
    }

    const formatValue = (val: any) => {
        if (val === null || val === undefined) return <span className="text-gray-400 italic">null</span>
        if (typeof val === 'object') return JSON.stringify(val)
        if (typeof val === 'boolean') return val.toString()
        return val.toString()
    }

    return (
        <div className="card">
            <h3 className="text-lg font-semibold text-gray-900 mb-6">Resource Changes</h3>

            <div className="space-y-6">
                {diffSkeleton.map((resource, idx) => (
                    <div
                        key={idx}
                        id={`resource-${resource.resource_id_hash}`}
                        className="border border-gray-200 rounded-lg overflow-hidden scroll-mt-20"
                    >
                        {/* Header */}
                        <div className="bg-gray-50 px-4 py-3 border-b border-gray-200 flex items-center justify-between">
                            <div className="flex items-center space-x-3">
                                <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${getActionColor(resource.action)}`}>
                                    {resource.action}
                                </span>
                                <span className="text-sm font-mono font-medium text-gray-900">
                                    {resource.resource_address ? extractResourceName(resource.resource_address) : resource.resource_type}
                                </span>
                            </div>
                            <span className="text-xs text-gray-500 font-mono">{resource.resource_type}</span>
                        </div>

                        {/* Diff Table */}
                        <div className="p-0 overflow-x-auto">
                            <table className="min-w-full divide-y divide-gray-200">
                                <thead className="bg-gray-50">
                                    <tr>
                                        <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Attribute</th>
                                        <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Old Value</th>
                                        <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">New Value</th>
                                    </tr>
                                </thead>
                                <tbody className="bg-white divide-y divide-gray-200">
                                    {resource.attribute_diffs.length > 0 ? (
                                        resource.attribute_diffs.map((diff, dIdx) => (
                                            <tr key={dIdx} className="hover:bg-gray-50 transition-colors">
                                                <td className="px-4 py-2 text-xs font-mono text-gray-600 whitespace-nowrap">
                                                    {diff.path}
                                                </td>
                                                <td className="px-4 py-2 text-xs font-mono text-red-600 bg-red-50/30 break-all w-1/3">
                                                    {formatValue(diff.before)}
                                                </td>
                                                <td className="px-4 py-2 text-xs font-mono text-green-600 bg-green-50/30 break-all w-1/3">
                                                    {formatValue(diff.after)}
                                                </td>
                                            </tr>
                                        ))
                                    ) : (
                                        <tr>
                                            <td colSpan={3} className="px-4 py-4 text-center text-sm text-gray-500 italic">
                                                No specific attribute changes recorded
                                            </td>
                                        </tr>
                                    )}
                                </tbody>
                            </table>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    )
}
