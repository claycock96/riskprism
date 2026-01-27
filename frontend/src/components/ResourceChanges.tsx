'use client'

import { ResourceChange, AttributeDiff } from '@/lib/types'
import { extractResourceName } from '@/lib/resourceMapping'

interface ResourceChangesProps {
    diffSkeleton: ResourceChange[]
}

export default function ResourceChanges({ diffSkeleton }: ResourceChangesProps) {
    if (!diffSkeleton || diffSkeleton.length === 0) return null

    const getActionStyles = (action: string) => {
        switch (action) {
            case 'create': return {
                badge: 'action-create',
                border: 'border-emerald-500/30',
                glow: 'shadow-[0_0_20px_-5px_rgba(16,185,129,0.3)]',
            }
            case 'update': return {
                badge: 'action-update',
                border: 'border-blue-500/30',
                glow: 'shadow-[0_0_20px_-5px_rgba(59,130,246,0.3)]',
            }
            case 'delete': return {
                badge: 'action-delete',
                border: 'border-red-500/30',
                glow: 'shadow-[0_0_20px_-5px_rgba(239,68,68,0.3)]',
            }
            case 'replace': return {
                badge: 'action-replace',
                border: 'border-orange-500/30',
                glow: 'shadow-[0_0_20px_-5px_rgba(249,115,22,0.3)]',
            }
            default: return {
                badge: 'bg-slate-500/20 text-slate-300 border border-slate-500/30',
                border: 'border-slate-500/30',
                glow: '',
            }
        }
    }

    const formatValue = (val: any) => {
        if (val === null || val === undefined) return <span className="text-slate-500 italic">null</span>
        if (typeof val === 'object') return JSON.stringify(val)
        if (typeof val === 'boolean') return val.toString()
        return val.toString()
    }

    return (
        <div className="glass-panel p-6 animate-fade-in">
            {/* Header */}
            <div className="flex items-center gap-3 mb-6">
                <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-500 flex items-center justify-center">
                    <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" />
                    </svg>
                </div>
                <h3 className="text-lg font-bold text-white">Resource Changes</h3>
            </div>

            {/* Resources */}
            <div className="space-y-4">
                {diffSkeleton.map((resource, idx) => {
                    const styles = getActionStyles(resource.action)

                    return (
                        <div
                            key={idx}
                            id={`resource-${resource.resource_ref}`}
                            className={`rounded-xl overflow-hidden border ${styles.border} bg-slate-900/50 ${styles.glow} scroll-mt-24 transition-all duration-300 hover:bg-slate-900/80`}
                        >
                            {/* Resource Header */}
                            <div className="flex items-center justify-between px-5 py-4 border-b border-white/5 bg-slate-900/30">
                                <div className="flex items-center gap-3">
                                    <span className={`px-3 py-1 rounded-lg text-xs font-bold uppercase ${styles.badge}`}>
                                        {resource.action}
                                    </span>
                                    <span className="font-mono font-medium text-white">
                                        {resource.resource_address ? extractResourceName(resource.resource_address) : resource.resource_type}
                                    </span>
                                </div>
                                <span className="text-xs text-slate-500 font-mono">{resource.resource_type}</span>
                            </div>

                            {/* Diff Table */}
                            <div className="overflow-x-auto">
                                <table className="w-full">
                                    <thead>
                                        <tr className="border-b border-white/5">
                                            <th className="px-5 py-3 text-left text-xs font-bold text-slate-400 uppercase tracking-wider">Attribute</th>
                                            <th className="px-5 py-3 text-left text-xs font-bold text-slate-400 uppercase tracking-wider">Before</th>
                                            <th className="px-5 py-3 text-left text-xs font-bold text-slate-400 uppercase tracking-wider">After</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-white/5">
                                        {resource.attribute_diffs.length > 0 ? (
                                            resource.attribute_diffs.map((diff, dIdx) => (
                                                <tr key={dIdx} className="hover:bg-white/5 transition-colors">
                                                    <td className="px-5 py-3 text-sm font-mono text-slate-300">
                                                        {diff.path}
                                                    </td>
                                                    <td className="px-5 py-3 text-sm font-mono text-red-400 bg-red-500/5">
                                                        {formatValue(diff.before)}
                                                    </td>
                                                    <td className="px-5 py-3 text-sm font-mono text-emerald-400 bg-emerald-500/5">
                                                        {formatValue(diff.after)}
                                                    </td>
                                                </tr>
                                            ))
                                        ) : (
                                            <tr>
                                                <td colSpan={3} className="px-5 py-6 text-center text-sm text-slate-500 italic">
                                                    No specific attribute changes recorded
                                                </td>
                                            </tr>
                                        )}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )
                })}
            </div>
        </div>
    )
}
