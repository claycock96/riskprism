'use client'

import { useState, useEffect } from 'react'
import Link from 'next/link'
import { SessionStats } from '@/lib/types'

import { authenticatedFetch } from '@/lib/api'

export default function SystemStats() {
    const [stats, setStats] = useState<SessionStats | null>(null)

    useEffect(() => {
        const fetchStats = async () => {
            try {
                const response = await authenticatedFetch(`${process.env.NEXT_PUBLIC_API_URL}/sessions/stats`)
                if (response.ok) {
                    const data = await response.json()
                    setStats(data)
                }
            } catch (error) {
                console.error('Failed to fetch system stats:', error)
            }
        }

        fetchStats()
        const interval = setInterval(fetchStats, 30000) // Update every 30 seconds

        return () => clearInterval(interval)
    }, [])

    const formatUptime = (seconds: number) => {
        if (seconds < 60) return `${seconds}s`
        const minutes = Math.floor(seconds / 60)
        const remainingSeconds = seconds % 60
        if (minutes < 60) return `${minutes}m ${remainingSeconds}s`
        const hours = Math.floor(minutes / 60)
        const remainingMinutes = minutes % 60
        return `${hours}h ${remainingMinutes}m`
    }

    if (!stats) return null

    return (
        <footer className="mt-12 py-6 border-t border-white/10">
            <div className="flex flex-col items-center gap-4">
                <div className="flex flex-wrap items-center justify-center gap-6 text-sm text-slate-500">
                    <Link href="/history" className="flex items-center hover:text-slate-300 transition-colors group">
                        <span className="relative flex h-2 w-2 mr-2">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                        </span>
                        System Online
                    </Link>
                    <div className="h-4 w-px bg-white/10" />
                    <div>
                        <span className="font-medium text-slate-300">{stats.total_sessions}</span>
                        <span className="text-slate-600"> / {stats.max_size} Reports</span>
                    </div>
                    <div className="h-4 w-px bg-white/10" />
                    <div>
                        Uptime: <span className="font-medium text-slate-300">{formatUptime(stats.uptime_seconds)}</span>
                    </div>
                    <div className="h-4 w-px bg-white/10" />
                    <div className="text-xs text-slate-600">
                        TTL: {stats.ttl_hours / 24}d
                    </div>
                </div>
                <div className="text-xs text-slate-600 flex items-center gap-1">
                    Built with AI<span className="text-violet-400">✨</span> by Chris
                </div>
            </div>
        </footer>
    )
}
