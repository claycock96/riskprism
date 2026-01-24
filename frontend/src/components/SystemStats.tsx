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
        <footer className="mt-12 py-8 border-t border-gray-100">
            <div className="flex flex-col items-center gap-4">
                <div className="flex flex-wrap items-center justify-center gap-6 text-sm text-gray-500">
                    <Link href="/history" className="flex items-center hover:text-gray-700 transition-colors group">
                        <span className="w-2 h-2 bg-green-500 rounded-full mr-2 group-hover:animate-pulse"></span>
                        System Online
                    </Link>
                    <div>
                        <span className="font-medium text-gray-700">{stats.total_sessions}</span> / {stats.max_size} Reports Stored
                    </div>
                    <div>
                        Uptime: <span className="font-medium text-gray-700">{formatUptime(stats.uptime_seconds)}</span>
                    </div>
                    <div className="text-gray-300">|</div>
                    <div className="text-xs italic text-gray-400">
                        Reports stored for {stats.ttl_hours / 24} days
                    </div>
                </div>
                <div className="text-xs font-medium text-gray-400 flex items-center tracking-wide">
                    Built with <span className="mx-1 text-gray-500 font-semibold">✨ vibe coding</span> by Chris
                </div>
            </div>
        </footer>
    )
}
