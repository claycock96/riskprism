'use client'

import { useState, useEffect } from 'react'
import EntryGate from './EntryGate'

interface GatekeeperProps {
    children: React.ReactNode
}

export default function Gatekeeper({ children }: GatekeeperProps) {
    const [isUnlocked, setIsUnlocked] = useState<boolean | null>(null)

    useEffect(() => {
        // Check if code exists in localStorage on mount
        const savedCode = localStorage.getItem('tf_analyzer_code')
        if (savedCode) {
            setIsUnlocked(true)
        } else {
            setIsUnlocked(false)
        }
    }, [])

    const handleUnlock = (code: string) => {
        // For now, we just store it. The first API call will verify if it's actually correct.
        // If the API returns 401, we'll need to clear it (handled in API calls).
        localStorage.setItem('tf_analyzer_code', code)
        setIsUnlocked(true)
    }

    // Show nothing while checking (prevents flickering)
    if (isUnlocked === null) return null

    if (!isUnlocked) {
        return <EntryGate onUnlock={handleUnlock} />
    }

    return <>{children}</>
}
