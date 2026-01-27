'use client'

import { useState, useEffect } from 'react'
import EntryGate from './EntryGate'
import { storeAccessCode, hasAccessCode } from '@/lib/auth'

interface GatekeeperProps {
    children: React.ReactNode
}

export default function Gatekeeper({ children }: GatekeeperProps) {
    const [isUnlocked, setIsUnlocked] = useState<boolean | null>(null)

    useEffect(() => {
        // Check if code exists in sessionStorage on mount
        // Using sessionStorage instead of localStorage for better security
        // (code is cleared when browser tab is closed)
        setIsUnlocked(hasAccessCode())
    }, [])

    const handleUnlock = (code: string) => {
        // Code has already been validated server-side by EntryGate
        // Now safe to store in session storage
        storeAccessCode(code)
        setIsUnlocked(true)
    }

    // Show nothing while checking (prevents flickering)
    if (isUnlocked === null) return null

    if (!isUnlocked) {
        return <EntryGate onUnlock={handleUnlock} />
    }

    return <>{children}</>
}
