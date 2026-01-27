/**
 * Utility for making authenticated API calls with the internal access code.
 */
import { getAccessCode, clearAccessCode } from './auth'

export async function authenticatedFetch(url: string, options: RequestInit = {}) {
    const code = getAccessCode()

    const headers = new Headers(options.headers || {})
    if (code) {
        headers.set('X-Internal-Code', code)
    }

    const response = await fetch(url, {
        ...options,
        headers,
    })

    if (response.status === 401) {
        // Unauthorized - clear the code and reload to trigger the gatekeeper
        clearAccessCode()
        window.location.reload()
        throw new Error('Unauthorized: Invalid access code')
    }

    return response
}
