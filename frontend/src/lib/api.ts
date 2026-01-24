/**
 * Utility for making authenticated API calls with the internal access code.
 */
export async function authenticatedFetch(url: string, options: RequestInit = {}) {
    const code = localStorage.getItem('tf_analyzer_code')

    const headers = new Headers(options.headers || {})
    if (code) {
        headers.set('X-Internal-Code', code)
    }

    const response = await fetch(url, {
        ...options,
        headers,
    })

    if (response.status === 401) {
        // Unauthorised - clear the code and reload to trigger the gatekeeper
        localStorage.removeItem('tf_analyzer_code')
        window.location.reload()
        throw new Error('Unauthorised: Invalid access code')
    }

    return response
}
