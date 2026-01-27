/**
 * Authentication utilities for managing access codes.
 *
 * Security notes:
 * - Uses sessionStorage instead of localStorage to limit exposure window
 * - Code is cleared when browser tab is closed
 * - For production with higher security requirements, consider httpOnly cookies
 */

const AUTH_STORAGE_KEY = 'riskprism_auth_code'

/**
 * Store the validated access code in session storage.
 * Only call this after server-side validation has succeeded.
 */
export function storeAccessCode(code: string): void {
    sessionStorage.setItem(AUTH_STORAGE_KEY, code)
}

/**
 * Retrieve the stored access code, if any.
 */
export function getAccessCode(): string | null {
    return sessionStorage.getItem(AUTH_STORAGE_KEY)
}

/**
 * Clear the stored access code (e.g., on logout or auth failure).
 */
export function clearAccessCode(): void {
    sessionStorage.removeItem(AUTH_STORAGE_KEY)
}

/**
 * Check if an access code is currently stored.
 */
export function hasAccessCode(): boolean {
    return sessionStorage.getItem(AUTH_STORAGE_KEY) !== null
}
