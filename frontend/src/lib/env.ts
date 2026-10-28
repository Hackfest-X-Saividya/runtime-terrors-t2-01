export const API_URL = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/$/, '')

const MOCK_KEY = 'zs-mock'

/**
 * Mock mode: VITE_USE_MOCKS=true, or ?mock=1 in the URL (remembered for the tab).
 * ?mock=0 turns a remembered ?mock=1 off again.
 */
export function isMockMode(): boolean {
  if (import.meta.env.VITE_USE_MOCKS === 'true') return true
  if (typeof window === 'undefined') return false
  const flag = new URLSearchParams(window.location.search).get('mock')
  try {
    if (flag === '1') sessionStorage.setItem(MOCK_KEY, '1')
    if (flag === '0') sessionStorage.removeItem(MOCK_KEY)
    return sessionStorage.getItem(MOCK_KEY) === '1'
  } catch {
    return flag === '1'
  }
}
