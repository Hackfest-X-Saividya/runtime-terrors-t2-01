import { getResponse } from 'msw'
import { setupWorker } from 'msw/browser'
import type { MockTransport } from '@/lib/runtime'
import { setScanSocketFactory } from '@/lib/socket'
import { resetDb } from './db'
import { handlers } from './handlers'
import { MockScanSocket } from './scanSocket'

/**
 * Starts the mock API. Prefers the MSW service worker; where service workers are
 * unavailable (some embedded browsers, file://, private modes) it routes window.fetch
 * through the same handlers in-page instead.
 */
export async function enableMocks(): Promise<MockTransport> {
  if (new URLSearchParams(window.location.search).get('reset') === '1') resetDb()
  setScanSocketFactory((_url, scanId) => new MockScanSocket(scanId))
  try {
    await setupWorker(...handlers).start({ onUnhandledRequest: 'bypass', quiet: true })
    return 'service-worker'
  } catch {
    const realFetch = window.fetch.bind(window)
    window.fetch = async (input, init) => {
      const request = new Request(input, init)
      const mocked = await getResponse(handlers, request.clone())
      return mocked ?? realFetch(request)
    }
    return 'in-page'
  }
}
