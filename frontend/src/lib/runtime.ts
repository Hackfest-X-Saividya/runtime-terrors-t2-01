/** How mocks are served this session, or null when the real API is used. Set once at startup. */
export type MockTransport = 'service-worker' | 'in-page'

let transport: MockTransport | null = null

export const mockTransport = () => transport

export function setMockTransport(t: MockTransport | null) {
  transport = t
}
