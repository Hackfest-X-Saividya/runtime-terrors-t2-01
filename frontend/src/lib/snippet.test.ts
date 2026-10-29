import { describe, expect, it } from 'vitest'
import { templates } from '@/mocks/templates'
import { sinkIndex, sinkLine } from './snippet'

describe('sinkLine', () => {
  it('prefers the dangerous call over a longer setup line', () => {
    expect(sinkLine('def f(raw):\n    data = base64.b64decode(raw_input_value)\n    return pickle.loads(data)')).toBe(
      'return pickle.loads(data)',
    )
  })

  it('falls back to the longest non-def line', () => {
    expect(sinkIndex('def f():\n    x = 1\n    total = compute_something_long(x)')).toBe(2)
  })

  it('never highlights the def line of a mock snippet', () => {
    for (const t of templates) {
      const line = sinkLine(t.snippet('fn'))
      expect(line.startsWith('def '), `${t.key}: ${line}`).toBe(false)
      expect(line.length).toBeGreaterThan(0)
    }
  })
})
