import { beforeEach, describe, expect, it } from 'vitest'
import { listScans, resetDb, scanFindings } from '@/mocks/db'
import type { Finding } from '@/types/contract'

describe('Security Frameworks & Correlation Contract Conformance', () => {
  beforeEach(() => {
    resetDb()
  })

  function getAllFindings(): Finding[] {
    const scans = listScans()
    return scans.flatMap((s) => scanFindings(s.id))
  }

  it('generates mock findings with official OWASP Top 10:2025 mappings', () => {
    const findings = getAllFindings()
    expect(findings.length).toBeGreaterThan(0)

    for (const f of findings) {
      expect(f.owasp).toMatch(/^A(0[1-9]|10):2025 /)
      expect(f.owasp_mappings).toBeDefined()
      expect(Array.isArray(f.owasp_mappings)).toBe(true)

      const primary = f.owasp_mappings?.[0]
      expect(primary).toBeDefined()
      expect(primary?.version).toBe('2025')
      expect(primary?.category_id).toMatch(/^A(0[1-9]|10)(:2025)?$/)
      expect(primary?.confidence).toBe('high')
      expect(primary?.rationale.length).toBeGreaterThan(0)
    }
  })

  it('generates mock findings with NIST CSF 2.0 mappings', () => {
    const findings = getAllFindings()
    for (const f of findings) {
      expect(f.nist_csf_mappings).toBeDefined()
      expect(Array.isArray(f.nist_csf_mappings)).toBe(true)

      const nist = f.nist_csf_mappings?.[0]
      expect(nist).toBeDefined()
      expect(nist?.version).toBe('2.0')
      expect(['GV', 'ID', 'PR', 'DE', 'RS', 'RC']).toContain(nist?.function_code)
      expect(nist?.subcategory_id).toMatch(/^[A-Z]{2}\.[A-Z]{2}-\d{2}$/)
      expect(nist?.rationale.length).toBeGreaterThan(0)
      expect(nist?.reference.length).toBeGreaterThan(0)
    }
  })

  it('generates mock findings with CVSS v3.1 structures', () => {
    const findings = getAllFindings()
    for (const f of findings) {
      expect(f.cvss).toBeDefined()
      expect(f.cvss?.version).toBe('3.1')
      expect(typeof f.cvss_score).toBe('number')
      expect(f.cvss_score).toBeGreaterThanOrEqual(0.0)
      expect(f.cvss_score).toBeLessThanOrEqual(10.0)

      if (f.cvss?.vector) {
        expect(f.cvss.vector.startsWith('CVSS:3.1/')).toBe(true)
      }
      expect(['analyst_assessed', 'rule_estimated', 'unassessed']).toContain(f.cvss_provenance)
    }
  })

  it('generates mock findings with explainable correlation clusters', () => {
    const findings = getAllFindings()
    for (const f of findings) {
      expect(f.correlation).toBeDefined()
      expect(f.correlation?.cluster_id).toBeDefined()
      expect([
        'exact_duplicate',
        'corroborated',
        'related_risk',
        'standalone_candidate',
        'unassigned',
      ]).toContain(f.correlation?.correlation_type)
      expect(typeof f.correlation?.is_primary).toBe('boolean')
      expect(Array.isArray(f.correlation?.evidence)).toBe(true)

      if (f.source === 'ml') {
        expect(f.correlation?.correlation_type).toBe('standalone_candidate')
        expect(f.correlation?.limitations).toContain('Unverified ML candidate')
      }
      if (f.source === 'both') {
        expect(f.correlation?.correlation_type).toBe('corroborated')
      }
    }
  })

  it('distinguishes CVSS Base Score from ZeroSentinel Risk Score', () => {
    const findings = getAllFindings()
    const criticals = findings.filter((f: Finding) => f.severity === 'critical')
    expect(criticals.length).toBeGreaterThan(0)
    for (const c of criticals) {
      // CVSS 3.1 Base Score is fixed by metric vector (e.g. 9.8)
      expect(c.cvss_score).toBe(9.8)
      // Risk score is ZeroSentinel's proprietary score calculated with site variance
      expect(typeof c.risk_score).toBe('number')
      expect(c.risk_score).toBeGreaterThan(0)
    }
  })
})
