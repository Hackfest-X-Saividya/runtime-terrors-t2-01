import { reportColors as c } from '@/lib/tokens'
import type { Finding, Scan, Severity } from '@/types/contract'

// Mock-mode risk report. The real backend generates its own; this mirrors the
// light document style of design screen 05.

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

const sevColour: Record<Severity, string> = { critical: c.critical, high: c.high, medium: c.medium, low: c.low }
const sevOrder: Severity[] = ['critical', 'high', 'medium', 'low']

/** Very small markdown subset for mitigations: fenced code, inline code, paragraphs. */
function md(text: string): string {
  return text
    .split(/```(?:\w+)?\n([\s\S]*?)```/g)
    .map((part, i) =>
      i % 2
        ? `<pre>${esc(part)}</pre>`
        : part
            .split(/\n{2,}/)
            .filter((p) => p.trim())
            .map((p) => `<p>${esc(p).replace(/`([^`]+)`/g, '<code>$1</code>')}</p>`)
            .join(''),
    )
    .join('')
}

export function buildReportHtml(scan: Scan, findings: Finding[], generatedAt = new Date()): string {
  const visible = findings.filter((f) => !f.suppressed)
  const total = visible.length || 1
  const owasp = new Map<string, number>()
  for (const f of visible) owasp.set(f.owasp, (owasp.get(f.owasp) ?? 0) + 1)
  const top = [...visible].sort((a, b) => b.risk_score - a.risk_score).slice(0, 10)
  const novel = visible.filter((f) => f.source === 'ml').length

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>ZeroSentinel report: ${esc(scan.name)}</title>
<style>
body{margin:0;background:${c.sheet};color:${c.textBody};font:14px/1.6 Inter,system-ui,sans-serif}
main{max-width:860px;margin:0 auto;padding:40px 32px}
h1{color:${c.text};font-size:28px;margin:0 0 4px}h2{color:${c.text};font-size:16px;text-transform:uppercase;letter-spacing:.04em;margin:32px 0 12px;border-bottom:1px solid ${c.border};padding-bottom:6px}
h3{color:${c.textStrong};font-size:15px;margin:0 0 4px}
.meta{color:${c.textFaint};font:12px/1.6 "JetBrains Mono",monospace}
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:24px}
.kpi{border:1px solid ${c.border};border-radius:8px;padding:12px}.kpi b{display:block;font-size:24px;color:${c.text}}.kpi span{font-size:12px;color:${c.textFaint};text-transform:uppercase}
table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;color:${c.textFaint};font-weight:600;border-bottom:1px solid ${c.borderStrong};padding:6px 8px}
td{border-bottom:1px solid ${c.borderFaint};padding:6px 8px}tr:nth-child(even) td{background:${c.rowTint}}
.sev{font-weight:700;font-family:"JetBrains Mono",monospace;font-size:12px}
.finding{border:1px solid ${c.border};border-radius:8px;padding:16px;margin-bottom:12px;break-inside:avoid}
.tag{display:inline-block;border-radius:4px;padding:1px 6px;font:600 11px "JetBrains Mono",monospace;margin-right:6px}
.crit{background:${c.criticalTagBg};color:${c.criticalTagText}}.high{background:${c.highTagBg};color:${c.highTagText}}.other{background:${c.border};color:${c.textBody}}
.novel{background:${c.successBg};color:${c.successText};border:1px solid ${c.successBorder}}
pre{background:${c.rowTint};border:1px solid ${c.border};border-radius:6px;padding:10px;font:12px/1.5 "JetBrains Mono",monospace;white-space:pre-wrap;color:${c.textStrong}}
code{font-family:"JetBrains Mono",monospace;font-size:12px;background:${c.borderFaint};padding:0 3px;border-radius:3px}
.callout{background:${c.criticalCalloutBg};border:1px solid ${c.criticalCalloutBorder};color:${c.criticalCalloutText};border-radius:8px;padding:12px;margin-top:16px}
footer{margin-top:40px;color:${c.textFaint};font-size:12px;border-top:1px solid ${c.border};padding-top:12px}
</style></head><body><main>
<p class="meta">ZEROSENTINEL RISK REPORT · SAMPLE DATA</p>
<h1>${esc(scan.name)}</h1>
<p class="meta">Scan ${esc(scan.id)} · ${esc(scan.source_type)} · model ${esc(scan.model_version)} · started ${esc(new Date(scan.started_at).toLocaleString())}</p>
<div class="kpis">
<div class="kpi"><span>Risk score</span><b>${scan.risk_score.toFixed(1)} / 10</b></div>
<div class="kpi"><span>Findings</span><b>${visible.length}</b></div>
<div class="kpi"><span>Critical</span><b style="color:${c.critical}">${scan.counts_by_severity.critical}</b></div>
<div class="kpi"><span>Novel (ML only)</span><b style="color:${c.success}">${novel}</b></div>
</div>
${scan.counts_by_severity.critical ? `<div class="callout"><b>Release blocker:</b> ${scan.counts_by_severity.critical} critical finding(s) must be fixed before deploying.</div>` : ''}
<h2>1. Severity distribution</h2>
<table><thead><tr><th>Severity</th><th>Count</th><th>Share</th></tr></thead><tbody>
${sevOrder.map((s) => `<tr><td class="sev" style="color:${sevColour[s]}">● ${s.toUpperCase()}</td><td>${scan.counts_by_severity[s]}</td><td>${((scan.counts_by_severity[s] / total) * 100).toFixed(1)}%</td></tr>`).join('')}
</tbody></table>
<h2>2. OWASP Top 10 (2025)</h2>
<table><thead><tr><th>Category</th><th>Findings</th></tr></thead><tbody>
${[...owasp.entries()]
  .sort((a, b) => b[1] - a[1])
  .map(([k, v]) => `<tr><td>${esc(k)}</td><td>${v}</td></tr>`)
  .join('')}
</tbody></table>
<h2>3. Top findings and mitigations</h2>
${top
  .map(
    (f) => `<div class="finding">
<span class="tag ${f.severity === 'critical' ? 'crit' : f.severity === 'high' ? 'high' : 'other'}">${f.severity.toUpperCase()} ${f.risk_score.toFixed(1)}</span>${f.source === 'ml' ? '<span class="tag novel">NOVEL</span>' : ''}<span class="meta">${esc(f.cwe_id)} · ${esc(f.owasp)}</span>
<h3>${esc(f.title)}</h3><p class="meta">${esc(f.file_path)}:${f.start_line}</p>
<pre>${esc(f.snippet)}</pre>${md(f.mitigation)}</div>`,
  )
  .join('')}
<footer>Generated ${esc(generatedAt.toLocaleString())} by ZeroSentinel (mock mode).</footer>
</main></body></html>`
}

/** Minimal one-page PDF (Helvetica text) for mock-mode downloads. */
export function buildReportPdf(scan: Scan, findings: Finding[]): Uint8Array {
  const visible = findings.filter((f) => !f.suppressed).sort((a, b) => b.risk_score - a.risk_score)
  const lines = [
    `ZeroSentinel risk report (sample data)`,
    ``,
    `Scan: ${scan.name} (${scan.id})`,
    `Risk score: ${scan.risk_score.toFixed(1)} / 10    Model: ${scan.model_version}`,
    `Critical ${scan.counts_by_severity.critical}  High ${scan.counts_by_severity.high}  Medium ${scan.counts_by_severity.medium}  Low ${scan.counts_by_severity.low}`,
    ``,
    `Top findings:`,
    ...visible
      .slice(0, 24)
      .map(
        (f) =>
          `${f.severity.toUpperCase().padEnd(9)} ${f.risk_score.toFixed(1)}  ${f.cwe_id.padEnd(9)} ${f.title}  (${f.file_path}:${f.start_line})`,
      ),
  ]
  const pdfText = (s: string) => s.replace(/[^\x20-\x7e]/g, '?').replace(/([\\()])/g, '\\$1')
  const content = [
    'BT /F1 9 Tf 40 800 Td 13 TL',
    ...lines.map((l, i) => `${i === 0 ? '/F1 14 Tf ' : i === 1 ? '/F1 9 Tf ' : ''}(${pdfText(l)}) '`),
    'ET',
  ].join('\n')
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
    `<< /Length ${content.length} >>\nstream\n${content}\nendstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ]
  let out = '%PDF-1.4\n'
  const offsets: number[] = []
  objects.forEach((body, i) => {
    offsets.push(out.length)
    out += `${i + 1} 0 obj\n${body}\nendobj\n`
  })
  const xref = out.length
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`
  out += offsets.map((o) => `${String(o).padStart(10, '0')} 00000 n \n`).join('')
  out += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`
  return new TextEncoder().encode(out)
}
