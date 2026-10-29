import { useState, type FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useHealth, useSummary } from '@/api/hooks'
import { API_URL } from '@/lib/env'
import { mockTransport } from '@/lib/runtime'
import { ButtonLink } from '../Button'
import { ScanStatusPill } from '../Badges'
import { Icon } from '../Icon'

function ApiStatus() {
  const health = useHealth()
  const mock = mockTransport()
  const status = mock ? 'mock' : health.isPending ? 'checking' : health.data?.ok ? 'online' : 'offline'
  const meta = {
    mock: {
      label: 'Mock mode',
      dot: 'bg-tertiary-container',
      text: 'text-tertiary',
      title: `Sample data served in the browser (${mock})`,
    },
    checking: { label: 'Checking API', dot: 'bg-outline', text: 'text-on-surface-variant', title: API_URL },
    online: { label: 'API online', dot: 'bg-primary', text: 'text-primary', title: API_URL },
    offline: { label: 'API offline', dot: 'bg-error', text: 'text-error', title: `${API_URL} is not responding` },
  }[status]

  return (
    <span
      title={meta.title}
      className="flex items-center gap-2 rounded bg-surface-container-low px-space-sm py-1 font-label-code-sm text-label-code-sm"
    >
      <span className="relative flex h-2 w-2" aria-hidden="true">
        {status === 'online' && (
          <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary opacity-75" />
        )}
        <span className={`relative inline-flex h-2 w-2 rounded-full ${meta.dot}`} />
      </span>
      <span className={meta.text}>{meta.label}</span>
    </span>
  )
}

export function TopBar() {
  const last = useSummary().data?.last_scan
  const navigate = useNavigate()
  const [q, setQ] = useState('')

  const search = (e: FormEvent) => {
    e.preventDefault()
    if (!last || !q.trim()) return
    navigate(`/scans/${last.id}/findings?q=${encodeURIComponent(q.trim())}`)
    setQ('')
  }

  return (
    <header className="fixed left-64 right-0 top-0 z-40 flex h-16 items-center justify-between gap-space-md bg-surface-container-lowest/90 px-space-lg shadow-topbar backdrop-blur-xl">
      <div className="flex min-w-0 flex-1 items-center gap-space-md">
        {last && (
          <Link
            to={`/scans/${last.id}/findings`}
            className="hidden min-w-0 shrink items-center gap-space-xs rounded-lg bg-surface-container px-space-sm py-1.5 text-on-surface-variant hover:text-on-surface lg:flex"
          >
            <Icon name="source_environment" className="text-primary" />
            <span className="max-w-52 truncate font-label-code-sm text-label-code-sm text-on-surface">{last.name}</span>
            <ScanStatusPill status={last.status} />
          </Link>
        )}
        <form role="search" onSubmit={search} className="relative max-w-xl flex-1">
          <Icon
            name="search"
            className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant"
          />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            aria-label="Search findings in the latest scan"
            placeholder="Search findings: file, CWE, title…"
            className="w-full rounded-lg bg-surface-container py-1.5 pl-9 pr-space-md font-label-code-sm text-label-code-sm text-on-surface placeholder:text-outline focus:bg-surface-container-high"
          />
        </form>
      </div>
      <div className="flex shrink-0 items-center gap-space-md">
        <ApiStatus />
        <ButtonLink to="/scan/new" variant="primary" icon="add">
          New scan
        </ButtonLink>
      </div>
    </header>
  )
}
