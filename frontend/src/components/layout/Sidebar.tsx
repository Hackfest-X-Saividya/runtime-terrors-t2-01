import { NavLink, useLocation } from 'react-router-dom'
import { useSummary } from '@/api/hooks'
import { mockTransport } from '@/lib/runtime'
import { Icon } from '../Icon'

export function Sidebar() {
  const { pathname } = useLocation()
  const last = useSummary().data?.last_scan
  const findingsTo = last ? `/scans/${last.id}/findings` : '/'
  const reportsTo = last ? `/reports/${last.id}` : '/reports'

  const nav = [
    { to: '/', label: 'Dashboard', icon: 'dashboard', active: pathname === '/' },
    { to: '/scan/new', label: 'New Scan', icon: 'radar', active: pathname === '/scan/new' },
    {
      to: findingsTo,
      label: 'Findings',
      icon: 'shield_with_house',
      active: pathname.startsWith('/findings') || /^\/scans\/[^/]+\/(findings|changes)/.test(pathname),
    },
    { to: reportsTo, label: 'Reports', icon: 'description', active: pathname.startsWith('/reports') },
    { to: '/model', label: 'Model', icon: 'smart_toy', active: pathname.startsWith('/model') },
  ]

  return (
    <aside className="fixed left-0 top-0 z-50 flex h-full w-64 flex-col justify-between bg-surface-container-low shadow-sidebar">
      <div className="flex flex-col">
        <NavLink to="/" className="flex h-16 items-center gap-space-sm px-space-md" aria-label="ZeroSentinel home">
          <Icon name="shield_lock" filled className="text-headline-md text-primary" />
          <span className="font-headline-sm text-headline-sm text-on-surface">ZeroSentinel</span>
          <span className="rounded bg-surface-container-highest px-1.5 py-0.5 font-label-code-sm text-label-code-sm text-primary">
            PS-01
          </span>
        </NavLink>
        <nav aria-label="Main" className="flex flex-col gap-1 px-space-sm pt-space-md">
          {nav.map((item) => (
            <NavLink
              key={item.label}
              to={item.to}
              aria-current={item.active ? 'page' : undefined}
              className={`flex items-center gap-space-sm rounded-lg px-space-sm py-2 font-body-md text-body-md transition-colors ${
                item.active
                  ? 'bg-surface-container-high font-medium text-primary'
                  : 'text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface'
              }`}
            >
              <Icon name={item.icon} filled={item.active} />
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>
      </div>
      <div className="flex flex-col gap-space-sm p-space-md">
        {mockTransport() && (
          <a
            href="/?reset=1"
            className="flex items-center gap-space-sm rounded-lg bg-surface-container px-space-sm py-1.5 font-label-code-sm text-label-code-sm text-tertiary hover:bg-surface-container-high"
            title="Discard demo changes and reload the sample data"
          >
            <Icon name="restart_alt" /> Reset sample data
          </a>
        )}
        <p className="font-label-code-sm text-label-code-sm text-outline">Zero-day detection · rules + ML</p>
      </div>
    </aside>
  )
}
