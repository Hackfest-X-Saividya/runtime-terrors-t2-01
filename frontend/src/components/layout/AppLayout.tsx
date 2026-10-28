import { Outlet, useLocation } from 'react-router-dom'
import { ErrorBoundary } from '../ErrorBoundary'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'

export function AppLayout() {
  const { pathname } = useLocation()
  return (
    <>
      <a
        href="#main"
        className="sr-only z-[70] rounded-lg bg-primary-container px-space-md py-space-sm text-on-primary-container focus:not-sr-only focus:fixed focus:left-space-md focus:top-space-md"
      >
        Skip to content
      </a>
      <Sidebar />
      <div className="pl-64">
        <TopBar />
        <main
          id="main"
          tabIndex={-1}
          className="mx-auto min-h-screen max-w-[1600px] px-gutter-desktop pb-space-xl pt-16"
        >
          <ErrorBoundary resetKey={pathname}>
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>
    </>
  )
}
