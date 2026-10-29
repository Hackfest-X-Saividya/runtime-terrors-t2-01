import { lazy, Suspense, type ReactNode } from 'react'
import { createBrowserRouter, Navigate, RouterProvider } from 'react-router-dom'
import { useSummary } from '@/api/hooks'
import { AppLayout } from './components/layout/AppLayout'
import { SkeletonRows } from './components/States'
import { ToastProvider } from './components/Toasts'

// One chunk per page keeps Recharts, Shiki and markdown out of the first load.
const DashboardPage = lazy(() => import('./pages/dashboard/DashboardPage'))
const NewScanPage = lazy(() => import('./pages/scan-new/NewScanPage'))
const FindingsPage = lazy(() => import('./pages/findings/FindingsPage'))
const ScanChangesPage = lazy(() => import('./pages/scan-changes/ScanChangesPage'))
const FindingDetailPage = lazy(() => import('./pages/finding-detail/FindingDetailPage'))
const ReportPage = lazy(() => import('./pages/report/ReportPage'))
const ModelPage = lazy(() => import('./pages/model/ModelPage'))
const NotFoundPage = lazy(() => import('./pages/not-found/NotFoundPage'))

const page = (el: ReactNode) => (
  <Suspense
    fallback={
      <div className="pt-space-xl">
        <SkeletonRows rows={6} />
      </div>
    }
  >
    {el}
  </Suspense>
)

/** /findings without a scan opens the latest scan's findings. */
function LatestFindings() {
  const summary = useSummary()
  if (summary.data) return <Navigate replace to={`/scans/${summary.data.last_scan.id}/findings`} />
  return summary.isError ? <Navigate replace to="/" /> : <SkeletonRows />
}

const router = createBrowserRouter([
  {
    element: <AppLayout />,
    children: [
      { path: '/', element: page(<DashboardPage />) },
      { path: '/scan/new', element: page(<NewScanPage />) },
      { path: '/findings', element: <LatestFindings /> },
      { path: '/scans/:scanId/findings', element: page(<FindingsPage />) },
      { path: '/scans/:scanId/changes', element: page(<ScanChangesPage />) },
      { path: '/findings/:findingId', element: page(<FindingDetailPage />) },
      { path: '/reports/:scanId?', element: page(<ReportPage />) },
      { path: '/model', element: page(<ModelPage />) },
      { path: '*', element: page(<NotFoundPage />) },
    ],
  },
])

export default function App() {
  return (
    <ToastProvider>
      <RouterProvider router={router} />
    </ToastProvider>
  )
}
