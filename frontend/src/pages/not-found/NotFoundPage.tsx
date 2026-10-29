import { ButtonLink } from '@/components/Button'
import { Card } from '@/components/Card'
import { EmptyState } from '@/components/States'

export default function NotFoundPage() {
  return (
    <div className="pt-space-xl">
      <Card>
        <EmptyState icon="explore_off" title="Page not found">
          <p className="mb-space-md">That address doesn't match any page in ZeroSentinel.</p>
          <ButtonLink to="/" icon="dashboard">
            Back to dashboard
          </ButtonLink>
        </EmptyState>
      </Card>
    </div>
  )
}
