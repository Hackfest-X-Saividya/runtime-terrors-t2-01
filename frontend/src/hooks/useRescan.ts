import { useNavigate } from 'react-router-dom'
import { useCreateScan } from '@/api/hooks'
import { useToast } from './useToast'

/** Starts a rescan (rescan_of) and opens its live progress. */
export function useRescan() {
  const create = useCreateScan()
  const navigate = useNavigate()
  const toast = useToast()
  return {
    pending: create.isPending,
    rescan: (scanId: string) =>
      create.mutate(
        { kind: 'rescan', rescan_of: scanId },
        {
          onSuccess: ({ scan_id }) => {
            toast('success', `Re-scan ${scan_id} started with the current model.`)
            navigate(`/scan/new?scan=${scan_id}`)
          },
          onError: (e) => toast('error', e.message),
        },
      ),
  }
}
