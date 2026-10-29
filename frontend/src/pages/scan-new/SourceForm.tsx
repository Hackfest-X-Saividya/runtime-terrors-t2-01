import { useState, type FormEvent } from 'react'
import { useDropzone, type FileRejection } from 'react-dropzone'
import { Button } from '@/components/Button'
import { Icon } from '@/components/Icon'
import { DEMO_CODE, DEMO_FILENAME } from '@/lib/demo'
import { fmtBytes } from '@/lib/format'
import type { CreateScanInput } from '@/types/contract'

const MAX_ZIP = 50 * 1024 * 1024
type Tab = 'zip' | 'git' | 'paste'

const tabs: { id: Tab; label: string; icon: string }[] = [
  { id: 'zip', label: 'Upload zip', icon: 'drive_folder_upload' },
  { id: 'git', label: 'Git URL', icon: 'commit' },
  { id: 'paste', label: 'Paste code', icon: 'code' },
]

function rejectionMessage(rejections: FileRejection[]): string {
  const code = rejections[0]?.errors[0]?.code
  if (code === 'file-too-large') return 'That file is over 50 MB. Zip only the source folders and try again.'
  if (code === 'file-invalid-type') return 'Only .zip archives are accepted.'
  if (code === 'too-many-files') return 'Drop one .zip at a time.'
  return 'That file could not be used.'
}

interface SourceFormProps {
  busy: boolean
  /** Button text while busy. */
  busyLabel?: string
  onStart: (input: CreateScanInput) => void
}

export function SourceForm({ busy, busyLabel = 'Starting…', onStart }: SourceFormProps) {
  const [tab, setTab] = useState<Tab>('zip')
  const [file, setFile] = useState<File | null>(null)
  const [fileError, setFileError] = useState<string | null>(null)
  const [gitUrl, setGitUrl] = useState('')
  const [code, setCode] = useState('')
  const [filename, setFilename] = useState('snippet.py')
  const [touched, setTouched] = useState(false)

  const { getRootProps, getInputProps, isDragActive, open } = useDropzone({
    accept: { 'application/zip': ['.zip'], 'application/x-zip-compressed': ['.zip'] },
    maxSize: MAX_ZIP,
    multiple: false,
    noClick: true,
    onDropAccepted: ([f]) => {
      setFile(f)
      setFileError(null)
    },
    onDropRejected: (r) => setFileError(rejectionMessage(r)),
  })

  const gitValid = /^https?:\/\/\S+\/\S+/.test(gitUrl.trim())
  const error =
    tab === 'zip' && !file
      ? 'Choose a .zip file first.'
      : tab === 'git' && !gitValid
        ? 'Enter an http(s) repository URL, e.g. https://github.com/org/repo'
        : tab === 'paste' && !code.trim()
          ? 'Paste some Python code first.'
          : null

  const submit = (e: FormEvent) => {
    e.preventDefault()
    setTouched(true)
    if (error) return
    if (tab === 'zip' && file) onStart({ kind: 'zip', file })
    if (tab === 'git') onStart({ kind: 'git', git_url: gitUrl.trim() })
    if (tab === 'paste') onStart({ kind: 'paste', code, filename: filename.trim() || 'snippet.py' })
  }

  const field =
    'w-full rounded-lg bg-surface-container-lowest px-space-sm py-2 font-label-code-md text-label-code-md text-on-surface placeholder:text-outline'

  return (
    <form onSubmit={submit} className="flex flex-col gap-space-md" noValidate>
      <div className="flex flex-wrap items-center justify-between gap-space-sm">
        <div role="tablist" aria-label="Code source" className="flex gap-1 rounded-lg bg-surface-container-lowest p-1">
          {tabs.map((t) => (
            <button
              key={t.id}
              type="button"
              role="tab"
              id={`tab-${t.id}`}
              aria-selected={tab === t.id}
              aria-controls={`panel-${t.id}`}
              onClick={() => {
                setTab(t.id)
                setTouched(false)
              }}
              className={`flex items-center gap-1.5 rounded-lg px-space-md py-1.5 font-label-code-md text-label-code-md transition-colors ${
                tab === t.id
                  ? 'bg-primary-container text-on-primary-container'
                  : 'text-on-surface-variant hover:text-on-surface'
              }`}
            >
              <span className="material-symbols-outlined" aria-hidden="true">
                {t.icon}
              </span>
              {t.label}
            </button>
          ))}
        </div>
        <span className="flex items-center gap-1 font-label-code-sm text-label-code-sm text-on-surface-variant">
          <Icon name="verified_user" className="text-primary" />
          Code is analysed statically, never executed
        </span>
      </div>

      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`}>
        {tab === 'zip' && (
          <div className="flex flex-col gap-space-sm">
            <div
              {...getRootProps({
                className: `flex flex-col items-center gap-space-sm rounded-xl border-2 border-dashed px-space-md py-space-xl text-center transition-colors ${
                  isDragActive ? 'border-primary bg-primary/10' : 'border-outline-variant bg-surface-container-lowest'
                }`,
              })}
            >
              <input {...getInputProps({ 'aria-label': 'Project zip file' })} />
              <span className="flex h-12 w-12 items-center justify-center rounded-lg bg-surface-container-high">
                <Icon name="cloud_upload" className="text-headline-md text-primary" />
              </span>
              <p className="font-headline-sm text-headline-sm text-on-surface">
                {isDragActive ? 'Drop the zip to stage it' : 'Drop a .zip of your project, max 50 MB'}
              </p>
              <p className="font-body-md text-body-md text-on-surface-variant">
                Python projects first; nested packages are fine.
              </p>
              <Button onClick={open} icon="folder_open">
                Browse files
              </Button>
            </div>
            {file && (
              <div className="flex items-center gap-space-sm rounded-lg bg-surface-container p-space-sm">
                <Icon name="folder_zip" className="text-primary" />
                <span className="min-w-0 flex-1 truncate font-label-code-md text-label-code-md text-on-surface">
                  {file.name}
                </span>
                <span className="font-label-code-sm text-label-code-sm text-on-surface-variant">
                  {fmtBytes(file.size)}
                </span>
                <span className="flex items-center gap-1 font-label-code-sm text-label-code-sm text-primary">
                  <Icon name="check_circle" /> Staged
                </span>
                <button
                  type="button"
                  aria-label={`Remove ${file.name}`}
                  onClick={() => setFile(null)}
                  className="rounded text-on-surface-variant hover:text-on-surface"
                >
                  <Icon name="close" />
                </button>
              </div>
            )}
            {fileError && (
              <p role="alert" className="font-body-md text-body-md text-error">
                {fileError}
              </p>
            )}
          </div>
        )}

        {tab === 'git' && (
          <div className="flex flex-col gap-space-sm py-space-md">
            <label
              htmlFor="git-url"
              className="font-label-code-sm text-label-code-sm uppercase text-on-surface-variant"
            >
              Public repository URL
            </label>
            <input
              id="git-url"
              type="url"
              value={gitUrl}
              onChange={(e) => setGitUrl(e.target.value)}
              placeholder="https://github.com/acme/billing-worker"
              aria-invalid={touched && !gitValid}
              className={field}
            />
            <p className="font-body-sm text-body-sm text-on-surface-variant">
              The default branch is cloned shallowly on the server.
            </p>
          </div>
        )}

        {tab === 'paste' && (
          <div className="flex flex-col gap-space-sm">
            <label
              htmlFor="paste-name"
              className="font-label-code-sm text-label-code-sm uppercase text-on-surface-variant"
            >
              File name
            </label>
            <input id="paste-name" value={filename} onChange={(e) => setFilename(e.target.value)} className={field} />
            <label
              htmlFor="paste-code"
              className="font-label-code-sm text-label-code-sm uppercase text-on-surface-variant"
            >
              Python code
            </label>
            <textarea
              id="paste-code"
              rows={10}
              value={code}
              onChange={(e) => setCode(e.target.value)}
              spellCheck={false}
              placeholder="def handler(request): ..."
              aria-invalid={touched && !code.trim()}
              className={`${field} resize-y`}
            />
          </div>
        )}
      </div>

      {touched && error && (
        <p role="alert" className="font-body-md text-body-md text-error">
          {error}
        </p>
      )}

      <div className="flex flex-wrap items-center justify-end gap-space-sm">
        <Button
          icon="science"
          disabled={busy}
          onClick={() => onStart({ kind: 'paste', code: DEMO_CODE, filename: DEMO_FILENAME })}
          title="Scans a small vulnerable Flask app"
        >
          Run demo scan
        </Button>
        <Button type="submit" variant="primary" icon="play_arrow" disabled={busy}>
          {busy ? busyLabel : 'Start scan'}
        </Button>
      </div>
    </form>
  )
}
