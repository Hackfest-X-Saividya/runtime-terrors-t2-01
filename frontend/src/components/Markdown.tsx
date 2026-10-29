import ReactMarkdown, { type Components } from 'react-markdown'
import remarkGfm from 'remark-gfm'

const components: Components = {
  p: ({ children }) => (
    <p className="mb-space-sm font-body-md text-body-md text-on-surface-variant last:mb-0">{children}</p>
  ),
  ul: ({ children }) => (
    <ul className="mb-space-sm list-disc pl-space-lg font-body-md text-body-md text-on-surface-variant">{children}</ul>
  ),
  ol: ({ children }) => (
    <ol className="mb-space-sm list-decimal pl-space-lg font-body-md text-body-md text-on-surface-variant">
      {children}
    </ol>
  ),
  a: ({ children, href }) => (
    <a href={href} target="_blank" rel="noreferrer" className="text-primary underline">
      {children}
    </a>
  ),
  strong: ({ children }) => <strong className="font-semibold text-on-surface">{children}</strong>,
  pre: ({ children }) => (
    <pre className="mb-space-sm overflow-x-auto rounded-lg bg-surface-container-lowest p-space-sm font-mono text-label-code-md text-primary">
      {children}
    </pre>
  ),
  code: ({ children, className }) =>
    className ? (
      <code className={className}>{children}</code>
    ) : (
      <code className="rounded bg-surface-container-highest px-1 font-mono text-label-code-md text-on-surface">
        {children}
      </code>
    ),
}

/** Renders backend markdown (mitigations). Raw HTML in the source is not rendered. */
export function Markdown({ children }: { children: string }) {
  return (
    <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
      {children}
    </ReactMarkdown>
  )
}
