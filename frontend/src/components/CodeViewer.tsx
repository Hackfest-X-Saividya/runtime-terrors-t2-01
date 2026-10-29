import { useEffect, useState, type CSSProperties } from 'react'
import type { HighlighterCore, ThemeRegistration } from 'shiki/core'
import { colors } from '@/lib/tokens'

// Shiki theme built only from DESIGN.md tokens.
const theme: ThemeRegistration = {
  name: 'zerosentinel',
  type: 'dark',
  colors: { 'editor.background': colors['surface-container-lowest'], 'editor.foreground': colors['on-surface'] },
  tokenColors: [
    {
      scope: ['comment', 'punctuation.definition.comment'],
      settings: { foreground: colors.outline, fontStyle: 'italic' },
    },
    { scope: ['keyword', 'storage', 'keyword.operator.logical'], settings: { foreground: colors.secondary } },
    { scope: ['string', 'string.quoted'], settings: { foreground: colors.tertiary } },
    { scope: ['constant.numeric', 'constant.language'], settings: { foreground: colors['tertiary-container'] } },
    {
      scope: ['entity.name.function', 'support.function', 'meta.function-call.generic'],
      settings: { foreground: colors.primary },
    },
    {
      scope: ['entity.name.decorator', 'meta.function.decorator'],
      settings: { foreground: colors['primary-fixed-dim'] },
    },
    {
      scope: ['variable.parameter', 'variable.language.special.self'],
      settings: { foreground: colors['secondary-fixed'] },
    },
    {
      scope: ['constant.character.format.placeholder', 'meta.fstring', 'storage.type.string'],
      settings: { foreground: colors.error },
    },
  ],
}

let highlighter: Promise<HighlighterCore> | null = null
/** Loaded on first use so Shiki stays out of the main bundle. */
function getHighlighter() {
  highlighter ??= Promise.all([import('shiki/core'), import('shiki/engine/javascript')]).then(
    ([{ createHighlighterCore }, { createJavaScriptRegexEngine }]) =>
      createHighlighterCore({
        themes: [theme],
        langs: [import('shiki/langs/python.mjs')],
        engine: createJavaScriptRegexEngine(),
      }),
  )
  return highlighter
}

interface CodeViewerProps {
  code: string
  /** Line number of the first line. */
  startLine: number
  /** 0-based indexes of lines to highlight. */
  highlight: number[]
  label: string
}

export function CodeViewer({ code, startLine, highlight, label }: CodeViewerProps) {
  const [html, setHtml] = useState<string | null>(null)
  const key = highlight.join(',')

  useEffect(() => {
    let live = true
    const marked = new Set(key ? key.split(',').map(Number) : [])
    getHighlighter()
      .then((h) =>
        h.codeToHtml(code, {
          lang: 'python',
          theme: 'zerosentinel',
          transformers: [
            {
              line(node, line) {
                if (marked.has(line - 1)) this.addClassToHast(node, 'hl')
              },
            },
          ],
        }),
      )
      .then((out) => live && setHtml(out))
      .catch(() => live && setHtml(null))
    return () => {
      live = false
    }
  }, [code, key])

  const style = { '--line-start': startLine - 1 } as CSSProperties
  return (
    <div
      role="region"
      aria-label={label}
      tabIndex={0}
      className="code-view overflow-x-auto bg-surface-container-lowest py-space-sm font-mono text-label-code-lg"
    >
      {html ? (
        // Shiki output is generated from the snippet text with HTML escaped.
        <div style={style} dangerouslySetInnerHTML={{ __html: html }} />
      ) : (
        <pre style={style}>
          <code>
            {code.split('\n').map((l, i) => (
              <span key={i} className={`line ${highlight.includes(i) ? 'hl' : ''}`}>
                {l}
                {'\n'}
              </span>
            ))}
          </code>
        </pre>
      )}
    </div>
  )
}
