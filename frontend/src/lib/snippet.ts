const skip = /^(def |async def |@|#|class |"""|''')/

/** Common Python sinks and dangerous settings; a line containing one is preferred. */
const sinks =
  /\b(execute|executemany|raw|system|popen|subprocess\.\w+|eval|exec|pickle\.loads?|yaml\.load|requests\.\w+|render_template_string|redirect|send_file|extractall|setattr|import_module|md5|sha1|random\.\w+|fromstring|jwt\.decode|CORS|assert|logger\.\w+|re\.compile|format_exc)\b|verify=False|debug=True|shell=True|except Exception|"0\.0\.0\.0"|= "[^"]{8,}"/

/**
 * Index (0-based) of the snippet line most likely to hold the bug: the first line
 * calling a known sink, else the longest line that isn't a def, decorator or comment.
 */
export function sinkIndex(snippet: string): number {
  const lines = snippet.split('\n')
  const hit = lines.findIndex((l) => l.trim() && !skip.test(l.trim()) && sinks.test(l))
  if (hit >= 0) return hit
  let best = 0
  let bestLen = -1
  lines.forEach((raw, i) => {
    const l = raw.trim()
    if (!l || skip.test(l)) return
    if (l.length > bestLen) {
      best = i
      bestLen = l.length
    }
  })
  return best
}

export const sinkLine = (snippet: string) => snippet.split('\n')[sinkIndex(snippet)]?.trim() ?? ''
