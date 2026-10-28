import type { Config } from 'tailwindcss'
import { borderRadius, boxShadow, colors, fontFamily, fontSize, spacing } from './src/lib/tokens'

// colors, fontSize, fontFamily and borderRadius REPLACE Tailwind's defaults so only
// DESIGN.md tokens exist. Stitch's per-style font names map to the two families.
const named = (family: string[], keys: string[]) => Object.fromEntries(keys.map((k) => [k, family]))

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    colors: { transparent: 'transparent', current: 'currentColor', inherit: 'inherit', ...colors },
    fontFamily: {
      ...fontFamily,
      ...named(fontFamily.sans, [
        'headline-xl',
        'headline-lg',
        'headline-md',
        'headline-sm',
        'body-lg',
        'body-md',
        'body-sm',
      ]),
      ...named(fontFamily.mono, ['label-code-lg', 'label-code-md', 'label-code-sm']),
    },
    fontSize,
    borderRadius,
    extend: { spacing, boxShadow },
  },
  plugins: [],
} satisfies Config
