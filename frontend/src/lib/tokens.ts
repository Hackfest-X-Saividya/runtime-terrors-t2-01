// Design tokens from design/stitch/DESIGN.md. Single source for tailwind.config.ts
// and for the few places that need raw values (SVG charts, Shiki theme, report HTML).
// Do not add values that are not in DESIGN.md.

export const colors = {
  background: '#0f131c',
  'on-background': '#dfe2ee',
  surface: '#0f131c',
  'surface-dim': '#0f131c',
  'surface-bright': '#353942',
  'surface-variant': '#31353e',
  'surface-tint': '#1ce388',
  'surface-container-lowest': '#0a0e16',
  'surface-container-low': '#181c24',
  'surface-container': '#1c2028',
  'surface-container-high': '#262a33',
  'surface-container-highest': '#31353e',
  'on-surface': '#dfe2ee',
  'on-surface-variant': '#bacbbc',
  'inverse-surface': '#dfe2ee',
  'inverse-on-surface': '#2c3039',
  outline: '#859587',
  'outline-variant': '#3c4a3f',

  primary: '#45f99c',
  'on-primary': '#00391d',
  'primary-container': '#00dc82',
  'on-primary-container': '#005b32',
  'primary-fixed': '#59ffa4',
  'primary-fixed-dim': '#1ce388',
  'on-primary-fixed': '#00210f',
  'on-primary-fixed-variant': '#00522d',
  'inverse-primary': '#006d3e',

  secondary: '#adc6ff',
  'on-secondary': '#002e6a',
  'secondary-container': '#0566d9',
  'on-secondary-container': '#e6ecff',
  'secondary-fixed': '#d8e2ff',
  'secondary-fixed-dim': '#adc6ff',
  'on-secondary-fixed': '#001a42',
  'on-secondary-fixed-variant': '#004395',

  tertiary: '#ffd5a5',
  'on-tertiary': '#472a00',
  'tertiary-container': '#ffb044',
  'on-tertiary-container': '#6f4500',
  'tertiary-fixed': '#ffddb8',
  'tertiary-fixed-dim': '#ffb95f',
  'on-tertiary-fixed': '#2a1700',
  'on-tertiary-fixed-variant': '#653e00',

  error: '#ffb4ab',
  'on-error': '#690005',
  'error-container': '#93000a',
  'on-error-container': '#ffdad6',
} as const

/** Print/report palette (DESIGN.md, screen 05 document). Report HTML only, never app UI. */
export const reportColors = {
  sheet: '#ffffff',
  text: '#0f172a',
  textStrong: '#1e293b',
  textBody: '#334155',
  textMuted: '#475569',
  textFaint: '#64748b',
  border: '#e2e8f0',
  borderStrong: '#cbd5e1',
  borderFaint: '#f1f5f9',
  rowTint: '#f8fafc',
  critical: '#dc2626',
  criticalTagBg: '#fee2e2',
  criticalTagText: '#991b1b',
  criticalCalloutBg: '#fef2f2',
  criticalCalloutBorder: '#fca5a5',
  criticalCalloutText: '#7f1d1d',
  high: '#d97706',
  highTagBg: '#fef3c7',
  highTagText: '#92400e',
  medium: '#2563eb',
  low: '#475569',
  lowDot: '#94a3b8',
  success: '#059669',
  successBg: '#f0fdf4',
  successBorder: '#bbf7d0',
  successText: '#166534',
} as const

export const fontFamily = {
  sans: ['Inter', 'sans-serif'],
  mono: ['"JetBrains Mono"', 'monospace'],
}

type FontSize = [string, { lineHeight: string; letterSpacing: string; fontWeight: string }]

export const fontSize: Record<string, FontSize> = {
  'headline-xl': ['2.25rem', { lineHeight: '2.75rem', letterSpacing: '-0.025em', fontWeight: '600' }],
  'headline-lg': ['1.75rem', { lineHeight: '2.25rem', letterSpacing: '-0.02em', fontWeight: '600' }],
  'headline-md': ['1.25rem', { lineHeight: '1.75rem', letterSpacing: '-0.015em', fontWeight: '600' }],
  'headline-sm': ['1rem', { lineHeight: '1.5rem', letterSpacing: '-0.01em', fontWeight: '600' }],
  'body-lg': ['1rem', { lineHeight: '1.625rem', letterSpacing: '-0.005em', fontWeight: '400' }],
  'body-md': ['0.875rem', { lineHeight: '1.375rem', letterSpacing: '0em', fontWeight: '400' }],
  'body-sm': ['0.75rem', { lineHeight: '1.125rem', letterSpacing: '0.01em', fontWeight: '400' }],
  'label-code-lg': ['0.875rem', { lineHeight: '1.375rem', letterSpacing: '-0.01em', fontWeight: '500' }],
  'label-code-md': ['0.75rem', { lineHeight: '1.125rem', letterSpacing: '0em', fontWeight: '500' }],
  'label-code-sm': ['0.6875rem', { lineHeight: '1rem', letterSpacing: '0.025em', fontWeight: '600' }],
}

/** px values of the type scale, for SVG/Recharts which need numbers. */
export const px = {
  bodyMd: 14,
  labelCodeLg: 14,
  headlineSm: 16,
  headlineLg: 28,
} as const

export const spacing = {
  'space-xs': '0.25rem',
  'space-sm': '0.5rem',
  'space-md': '1rem',
  'space-lg': '1.5rem',
  'space-xl': '2rem',
  gutter: '1rem',
  margin: '1rem',
  'gutter-desktop': '1.5rem',
  'margin-desktop': '2rem',
}

export const borderRadius = {
  none: '0',
  DEFAULT: '0.25rem',
  lg: '0.5rem',
  xl: '0.75rem',
  full: '9999px',
}

export const boxShadow = {
  sidebar: '0 1px 8px rgba(0,0,0,0.4)',
  topbar: '0 1px 8px rgba(0,0,0,0.3)',
}
