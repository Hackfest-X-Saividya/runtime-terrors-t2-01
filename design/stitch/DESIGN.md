# ZeroSentinel design tokens

Extracted from the Stitch exports in this folder (`*.html`) and `screens/*.png`.
All 7 HTML files embed the same `tailwind.config` (identical hash), so that
config is the source of truth. Every value below appears in the exports; nothing
is invented. Token names are kept exactly as Stitch named them so they drop
straight into `tailwind.config` `theme.extend`.

Theme: dark only (`darkMode: "class"`). Report document preview (05) is the one
exception, see "Print / report palette".

## Colour

### Background and panels

| Token | Hex | Used for |
|---|---|---|
| `background` / `surface` / `surface-dim` | `#0f131c` | Page background (`body`, `main`) |
| `surface-container-lowest` | `#0a0e16` | Top bar (`/90` + `backdrop-blur-xl`), code blocks, drop zone |
| `surface-container-low` | `#181c24` | Sidebar; **default card** (`rounded-xl bg-surface-container-low shadow-sm p-space-md`) |
| `surface-container` | `#1c2028` | Inputs, chips, nested rows inside cards |
| `surface-container-high` | `#262a33` | Active nav item, hover, selected rows |
| `surface-container-highest` / `surface-variant` | `#31353e` | Small tags (version pill, CWE chip) |
| `surface-bright` | `#353942` | Raised controls |

### Borders

Borders are rare; separation comes from surface tone steps and `shadow-sm`.

| Token | Hex | Used for |
|---|---|---|
| `outline-variant` | `#3c4a3f` | Default hairline (`border-outline-variant`), dividers |
| `outline` | `#859587` | Strong divider, disabled dot, placeholder text |
| `surface-container-highest` | `#31353e` | Card border where one is used |

### Text

| Token | Hex | Used for |
|---|---|---|
| `on-surface` / `on-background` | `#dfe2ee` | Primary text |
| `on-surface-variant` | `#bacbbc` | Secondary text, nav items, labels |
| `outline` | `#859587` | Muted / placeholder |

### Accent (brand green)

| Token | Hex | Used for |
|---|---|---|
| `primary` | `#45f99c` | Accent text, active nav, links, status dots, chart bars |
| `primary-container` | `#00dc82` | Primary button fill ("New scan", "Start scan") |
| `on-primary-container` | `#005b32` | Text on primary button |
| `primary-fixed-dim` / `surface-tint` | `#1ce388` | |
| `primary-fixed` | `#59ffa4` | |
| `on-primary` | `#00391d` | |
| `inverse-primary` | `#006d3e` | |

### Severity

Canonical set, taken from the Findings table (03) and the New Scan live stream (02).
Badge pattern: `inline-flex items-center gap-1.5 px-2 py-0.5 rounded font-label-code-sm text-label-code-sm font-semibold`
with a `w-1.5 h-1.5 rounded-full` dot, and **always** a text label (`CRITICAL` / `CRIT 9.8`).

| Severity | Dot | Badge background | Badge text |
|---|---|---|---|
| Critical | `error` `#ffb4ab` | `error-container` `#93000a` | `on-error-container` `#ffdad6` |
| High | `tertiary-container` `#ffb044` | `tertiary-container/20` | `tertiary` `#ffd5a5` |
| Medium | `tertiary` `#ffd5a5` | `tertiary/15` | `tertiary` `#ffd5a5` |
| Low | `secondary` `#adc6ff` | `secondary/15` | `secondary` `#adc6ff` |

Inconsistencies in the exports:
- **Low**: dashboard legend and donut (01) use `secondary-container` `#0566d9`; 02 and 03 use `secondary` `#adc6ff`.
  **Decided:** `secondary` `#adc6ff` is the Low colour everywhere. `#0566d9` may be used only in dashboard charts, where extra contrast is needed.
- **High** text: 01 and 02 use `text-tertiary-container` `#ffb044`; 03 uses `text-tertiary` `#ffd5a5`.
  **Decided:** follow 03, `text-tertiary` `#ffd5a5` (as in the table above).
- **Critical** text: 01 and 02 use `text-error` `#ffb4ab`; 03 uses `text-on-error-container` `#ffdad6`.
  **Decided:** follow 03, `text-on-error-container` `#ffdad6` (as in the table above).
- High (`#ffb044`) and Medium (`#ffd5a5`) are both amber. They are hard to tell apart by colour, which is another reason the text label is required.
- Suppressed / false-positive rows: `bg-surface-container text-on-surface-variant line-through`, dot `outline` `#859587`.

### Novel badge

**Decided:** use the green badge: `bg-primary-container text-on-primary-container`,
`auto_awesome` icon, label "Novel" or "Novel ML" (as in 02, 03, 07).
The grey-blue version from the Model page (06) (`bg-surface-container-highest text-secondary`, label "NOVEL", no icon)
is kept only where a design specifically calls for it.

**When a finding is Novel:** `source === "ml"` (CONTRACT.md has no separate novel field).
If the backend later adds a dedicated novelty property, use that instead.

### Supporting palette (full Stitch set)

| Token | Hex |
|---|---|
| `secondary` / `secondary-fixed-dim` | `#adc6ff` |
| `secondary-container` | `#0566d9` |
| `on-secondary-container` | `#e6ecff` |
| `secondary-fixed` | `#d8e2ff` |
| `on-secondary` | `#002e6a` |
| `on-secondary-fixed` | `#001a42` |
| `on-secondary-fixed-variant` | `#004395` |
| `tertiary` | `#ffd5a5` |
| `tertiary-container` | `#ffb044` |
| `tertiary-fixed-dim` | `#ffb95f` |
| `tertiary-fixed` | `#ffddb8` |
| `on-tertiary` | `#472a00` |
| `on-tertiary-container` | `#6f4500` |
| `on-tertiary-fixed` | `#2a1700` |
| `on-tertiary-fixed-variant` | `#653e00` |
| `error` | `#ffb4ab` |
| `error-container` | `#93000a` |
| `on-error` | `#690005` |
| `on-error-container` | `#ffdad6` |
| `on-primary-fixed` | `#00210f` |
| `on-primary-fixed-variant` | `#00522d` |
| `inverse-surface` | `#dfe2ee` |
| `inverse-on-surface` | `#2c3039` |

### Print / report palette (05 document preview only)

The white report sheet in 05 uses hard-coded Tailwind slate/red/amber values,
not theme tokens. Use these only for the HTML/PDF export, never in the app UI.

| Role | Hex |
|---|---|
| Sheet background | `#ffffff` |
| Text | `#0f172a`, `#1e293b`, `#334155`, `#475569`, `#64748b` |
| Borders / dividers | `#e2e8f0`, `#cbd5e1`, `#f1f5f9` |
| Row tint | `#f8fafc` |
| Critical | text/dot `#dc2626`; tag `#fee2e2` bg, `#991b1b` text; callout `#fef2f2` / `#fca5a5` / `#7f1d1d` |
| High | text/dot `#d97706`; tag `#fef3c7` bg, `#92400e` text |
| Medium | text/dot `#2563eb` (blue here, not amber) |
| Low | text `#475569`, dot `#94a3b8` |
| Fix / success | `#059669`, `#f0fdf4`, `#bbf7d0`, `#166534`, `#14532d` |

## Fonts

From the Google Fonts links in every export:

- **Inter** 400 / 500 / 600 / 700: UI text and headings
- **JetBrains Mono** 400 / 500 / 600: labels, badges, code, file paths, numbers
- **Material Symbols Outlined** (variable `wght 100..700`, `FILL 0..1`): icons, usually `text-lg` / `text-base`

## Type scale

| Token | Family | Size | Line height | Tracking | Weight |
|---|---|---|---|---|---|
| `headline-xl` | Inter | 2.25rem (36px) | 2.75rem | -0.025em | 600 |
| `headline-lg` | Inter | 1.75rem (28px) | 2.25rem | -0.02em | 600 |
| `headline-md` | Inter | 1.25rem (20px) | 1.75rem | -0.015em | 600 |
| `headline-sm` | Inter | 1rem (16px) | 1.5rem | -0.01em | 600 |
| `body-lg` | Inter | 1rem (16px) | 1.625rem | -0.005em | 400 |
| `body-md` | Inter | 0.875rem (14px) | 1.375rem | 0 | 400 |
| `body-sm` | Inter | 0.75rem (12px) | 1.125rem | 0.01em | 400 |
| `label-code-lg` | JetBrains Mono | 0.875rem (14px) | 1.375rem | -0.01em | 500 |
| `label-code-md` | JetBrains Mono | 0.75rem (12px) | 1.125rem | 0 | 500 |
| `label-code-sm` | JetBrains Mono | 0.6875rem (11px) | 1rem | 0.025em | 600 |

Applied as a pair: `font-label-code-sm text-label-code-sm`. Body default is `body-md`.
`label-code-sm` is by far the most used (500+ uses). The exports also use stock
Tailwind sizes (`text-xs/sm/base/lg/xl/2xl`) plus `text-[10px]`, `text-[11px]` and
`text-[0.625rem]`; map those to the scale above when rebuilding.

## Spacing

| Token | Value |
|---|---|
| `space-xs` | 0.25rem (4px) |
| `space-sm` | 0.5rem (8px) |
| `space-md` | 1rem (16px) |
| `space-lg` | 1.5rem (24px) |
| `space-xl` | 2rem (32px) |
| `gutter` / `margin` | 1rem (16px) |
| `gutter-desktop` | 1.5rem (24px): `main` horizontal padding |
| `margin-desktop` | 2rem (32px) |

Layout: fixed sidebar `w-64` (256px), fixed top bar `h-16` (64px), content `pl-64 pt-16`.

## Radius

| Token | Value | Used for |
|---|---|---|
| `DEFAULT` (`rounded`) | 0.25rem (4px) | Badges, chips, tags |
| `lg` | 0.5rem (8px) | Buttons, inputs, nav items |
| `xl` | 0.75rem (12px) | Cards / panels |
| `full` | 9999px | Dots, avatars, pills |

`rounded-md` and `rounded-sm` appear a handful of times (stock Tailwind values, not in the config). Treat them as `lg` and `DEFAULT`.

## Elevation

| Value | Used for |
|---|---|
| `shadow-sm` | Cards (most common) |
| `shadow-md` | Raised cards |
| `0 1px 8px rgba(0,0,0,0.4)` | Sidebar |
| `0 1px 8px rgba(0,0,0,0.3)` | Top bar |
