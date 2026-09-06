/**
 * The icons the devtools use, hand-inlined as SVG.
 *
 * A devtools panel that pulled in an icon package would put that package in the
 * dependency tree of every consumer of `@gentleduck/iam`, for artwork most
 * builds drop entirely. Each is a plain component over the shared `base`
 * stroke attributes at a default 12px (`Close` at 14). Each carries a single line saying what
 * it marks rather than what it draws - the glyph is evident from the name, the
 * meaning it carries in a trace is not. {@link Dot} and {@link Spinner} break
 * the shared pattern and say why.
 */
import type { CSSProperties } from 'react'

interface IconProps {
  size?: number
  className?: string
  style?: CSSProperties
}

/**
 * Every icon here is decorative - each sits beside the text that carries the
 * meaning, or inside a control that has its own label - so all of them are
 * hidden from assistive technology and taken out of the tab order rather than
 * being announced as unnamed graphics.
 */
const base = {
  'aria-hidden': true,
  fill: 'none',
  focusable: 'false' as const,
  stroke: 'currentColor',
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
  strokeWidth: 1.5,
}

/** Disclosure caret, expanded state. */
export function ChevronDown({ size = 12, className, style }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" {...base} className={className} style={style}>
      <path d="M3 6l5 5 5-5" />
    </svg>
  )
}

/** Disclosure caret, collapsed state. */
export function ChevronRight({ size = 12, className, style }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" {...base} className={className} style={style}>
      <path d="M6 3l5 5-5 5" />
    </svg>
  )
}

/** Dismiss affordance - the panel's own close control. */
export function Close({ size = 14, className, style }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" {...base} className={className} style={style}>
      <path d="M3 3l10 10M13 3L3 13" />
    </svg>
  )
}

/** Re-read affordance on panels that load from the engine on demand. */
export function Refresh({ size = 12, className, style }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" {...base} className={className} style={style}>
      <path d="M13.5 7a5.5 5.5 0 1 0-1.5 4M13.5 3v4h-4" />
    </svg>
  )
}

/** Magnifier, rendered inside {@link FilterBar}'s input rather than beside it. */
export function Search({ size = 12, className, style }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" {...base} className={className} style={style}>
      <circle cx="7" cy="7" r="4.5" />
      <path d="M10.5 10.5L14 14" />
    </svg>
  )
}

/** Forward/step marker in the decision trace. */
export function ArrowRight({ size = 12, className, style }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" {...base} className={className} style={style}>
      <path d="M3 8h10M9 4l4 4-4 4" />
    </svg>
  )
}

/** Inheritance marker in the Roles panel: the arrow before a role's `inherits` list. */
export function CornerUpRight({ size = 12, className, style }: IconProps) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" {...base} className={className} style={style}>
      <path d="M3 12V6a2 2 0 0 1 2-2h8M10 1l4 3-4 3" />
    </svg>
  )
}

/** The odd one out: a filled circle, so it takes none of the shared `base` stroke attributes and defaults to 4px rather than 12. */
export function Dot({ size = 4, className, style }: IconProps) {
  return (
    <svg aria-hidden focusable="false" width={size} height={size} viewBox="0 0 4 4" className={className} style={style}>
      <circle cx="2" cy="2" r="2" fill="currentColor" />
    </svg>
  )
}

/**
 * The one animated icon. Spins via the `.iam-dt-spin` class from
 * `lib/styles.ts` rather than an inline `animation`, which it used to
 * duplicate - two copies of the same 0.9s timing that could drift apart.
 */
export function Spinner({ size = 12, className, style }: IconProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 16 16"
      {...base}
      className={className ? `iam-dt-spin ${className}` : 'iam-dt-spin'}
      style={style}>
      <path d="M8 1.5a6.5 6.5 0 1 1-6.5 6.5" />
    </svg>
  )
}
