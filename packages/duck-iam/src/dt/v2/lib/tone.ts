/**
 * The one place v2 decides what a verdict looks like.
 *
 * v1 owns its whole palette as `--iam-dt-*` custom properties, so it renders
 * identically wherever it is mounted. v2 makes the opposite trade on purpose:
 * chrome - surfaces, borders, body text, focus rings - comes from the host's
 * duck-ui tokens (`bg-card`, `border-border`, `text-muted-foreground`, `ring`),
 * so the panel looks like the app it is docked into rather than like a
 * foreign window.
 *
 * Semantic colour cannot come from there. duck-ui ships `destructive` and
 * `warning` but has no success token, and "the rule allowed this" is not a
 * shade a theme gets to reinterpret - an allow that renders in the host's
 * primary hue is unreadable next to a deny that renders in the same one. So
 * the five decision tones below are pinned to Tailwind's own palette, which
 * exists in every Tailwind build without the host defining anything, and each
 * carries a `dark:` partner so it stays legible on both grounds.
 */
export type IamV2Tone = 'allow' | 'deny' | 'warn' | 'info' | 'neutral'

/** Border + fill + text, for a badge or a pill that must read as a verdict. */
const CHIP: Record<IamV2Tone, string> = {
  allow: 'border-emerald-600/35 bg-emerald-500/10 text-emerald-700 dark:border-emerald-400/35 dark:text-emerald-300',
  deny: 'border-destructive/40 bg-destructive/10 text-destructive',
  info: 'border-sky-600/35 bg-sky-500/10 text-sky-700 dark:border-sky-400/35 dark:text-sky-300',
  neutral: 'border-border bg-muted text-muted-foreground',
  warn: 'border-amber-600/35 bg-amber-500/10 text-amber-700 dark:border-amber-400/35 dark:text-amber-300',
}

/** Text only, for a value rendered inline in a sentence. */
const TEXT: Record<IamV2Tone, string> = {
  allow: 'text-emerald-700 dark:text-emerald-300',
  deny: 'text-destructive',
  info: 'text-sky-700 dark:text-sky-300',
  neutral: 'text-muted-foreground',
  warn: 'text-amber-700 dark:text-amber-300',
}

/** Solid fill, for the 6px status dot on a list row or a tab. */
const DOT: Record<IamV2Tone, string> = {
  allow: 'bg-emerald-500',
  deny: 'bg-destructive',
  info: 'bg-sky-500',
  neutral: 'bg-muted-foreground/40',
  warn: 'bg-amber-500',
}

/**
 * The filled part of a duck-ui `Progress`.
 *
 * `Progress` paints its indicator `bg-primary` and exposes no slot for it, so
 * the tone is applied through the child selector. Same colours as {@link DOT},
 * separately named because the two would drift the moment either grew a
 * variant the other did not need.
 */
const TRACK: Record<IamV2Tone, string> = {
  allow: '[&>div]:bg-emerald-500',
  deny: '[&>div]:bg-destructive',
  info: '[&>div]:bg-sky-500',
  neutral: '[&>div]:bg-muted-foreground/40',
  warn: '[&>div]:bg-amber-500',
}

/** Border, fill and text for a `tone`. */
export function iamV2Chip(tone: IamV2Tone): string {
  return CHIP[tone]
}

/** Text colour alone for a `tone`. */
export function iamV2Text(tone: IamV2Tone): string {
  return TEXT[tone]
}

/** Solid background for a `tone`, for status dots. */
export function iamV2Dot(tone: IamV2Tone): string {
  return DOT[tone]
}

/** Indicator fill for a `tone`, for a `Progress` bar. */
export function iamV2Track(tone: IamV2Tone): string {
  return TRACK[tone]
}

/** The tone a boolean verdict renders in. */
export function iamV2Decision(allowed: boolean): IamV2Tone {
  return allowed ? 'allow' : 'deny'
}

/**
 * Syntax colours for the two halves of a request. An action and a resource
 * type sit next to each other on nearly every row in the devtool, and reading
 * `read on post` as two words rather than one phrase is most of what makes the
 * flow list scannable.
 */
export const IAM_V2_ACTION = 'text-sky-700 dark:text-sky-300'
export const IAM_V2_RESOURCE = 'text-orange-700 dark:text-orange-300'
/** Monospace run used for every id, action, resource and rule name. */
export const IAM_V2_MONO = 'font-mono text-[0.8125rem] leading-tight'
