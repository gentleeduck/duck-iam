/**
 * The devtools' own control set - a card with a title slot, a button at the
 * sizes these panels use, the form controls, the status pill.
 *
 * They used to be thin wrappers over `@gentleduck/registry-ui` carrying
 * Tailwind utility classes. Both halves of that were wrong for a published
 * package: `@gentleduck/registry-ui` is an *optional* peer, so importing
 * `@gentleduck/iam/dt` without it threw at module load, and the utilities only
 * name real CSS if the consumer's Tailwind happens to scan this package's
 * `dist`. These are plain elements over the `iam-dt-*` classes in
 * `lib/styles.ts`, which the devtools inject themselves - so they look the same
 * in a consumer's app as they do in this monorepo.
 *
 * Each is presentational and does what its name says; anything with behaviour
 * worth knowing about says so on the export.
 */
import type React from 'react'
import { cn } from '../lib/cn'

/** A titled box. Header renders only when there is a `title` or `actions` to put in it, so an untitled card is just a bordered body. */
export function Card({
  title,
  children,
  actions,
}: {
  title?: string
  children: React.ReactNode
  actions?: React.ReactNode
}) {
  return (
    <div className="iam-dt-card">
      {(title || actions) && (
        <div className="iam-dt-card__head">
          {title && <span className="iam-dt-card__title">{title}</span>}
          {actions}
        </div>
      )}
      <div className="iam-dt-card__body">{children}</div>
    </div>
  )
}

const BUTTON_VARIANT = {
  danger: 'iam-dt-btn--danger',
  default: '',
  ghost: 'iam-dt-btn--ghost',
  primary: 'iam-dt-btn--primary',
} as const

/**
 * A button at the sizes these panels use.
 *
 * `type` defaults to `'button'`, so one inside a panel form cannot submit it by
 * accident. `title` and `aria-label` are passed through because several call
 * sites render an icon alone, which is unreadable to a screen reader without
 * one.
 */
export function Button({
  children,
  onClick,
  variant = 'default',
  disabled,
  type = 'button',
  className,
  title,
  'aria-label': ariaLabel,
}: {
  children: React.ReactNode
  onClick?: () => void
  variant?: keyof typeof BUTTON_VARIANT
  disabled?: boolean
  type?: 'button' | 'submit'
  className?: string
  title?: string
  'aria-label'?: string
}) {
  return (
    <button
      aria-label={ariaLabel}
      className={cn('iam-dt-btn', BUTTON_VARIANT[variant], className)}
      disabled={disabled}
      onClick={onClick}
      title={title}
      type={type}>
      {children}
    </button>
  )
}

/**
 * A labelled form row.
 *
 * The label is a real `<label>` wrapping its control rather than a `<span>`
 * beside it, so clicking the caption focuses the input and a screen reader
 * announces the two together - the panels label every field this way and none
 * of them were associated before.
 */
export function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    // biome-ignore lint/a11y/noLabelWithoutControl: the control is the `children` this wraps, which is an implicit association the rule cannot see through.
    <label className="iam-dt-field">
      <span className="iam-dt-field__label">{label}</span>
      {children}
    </label>
  )
}

/** An `input` at devtools scale. Passes every native prop through, so callers keep full control of the element. */
export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={cn('iam-dt-input', props.className)} />
}

/** A monospaced `textarea`, for the JSON the Decision Inspector and Subjects panel take as free text. */
export function TextArea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...props} className={cn('iam-dt-textarea', props.className)} />
}

const BADGE_TONE = {
  allow: 'iam-dt-badge--allow',
  deny: 'iam-dt-badge--deny',
  info: 'iam-dt-badge--info',
  neutral: '',
  warn: 'iam-dt-badge--warn',
} as const

/**
 * A small status pill. `tone` is semantic rather than a colour: `'allow'` and
 * `'deny'` are the two the panels lean on, and they read the same here as in
 * the trace tree and the flow log, so a green pill means the same thing
 * wherever it appears.
 */
export function Badge({
  children,
  tone = 'neutral',
  className,
}: {
  children: React.ReactNode
  tone?: keyof typeof BADGE_TONE
  className?: string
}) {
  return <span className={cn('iam-dt-badge', BADGE_TONE[tone], className)}>{children}</span>
}

/** The dashed placeholder for a list with nothing in it - distinct from {@link DetailEmpty}, which fills a detail pane. */
export function Empty({ message }: { message: string }) {
  return <div className="iam-dt-empty iam-dt-empty--dashed">{message}</div>
}

/**
 * An inline error or success banner, used for the results of the writes the
 * Subjects panel makes.
 *
 * An error carries `role="alert"`, so a failed save is announced rather than
 * only drawn; a success is `role="status"`, which is polite enough not to
 * interrupt whatever the reader is doing.
 */
export function Alert({ kind, children }: { kind: 'error' | 'success'; children: React.ReactNode }) {
  return (
    <div
      className={cn('iam-dt-alert', kind === 'error' ? 'iam-dt-alert--error' : 'iam-dt-alert--success')}
      role={kind === 'error' ? 'alert' : 'status'}>
      {children}
    </div>
  )
}
