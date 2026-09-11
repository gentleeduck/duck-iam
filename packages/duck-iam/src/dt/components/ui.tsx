/**
 * The devtools' own controls: plain elements over the `iam-dt-*` classes in `lib/styles.ts`.
 * NOTE: no `@gentleduck/registry-ui` or Tailwind - both are optional for consumers of `./dt`.
 */
import type React from 'react'
import { cn } from '../lib/cn'

/** A titled box; the header renders only when there is a `title` or `actions`. */
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

/** A devtools button. `type` defaults to `'button'` so it never submits a surrounding form by accident. */
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

/** A form row whose `<label>` wraps its control, so clicking the caption focuses it and screen readers pair them. */
export function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    // biome-ignore lint/a11y/noLabelWithoutControl: the control is the `children` this wraps, which is an implicit association the rule cannot see through.
    <label className="iam-dt-field">
      <span className="iam-dt-field__label">{label}</span>
      {children}
    </label>
  )
}

/** An `input` at devtools scale; every native prop passes through. */
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

/** A small status pill. `tone` is semantic, so `allow` and `deny` look the same wherever they appear. */
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

/** Dashed placeholder for an empty list; {@link DetailEmpty} is the detail-pane version. */
export function Empty({ message }: { message: string }) {
  return <div className="iam-dt-empty iam-dt-empty--dashed">{message}</div>
}

/**
 * Inline result banner. Errors use `role="alert"` so they are announced; successes use the politer `role="status"`.
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
