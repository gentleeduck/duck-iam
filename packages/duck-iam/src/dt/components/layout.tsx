/** The two-pane skeleton the panels share: list, detail pane, and the filter, section and empty-state pieces. */
import React from 'react'
import { ChevronDown, ChevronRight, Search } from './icons'

/**
 * Two-pane frame: a 300px list beside a fluid detail pane, stacking into rows at 720px and below.
 * NOTE: carries the `iam-dt` root class so a panel mounted on its own still gets the theme tokens.
 */
export function SplitView({ left, right }: { left: React.ReactNode; right: React.ReactNode }) {
  return (
    <div className="iam-dt iam-dt-split">
      <aside className="iam-dt-split__aside">{left}</aside>
      <section className="iam-dt-split__main">{right}</section>
    </div>
  )
}

/** A scrolling list under a fixed header with its title, item count and toolbar. */
export function ListShell({
  title,
  count,
  toolbar,
  children,
}: {
  title?: string
  count?: number
  toolbar?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <div className="iam-dt-list">
      <div className="iam-dt-list__head">
        <div className="iam-dt-list__titles">
          {title && <h3 className="iam-dt-list__title">{title}</h3>}
          {typeof count === 'number' && <span className="iam-dt-list__count">{count}</span>}
        </div>
        {toolbar}
      </div>
      <div className="iam-dt-list__body">{children}</div>
    </div>
  )
}

/** One selectable row. `active` is owned by the caller and mirrored to `aria-current`. */
export function ListItem({
  active,
  onClick,
  dot,
  primary,
  secondary,
  trailing,
}: {
  active?: boolean
  onClick?: () => void
  dot?: string
  primary: React.ReactNode
  secondary?: React.ReactNode
  trailing?: React.ReactNode
}) {
  return (
    <button
      aria-current={active ? 'true' : undefined}
      className="iam-dt-item"
      data-active={active ? '1' : undefined}
      onClick={onClick}
      type="button">
      {dot && <span aria-hidden className="iam-dt-item__dot" style={{ backgroundColor: dot }} />}
      <span className="iam-dt-item__text">
        <span className="iam-dt-item__primary">{primary}</span>
        {secondary && <span className="iam-dt-item__secondary">{secondary}</span>}
      </span>
      {trailing}
    </button>
  )
}

/** A collapsible detail-pane block. Open state is seeded once from `defaultOpen`, so polling re-renders keep it. */
export function Section({
  title,
  defaultOpen = true,
  toolbar,
  children,
}: {
  title: string
  defaultOpen?: boolean
  toolbar?: React.ReactNode
  children: React.ReactNode
}) {
  const [open, setOpen] = React.useState(defaultOpen)
  const bodyId = React.useId()
  return (
    <div className="iam-dt-section">
      <div className="iam-dt-section__head">
        <button
          aria-controls={bodyId}
          aria-expanded={open}
          className="iam-dt-section__btn"
          onClick={() => setOpen((o) => !o)}
          type="button">
          <span aria-hidden className="iam-dt-section__chev">
            {open ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
          </span>
          <h4 className="iam-dt-section__title">{title}</h4>
        </button>
        {toolbar}
      </div>
      {open && (
        <div className="iam-dt-section__body" id={bodyId}>
          {children}
        </div>
      )}
    </div>
  )
}

/**
 * The compact collapsible row shared by every trace/rule/permission listing: a chevron-toggle header and a body
 * shown only while open. Distinct from {@link Section}, which is the titled top-level section header.
 */
export function CollapsibleGroup({
  summary,
  detail,
  defaultOpen = false,
  disabled = false,
}: {
  summary: React.ReactNode
  detail: React.ReactNode
  defaultOpen?: boolean
  disabled?: boolean
}) {
  const [open, setOpen] = React.useState(defaultOpen)
  return (
    <div className="iam-dt-trace__group">
      <button
        className="iam-dt-trace__group-head"
        disabled={disabled}
        onClick={() => !disabled && setOpen((o) => !o)}
        type="button">
        <span className="iam-dt-section__chev">{disabled ? null : open ? <ChevronDown /> : <ChevronRight />}</span>
        {summary}
      </button>
      {open && <div className="iam-dt-trace__group-body">{detail}</div>}
    </div>
  )
}

/** An optional blurb rendered in its own {@link Section}; renders nothing when `text` is absent. */
export function DescriptionSection({ text }: { text?: string }) {
  if (!text) return null
  return (
    <Section title="Description">
      <p className="iam-dt-soft" style={{ fontSize: 11 }}>
        {text}
      </p>
    </Section>
  )
}

/** The centred placeholder shown in a detail pane before anything is selected. */
export function DetailEmpty({ message }: { message: string }) {
  return <div className="iam-dt-empty iam-dt-empty--fill">{message}</div>
}

/** A detail pane's header bar once something is selected: id, name, and whatever badges the panel adds. */
export function DetailHead({ children }: { children: React.ReactNode }) {
  return <div className="iam-dt-detail__head">{children}</div>
}

/** Controlled search input above a list; the placeholder doubles as its `aria-label`. */
export function FilterBar({
  value,
  onChange,
  placeholder = 'Filter',
  trailing,
}: {
  value: string
  onChange: (v: string) => void
  placeholder?: string
  trailing?: React.ReactNode
}) {
  return (
    <div className="iam-dt-filter">
      <div className="iam-dt-filter__wrap">
        <Search className="iam-dt-filter__icon" size={11} />
        <input
          aria-label={placeholder}
          className="iam-dt-input"
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          type="search"
          value={value}
        />
      </div>
      {trailing}
    </div>
  )
}
