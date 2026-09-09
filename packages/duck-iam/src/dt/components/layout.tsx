/**
 * The shared skeleton every devtools panel is built from: a list on the left, a
 * detail pane on the right, and the filter / section / empty-state pieces that
 * go inside them.
 *
 * Factored out because five of the six panels are the same shape, and a panel
 * that reuses this one gets keyboard and overflow behaviour right for free
 * rather than re-deriving it. Purely presentational - each export does what its
 * name says.
 */
import React from 'react'
import { ChevronDown, ChevronRight, Search } from './icons'

/**
 * The two-pane frame the panels sit in: a fixed 300px list beside a fluid
 * detail pane, both scrolling independently, stacking to rows under 720px so a
 * panel docked to a narrow left or right edge stays usable.
 *
 * It carries the `iam-dt` root class as well as the layout one. Every panel is
 * exported individually from `./dt`, so a panel mounted on its own has no
 * ancestor to inherit the theme tokens from; the stylesheet only declares them
 * on the *outermost* `.iam-dt`, so the duplicate under `IamDevtools` is inert.
 */
export function SplitView({ left, right }: { left: React.ReactNode; right: React.ReactNode }) {
  return (
    <div className="iam-dt iam-dt-split">
      <aside className="iam-dt-split__aside">{left}</aside>
      <section className="iam-dt-split__main">{right}</section>
    </div>
  )
}

/** A scrolling list under a fixed header carrying its title, item count and toolbar - so the header stays put while the list moves. */
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

/**
 * One selectable row.
 *
 * `active` is the caller's selection state, not internal: the panels keep the
 * selected id, so the list stays consistent when the underlying data reloads.
 * It is mirrored onto `aria-current`, so the selected row is announced as such
 * and not merely tinted.
 */
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

/**
 * A collapsible block in a detail pane.
 *
 * Open state is internal and seeded once from `defaultOpen`, so a re-render
 * from polling cannot snap a section the reader opened back shut. The toggle
 * reports `aria-expanded` and owns the body through `aria-controls`, so the
 * disclosure is navigable rather than just clickable.
 */
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

/** The centred placeholder shown in a detail pane before anything is selected. */
export function DetailEmpty({ message }: { message: string }) {
  return <div className="iam-dt-empty iam-dt-empty--fill">{message}</div>
}

/**
 * The search input above a list.
 *
 * Fully controlled - the panel owns the filter string, since it also decides
 * what filtering means for its own data. `type="search"` so the browser offers
 * its clear affordance, and the placeholder is mirrored into `aria-label`,
 * because a placeholder alone is not a label.
 */
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
