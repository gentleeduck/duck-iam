import React from 'react'
import { Close } from './components/icons'
import { Button } from './components/ui'
import { IamDevtoolsInner, type IIamDevtoolsInnerProps } from './iam-devtools'
import { cn } from './lib/cn'
import { isDevtoolsAllowed } from './lib/guard'
import { GENTLEDUCK_LOGO_DATA_URL } from './lib/logo'
import { iamDevtoolsThemeAttr, useIamDevtoolsStyles } from './lib/styles'

/** Where the floating launcher sits; `'relative'` renders it in normal flow, e.g. inside your own toolbar. */
export type ButtonPosition = 'bottom-right' | 'bottom-left' | 'top-right' | 'top-left' | 'relative'
/** Which edge the panel docks to. Cycled through by the dock button in `PANEL_POSITIONS` order. */
export type PanelPosition = 'top' | 'bottom' | 'left' | 'right'

/**
 * Props for `IamDevtools`: the launcher button plus the dockable panel around {@link IamDevtoolsInner}.
 * NOTE: give each instance on a page its own `storagePrefix`, or they share persisted open/dock/size state.
 */
export interface IIamDevtoolsProps extends IIamDevtoolsInnerProps {
  initialIsOpen?: boolean
  buttonPosition?: ButtonPosition
  position?: PanelPosition
  hideButton?: boolean
  storagePrefix?: string
  /** Floating gutter in px around the panel. 0 = flush edges (default). */
  inset?: number
}

const DEFAULT_SIZE = 500
const MIN_SIZE = 220
const MAX_SIZE_VW = 0.9
const ANIM_MS = 240
/** How far one arrow key nudges the resize edge; Page Up/Down move ten times that. */
const KEY_RESIZE_STEP = 16

/** Dock positions, in the order the dock button cycles through them. */
const PANEL_POSITIONS: readonly PanelPosition[] = ['bottom', 'right', 'top', 'left']

function isPanelPosition(value: unknown): value is PanelPosition {
  return typeof value === 'string' && PANEL_POSITIONS.some((position) => position === value)
}

function isBoolean(value: unknown): value is boolean {
  return typeof value === 'boolean'
}

function isPanelSize(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value > 0
}

/**
 * Reads one persisted panel preference, falling back when it is missing or fails `isValid`.
 * NOTE: localStorage is user-editable and outlives upgrades, so the parsed value is never trusted.
 */
function loadState<T>(key: string, isValid: (value: unknown) => value is T, fallback: T): T {
  if (typeof window === 'undefined') return fallback
  try {
    const raw = window.localStorage.getItem(key)
    if (raw == null) return fallback
    const parsed: unknown = JSON.parse(raw)
    return isValid(parsed) ? parsed : fallback
  } catch {
    return fallback
  }
}
function saveState(key: string, value: unknown) {
  if (typeof window === 'undefined') return
  try {
    window.localStorage.setItem(key, JSON.stringify(value))
  } catch {}
}

/** Max panel size along the dock axis: 90% of the viewport, at least `MIN_SIZE`, and `DEFAULT_SIZE` under SSR. */
function viewportLimit(position: PanelPosition): number {
  if (typeof window === 'undefined') return DEFAULT_SIZE
  const axis = position === 'left' || position === 'right' ? window.innerWidth : window.innerHeight
  return Math.max(MIN_SIZE, axis * MAX_SIZE_VW)
}

function panelSize(position: PanelPosition, size: number): React.CSSProperties {
  if (position === 'bottom' || position === 'top') return { height: size }
  return { width: size }
}

function panelHidden(position: PanelPosition): string {
  if (position === 'bottom') return 'translateY(100%)'
  if (position === 'top') return 'translateY(-100%)'
  if (position === 'right') return 'translateX(100%)'
  return 'translateX(-100%)'
}

// SECURITY: renders nothing unless `isDevtoolsAllowed` passes; no escape hatch (see lib/guard.ts).
// NOTE: the guard lives in this wrapper so the inner component's hook order stays unconditional.
export function IamDevtools(props: IIamDevtoolsProps) {
  if (!isDevtoolsAllowed(props.engine)) return null
  return <IamDevtoolsImpl {...props} />
}

function IamDevtoolsImpl({
  initialIsOpen = false,
  buttonPosition = 'bottom-right',
  position: positionProp,
  hideButton = false,
  storagePrefix = '__GENTLEDUCK_IAM_DEVTOOLS_V1',
  inset = 0,
  ...inner
}: IIamDevtoolsProps) {
  useIamDevtoolsStyles()

  const openKey = `${storagePrefix}_OPEN`
  const sizeKey = `${storagePrefix}_SIZE`
  const posKey = `${storagePrefix}_POSITION`

  const [open, setOpen] = React.useState<boolean>(() => loadState(openKey, isBoolean, initialIsOpen))
  const [mounted, setMounted] = React.useState<boolean>(() => loadState(openKey, isBoolean, initialIsOpen))
  const [animateIn, setAnimateIn] = React.useState<boolean>(false)
  const [size, setSize] = React.useState<number>(() => loadState(sizeKey, isPanelSize, DEFAULT_SIZE))
  const [position, setPosition] = React.useState<PanelPosition>(() =>
    loadState(posKey, isPanelPosition, positionProp ?? 'bottom'),
  )
  // Max panel size in px, held in state because the resize handle renders it as `aria-valuemax`.
  const [maxSize, setMaxSize] = React.useState<number>(() => viewportLimit(positionProp ?? 'bottom'))
  const dragRef = React.useRef<{ start: number; size: number; axis: 'x' | 'y' } | null>(null)
  const launcherRef = React.useRef<HTMLButtonElement | null>(null)
  const dockRef = React.useRef<HTMLDivElement | null>(null)
  const titleId = React.useId()

  React.useEffect(() => saveState(openKey, open), [open, openKey])
  React.useEffect(() => saveState(sizeKey, size), [size, sizeKey])
  React.useEffect(() => saveState(posKey, position), [position, posKey])
  React.useEffect(() => {
    if (positionProp) setPosition(positionProp)
  }, [positionProp])

  React.useEffect(() => {
    const update = () => setMaxSize(viewportLimit(position))
    update()
    window.addEventListener('resize', update)
    return () => window.removeEventListener('resize', update)
  }, [position])

  React.useEffect(() => {
    let raf = 0
    let timeout = 0
    if (open) {
      setMounted(true)
      raf = requestAnimationFrame(() => {
        raf = requestAnimationFrame(() => setAnimateIn(true))
      })
    } else {
      setAnimateIn(false)
      timeout = window.setTimeout(() => setMounted(false), ANIM_MS)
    }
    return () => {
      cancelAnimationFrame(raf)
      window.clearTimeout(timeout)
    }
  }, [open])

  // Escape closes the panel and refocuses the launcher. Listens on `document`, since focus may be anywhere.
  React.useEffect(() => {
    if (!open) return
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return
      setOpen(false)
      launcherRef.current?.focus()
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [open])

  // Opening moves focus into the panel, so the next Tab lands on the dock and
  // close controls rather than back at the top of the host page.
  React.useEffect(() => {
    if (open && mounted) dockRef.current?.focus()
  }, [open, mounted])

  const clampSize = React.useCallback(
    (next: number) => Math.max(MIN_SIZE, Math.min(viewportLimit(position), next)),
    [position],
  )

  const onDragStart = (e: React.PointerEvent) => {
    const axis: 'x' | 'y' = position === 'left' || position === 'right' ? 'x' : 'y'
    dragRef.current = { axis, size, start: axis === 'x' ? e.clientX : e.clientY }
    if (e.target instanceof Element) e.target.setPointerCapture(e.pointerId)
  }
  const onDragMove = (e: React.PointerEvent) => {
    const d = dragRef.current
    if (!d) return
    const delta = (d.axis === 'x' ? e.clientX : e.clientY) - d.start
    const sign = position === 'bottom' || position === 'right' ? -1 : 1
    setSize(clampSize(d.size + sign * delta))
  }
  const onDragEnd = (e: React.PointerEvent) => {
    dragRef.current = null
    try {
      if (e.target instanceof Element) e.target.releasePointerCapture(e.pointerId)
    } catch {}
  }

  // Keyboard resizing for the focusable `separator`; which arrow grows the panel depends on the dock edge.
  const onResizeKeyDown = (e: React.KeyboardEvent) => {
    const grows = position === 'bottom' || position === 'right' ? -1 : 1
    const step = e.key === 'PageUp' || e.key === 'PageDown' ? KEY_RESIZE_STEP * 10 : KEY_RESIZE_STEP
    let dir = 0
    if (e.key === 'ArrowUp' || e.key === 'ArrowLeft' || e.key === 'PageUp') dir = grows
    else if (e.key === 'ArrowDown' || e.key === 'ArrowRight' || e.key === 'PageDown') dir = -grows
    else if (e.key === 'Home') {
      e.preventDefault()
      return setSize(clampSize(MIN_SIZE))
    } else if (e.key === 'End') {
      e.preventDefault()
      return setSize(clampSize(Number.POSITIVE_INFINITY))
    }
    if (dir === 0) return
    e.preventDefault()
    setSize((current) => clampSize(current + dir * step))
  }

  const cycleDock = () => {
    const idx = PANEL_POSITIONS.indexOf(position)
    const next = PANEL_POSITIONS[(idx + 1) % PANEL_POSITIONS.length]
    // `noUncheckedIndexedAccess` types the index as possibly undefined; the modulo keeps it defined, so no cast.
    if (next !== undefined) setPosition(next)
  }

  const isHorizontal = position === 'left' || position === 'right'
  const themeAttr = iamDevtoolsThemeAttr(inner.theme)

  return (
    <>
      {!hideButton && buttonPosition !== 'relative' && (
        <div className={cn('iam-dt', 'iam-dt-btn-wrap')} data-iam-dt-theme={themeAttr} data-pos={buttonPosition}>
          <button
            aria-expanded={open}
            aria-label="Open duck-iam devtools"
            className="iam-dt-launch"
            data-hidden={open ? '1' : undefined}
            onClick={() => setOpen(true)}
            ref={launcherRef}
            type="button">
            <img alt="" draggable={false} src={GENTLEDUCK_LOGO_DATA_URL} />
          </button>
        </div>
      )}

      {mounted && (
        <div
          className={cn('iam-dt', 'iam-dt-panel-wrap')}
          data-iam-dt-theme={themeAttr}
          data-inset={inset > 0 ? '1' : undefined}
          data-pos={position}
          style={{
            opacity: animateIn ? 1 : 0,
            transform: animateIn ? 'translate(0,0)' : panelHidden(position),
            ...panelSize(position, size),
          }}>
          <div
            aria-labelledby={titleId}
            className="iam-dt-dock"
            data-flush={inset === 0 ? position : undefined}
            data-inset={inset > 0 ? '1' : undefined}
            ref={dockRef}
            role="dialog"
            tabIndex={-1}>
            {/* biome-ignore lint/a11y/useSemanticElements: `<hr>` is the thematic-break separator; this is the focusable window-splitter variant of the role, which has no element form. */}
            <div
              aria-label="Resize devtools panel"
              aria-orientation={isHorizontal ? 'vertical' : 'horizontal'}
              aria-valuemax={Math.round(maxSize)}
              aria-valuemin={MIN_SIZE}
              aria-valuenow={Math.round(size)}
              className={cn('iam-dt-resize', isHorizontal ? 'iam-dt-resize--ew' : 'iam-dt-resize--ns')}
              onKeyDown={onResizeKeyDown}
              onPointerCancel={onDragEnd}
              onPointerDown={onDragStart}
              onPointerMove={onDragMove}
              onPointerUp={onDragEnd}
              role="separator"
              tabIndex={0}
            />
            <header className="iam-dt-header">
              <div className="iam-dt-header__brand">
                <span className="iam-dt-header__logo">
                  <img alt="" draggable={false} src={GENTLEDUCK_LOGO_DATA_URL} />
                </span>
                <span className="iam-dt-header__names">
                  <span className="iam-dt-header__title" id={titleId}>
                    duck-iam
                  </span>
                  <span className="iam-dt-header__sub">devtools</span>
                </span>
                <span className="iam-dt-live">
                  <span aria-hidden className="iam-dt-live__dot" />
                  live
                </span>
              </div>
              <div className="iam-dt-header__actions">
                <Button
                  className="iam-dt-btn--dock"
                  onClick={cycleDock}
                  title={`Docked ${position} - click to move`}
                  variant="default">
                  {position}
                </Button>
                <Button
                  aria-label="Close devtools"
                  className="iam-dt-btn--icon"
                  onClick={() => {
                    setOpen(false)
                    launcherRef.current?.focus()
                  }}
                  title="Close devtools (Esc)">
                  <Close size={12} />
                </Button>
              </div>
            </header>
            <div className="iam-dt-body">
              <IamDevtoolsInner {...inner} embedded />
            </div>
          </div>
        </div>
      )}
    </>
  )
}
