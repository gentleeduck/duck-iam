import React from 'react'

/** Where a dockable devtools panel can attach: the shared shape behind v1's `PanelPosition` and v2's `IamV2PanelPosition`. */
export type IamDockPosition = 'top' | 'bottom' | 'left' | 'right'

/** Dock positions, in the order the dock button cycles through them. */
const POSITIONS: readonly IamDockPosition[] = ['bottom', 'right', 'top', 'left']

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

function saveState(key: string, value: unknown): void {
  if (typeof window === 'undefined') return
  try {
    window.localStorage.setItem(key, JSON.stringify(value))
  } catch {
    // Private-mode quota or a blocked origin: losing the preference is fine, throwing from an effect is not.
  }
}

function isBoolean(value: unknown): value is boolean {
  return typeof value === 'boolean'
}

function isPositiveFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value > 0
}

function isDockPosition(value: unknown): value is IamDockPosition {
  return typeof value === 'string' && POSITIONS.some((position) => position === value)
}

/** Max panel size along the dock axis: `fraction` of the viewport, at least `minSize`, and `defaultSize` under SSR. */
function viewportLimit(position: IamDockPosition, minSize: number, fraction: number, defaultSize: number): number {
  if (typeof window === 'undefined') return defaultSize
  const axis = position === 'left' || position === 'right' ? window.innerWidth : window.innerHeight
  return Math.max(minSize, axis * fraction)
}

export interface IamDockablePanelOptions {
  /** `localStorage` key prefix; combined with `_OPEN`/`_SIZE`/`positionKeySuffix`. */
  storagePrefix: string
  /** Suffix for the persisted position key - v1 devtools used `_POSITION`, v2 uses `_DOCK`. */
  positionKeySuffix: string
  initialIsOpen: boolean
  positionProp: IamDockPosition | undefined
  defaultSize: number
  minSize: number
  /** Fraction of the viewport's cross-axis the panel may grow to. */
  maxSizeFraction: number
  /** How far one arrow key nudges the resize edge; Page Up/Down move ten times that. */
  keyResizeStep: number
}

/**
 * Shared state behind the floating launcher + dockable, resizable, persisted panel shell used by both v1's
 * `IamDevtools` and v2's `IamDevtoolsV2`: open/size/dock persisted to `localStorage`, drag-to-resize, keyboard
 * resize, dock cycling and Escape-to-close. Each caller keeps its own open/close *animation* on top of
 * `open`/`setOpen` - v1 sequences mount/animate-in/animate-out, v2 has none - since that is the one place
 * the two shells genuinely differ.
 */
export function useIamDockablePanel(options: IamDockablePanelOptions) {
  const {
    defaultSize,
    initialIsOpen,
    keyResizeStep,
    maxSizeFraction,
    minSize,
    positionKeySuffix,
    positionProp,
    storagePrefix,
  } = options

  const openKey = `${storagePrefix}_OPEN`
  const sizeKey = `${storagePrefix}_SIZE`
  const positionKey = `${storagePrefix}${positionKeySuffix}`

  const [open, setOpen] = React.useState<boolean>(() => loadState(openKey, isBoolean, initialIsOpen))
  const [size, setSize] = React.useState<number>(() => loadState(sizeKey, isPositiveFiniteNumber, defaultSize))
  const [position, setPosition] = React.useState<IamDockPosition>(() =>
    loadState(positionKey, isDockPosition, positionProp ?? 'bottom'),
  )
  const [maxSize, setMaxSize] = React.useState<number>(() =>
    viewportLimit(positionProp ?? 'bottom', minSize, maxSizeFraction, defaultSize),
  )
  const dragRef = React.useRef<{ start: number; size: number; axis: 'x' | 'y' } | null>(null)
  const launcherRef = React.useRef<HTMLButtonElement | null>(null)
  const panelRef = React.useRef<HTMLDivElement | null>(null)

  React.useEffect(() => saveState(openKey, open), [open, openKey])
  React.useEffect(() => saveState(sizeKey, size), [size, sizeKey])
  React.useEffect(() => saveState(positionKey, position), [position, positionKey])
  React.useEffect(() => {
    if (positionProp) setPosition(positionProp)
  }, [positionProp])

  React.useEffect(() => {
    const update = () => setMaxSize(viewportLimit(position, minSize, maxSizeFraction, defaultSize))
    update()
    window.addEventListener('resize', update)
    return () => window.removeEventListener('resize', update)
  }, [position, minSize, maxSizeFraction, defaultSize])

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

  const clampSize = React.useCallback(
    (next: number) => Math.max(minSize, Math.min(viewportLimit(position, minSize, maxSizeFraction, defaultSize), next)),
    [position, minSize, maxSizeFraction, defaultSize],
  )

  const isHorizontal = position === 'left' || position === 'right'

  const onDragStart = (e: React.PointerEvent) => {
    const axis: 'x' | 'y' = isHorizontal ? 'x' : 'y'
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
    } catch {
      // Capture was never taken, or the element is already detached.
    }
  }

  // Keyboard resizing for the focusable `separator`; which arrow grows the panel depends on the dock edge.
  const onResizeKeyDown = (e: React.KeyboardEvent) => {
    const grows = position === 'bottom' || position === 'right' ? -1 : 1
    const step = e.key === 'PageUp' || e.key === 'PageDown' ? keyResizeStep * 10 : keyResizeStep
    let dir = 0
    if (e.key === 'ArrowUp' || e.key === 'ArrowLeft' || e.key === 'PageUp') dir = grows
    else if (e.key === 'ArrowDown' || e.key === 'ArrowRight' || e.key === 'PageDown') dir = -grows
    else if (e.key === 'Home') {
      e.preventDefault()
      return setSize(clampSize(minSize))
    } else if (e.key === 'End') {
      e.preventDefault()
      return setSize(clampSize(Number.POSITIVE_INFINITY))
    }
    if (dir === 0) return
    e.preventDefault()
    setSize((current) => clampSize(current + dir * step))
  }

  const cycleDock = () => {
    const idx = POSITIONS.indexOf(position)
    const next = POSITIONS[(idx + 1) % POSITIONS.length]
    // The modulo keeps this defined; the check satisfies `noUncheckedIndexedAccess`.
    if (next !== undefined) setPosition(next)
  }

  return {
    cycleDock,
    isHorizontal,
    launcherRef,
    maxSize,
    onDragEnd,
    onDragMove,
    onDragStart,
    onResizeKeyDown,
    open,
    panelRef,
    position,
    setOpen,
    size,
  }
}
