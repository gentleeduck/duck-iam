'use client'

import { cn } from '@gentleduck/libs/cn'
import { Badge } from '@gentleduck/registry-ui/badge'
import { Button } from '@gentleduck/registry-ui/button'
import { Kbd } from '@gentleduck/registry-ui/kbd'
import { Separator } from '@gentleduck/registry-ui/separator'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@gentleduck/registry-ui/tooltip'
import { LayoutPanelLeft, ShieldCheck, X } from 'lucide-react'
import React from 'react'
import { isDevtoolsAllowed } from '../lib/guard'
import { IamV2Chip } from './components/chrome'
import { IamDevtoolsInnerV2, type IIamDevtoolsInnerV2Props } from './iam-devtools-inner-v2'

/** Where the floating launcher sits. `'relative'` drops it into normal flow, for a toolbar of your own. */
export type IamV2ButtonPosition = 'bottom-right' | 'bottom-left' | 'top-right' | 'top-left' | 'relative'
/** Which edge the panel docks to. Cycled through in {@link DOCKS} order. */
export type IamV2PanelPosition = 'top' | 'bottom' | 'left' | 'right'

/**
 * Props for `IamDevtoolsV2` - the launcher plus the dockable panel around
 * {@link IamDevtoolsInnerV2}. Extends the inner props, so everything the
 * panels need passes straight through.
 */
export interface IIamDevtoolsV2Props extends IIamDevtoolsInnerV2Props {
  buttonPosition?: IamV2ButtonPosition
  hideButton?: boolean
  initialIsOpen?: boolean
  position?: IamV2PanelPosition
  /** `localStorage` key prefix for the persisted open/dock/size state. Set it when two devtools share a page. */
  storagePrefix?: string
}

const DEFAULT_SIZE = 520
const MIN_SIZE = 260
const MAX_SIZE_FRACTION = 0.9
/** How far one arrow key nudges the resize edge; Page Up/Down move ten times that. */
const KEY_RESIZE_STEP = 16

/** Dock edges, in the order the dock button cycles through them. */
const DOCKS: readonly IamV2PanelPosition[] = ['bottom', 'right', 'top', 'left']

function isDock(value: unknown): value is IamV2PanelPosition {
  return typeof value === 'string' && DOCKS.some((dock) => dock === value)
}

function isBoolean(value: unknown): value is boolean {
  return typeof value === 'boolean'
}

function isSize(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value > 0
}

/**
 * Reads one persisted preference, validating what it finds.
 *
 * `localStorage` is editable, shared across every page of the origin and
 * survives an upgrade, so a stale entry can hold a string where a number
 * belongs (`NaN` into a CSS length collapses the panel) or an unknown dock
 * name (no matching placement, panel off-screen). Each reader proves the shape
 * it wants rather than trusting `JSON.parse`'s `any`.
 */
function loadState<T>(key: string, isValid: (value: unknown) => value is T, fallback: T): T {
  if (typeof window === 'undefined') return fallback
  try {
    const raw = window.localStorage.getItem(key)
    if (raw === null) return fallback
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
  } catch {
    // Private-mode quota or a blocked origin. Losing the preference is fine;
    // throwing out of an effect is not.
  }
}

/**
 * How large the panel may get on the axis its dock edge constrains. Falls back
 * to the default under SSR, where there is no viewport to measure.
 */
function viewportLimit(dock: IamV2PanelPosition): number {
  if (typeof window === 'undefined') return DEFAULT_SIZE
  const axis = dock === 'left' || dock === 'right' ? window.innerWidth : window.innerHeight
  return Math.max(MIN_SIZE, axis * MAX_SIZE_FRACTION)
}

/** Fixed placement for a dock edge. */
const DOCK_CLASS: Record<IamV2PanelPosition, string> = {
  bottom: 'inset-x-0 bottom-0 border-t',
  left: 'inset-y-0 left-0 border-r',
  right: 'inset-y-0 right-0 border-l',
  top: 'inset-x-0 top-0 border-b',
}

/** Where the resize handle sits, and which cursor it takes. */
const HANDLE_CLASS: Record<IamV2PanelPosition, string> = {
  bottom: 'inset-x-0 top-0 h-1.5 cursor-ns-resize',
  left: 'inset-y-0 right-0 w-1.5 cursor-ew-resize',
  right: 'inset-y-0 left-0 w-1.5 cursor-ew-resize',
  top: 'inset-x-0 bottom-0 h-1.5 cursor-ns-resize',
}

const LAUNCHER_CLASS: Record<Exclude<IamV2ButtonPosition, 'relative'>, string> = {
  'bottom-left': 'fixed bottom-4 left-4',
  'bottom-right': 'fixed right-4 bottom-4',
  'top-left': 'fixed top-4 left-4',
  'top-right': 'fixed top-4 right-4',
}

/**
 * Hard-no in production. No escape hatch - see `lib/guard.ts`. The guard sits
 * in a thin wrapper so the implementation's hook order stays unconditional.
 */
export function IamDevtoolsV2(props: IIamDevtoolsV2Props) {
  if (!isDevtoolsAllowed(props.engine)) return null
  return <Impl {...props} />
}

function Impl({
  buttonPosition = 'bottom-right',
  hideButton = false,
  initialIsOpen = false,
  position: positionProp,
  storagePrefix = '__GENTLEDUCK_IAM_DEVTOOLS_V2',
  ...inner
}: IIamDevtoolsV2Props) {
  const openKey = `${storagePrefix}_OPEN`
  const sizeKey = `${storagePrefix}_SIZE`
  const dockKey = `${storagePrefix}_DOCK`

  const [open, setOpen] = React.useState(() => loadState(openKey, isBoolean, initialIsOpen))
  const [size, setSize] = React.useState(() => loadState(sizeKey, isSize, DEFAULT_SIZE))
  const [dock, setDock] = React.useState<IamV2PanelPosition>(() => loadState(dockKey, isDock, positionProp ?? 'bottom'))
  /**
   * The largest the panel may grow to, in px.
   *
   * Held in state because the resize handle reports it as `aria-valuemax`: a
   * focusable `separator` is the window-splitter role, and a widget that
   * announces a position has to announce the scale it sits on. Recomputed when
   * the dock edge flips the limiting dimension and when the viewport changes;
   * seeded lazily so an SSR render never touches `window`.
   */
  const [maxSize, setMaxSize] = React.useState(() => viewportLimit(positionProp ?? 'bottom'))

  const drag = React.useRef<{ axis: 'x' | 'y'; size: number; start: number } | null>(null)
  const launcherRef = React.useRef<HTMLButtonElement | null>(null)
  const panelRef = React.useRef<HTMLDivElement | null>(null)
  const titleId = React.useId()

  React.useEffect(() => saveState(openKey, open), [open, openKey])
  React.useEffect(() => saveState(sizeKey, size), [size, sizeKey])
  React.useEffect(() => saveState(dockKey, dock), [dock, dockKey])
  React.useEffect(() => {
    if (positionProp) setDock(positionProp)
  }, [positionProp])

  React.useEffect(() => {
    const update = () => setMaxSize(viewportLimit(dock))
    update()
    window.addEventListener('resize', update)
    return () => window.removeEventListener('resize', update)
  }, [dock])

  /**
   * Escape closes the panel and hands focus back to the launcher.
   *
   * On `document` because focus may legitimately sit inside the panel, on the
   * launcher, or nowhere at all - and without it the only way out is to find
   * and click one small button, which for a keyboard user means tabbing
   * through every control in whichever panel is open.
   */
  React.useEffect(() => {
    if (!open) return
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return
      setOpen(false)
      launcherRef.current?.focus()
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [open])

  // Opening moves focus into the panel, so the next Tab lands on the dock and
  // close controls rather than back at the top of the host page.
  React.useEffect(() => {
    if (open) panelRef.current?.focus()
  }, [open])

  const clamp = React.useCallback((next: number) => Math.max(MIN_SIZE, Math.min(viewportLimit(dock), next)), [dock])

  const onPointerDown = (event: React.PointerEvent) => {
    const axis: 'x' | 'y' = dock === 'left' || dock === 'right' ? 'x' : 'y'
    drag.current = { axis, size, start: axis === 'x' ? event.clientX : event.clientY }
    if (event.target instanceof Element) event.target.setPointerCapture(event.pointerId)
  }
  const onPointerMove = (event: React.PointerEvent) => {
    const state = drag.current
    if (!state) return
    const delta = (state.axis === 'x' ? event.clientX : event.clientY) - state.start
    const sign = dock === 'bottom' || dock === 'right' ? -1 : 1
    setSize(clamp(state.size + sign * delta))
  }
  const onPointerUp = (event: React.PointerEvent) => {
    drag.current = null
    try {
      if (event.target instanceof Element) event.target.releasePointerCapture(event.pointerId)
    } catch {
      // Capture was never taken, or the element is already detached.
    }
  }

  /**
   * The resize edge from the keyboard.
   *
   * Grow and shrink rather than left and right: which arrow enlarges the panel
   * depends on which edge it is docked to, and a role that claims an operation
   * it only supports through `pointerdown` is a worse lie than no role at all.
   */
  const onResizeKeyDown = (event: React.KeyboardEvent) => {
    const grows = dock === 'bottom' || dock === 'right' ? -1 : 1
    const step = event.key === 'PageUp' || event.key === 'PageDown' ? KEY_RESIZE_STEP * 10 : KEY_RESIZE_STEP
    let direction = 0
    if (event.key === 'ArrowUp' || event.key === 'ArrowLeft' || event.key === 'PageUp') direction = grows
    else if (event.key === 'ArrowDown' || event.key === 'ArrowRight' || event.key === 'PageDown') direction = -grows
    else if (event.key === 'Home') {
      event.preventDefault()
      return setSize(clamp(MIN_SIZE))
    } else if (event.key === 'End') {
      event.preventDefault()
      return setSize(clamp(Number.POSITIVE_INFINITY))
    }
    if (direction === 0) return
    event.preventDefault()
    setSize((current) => clamp(current + direction * step))
  }

  const cycleDock = () => {
    const next = DOCKS[(DOCKS.indexOf(dock) + 1) % DOCKS.length]
    // A `readonly` index is `T | undefined` under `noUncheckedIndexedAccess`;
    // the modulo makes it always defined, so the guard costs nothing.
    if (next !== undefined) setDock(next)
  }

  const isHorizontal = dock === 'left' || dock === 'right'

  return (
    <>
      {!hideButton && buttonPosition !== 'relative' && (
        <div className={cn('z-[2147483000]', LAUNCHER_CLASS[buttonPosition], open && 'hidden')}>
          <TooltipProvider delayDuration={300}>
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  aria-expanded={open}
                  aria-label="Open duck-iam devtools"
                  className="size-10 rounded-full shadow-lg"
                  onClick={() => setOpen(true)}
                  ref={launcherRef}
                  size="icon"
                  variant="default">
                  <ShieldCheck />
                </Button>
              </TooltipTrigger>
              <TooltipContent className="px-2 py-1 text-xs">duck-iam devtools</TooltipContent>
            </Tooltip>
          </TooltipProvider>
        </div>
      )}

      {open && (
        <div
          aria-labelledby={titleId}
          className={cn(
            'fixed z-[2147483000] flex flex-col overflow-hidden border-border bg-background shadow-2xl',
            DOCK_CLASS[dock],
          )}
          ref={panelRef}
          role="dialog"
          style={isHorizontal ? { width: size } : { height: size }}
          tabIndex={-1}>
          {/* biome-ignore lint/a11y/useSemanticElements: `<hr>` is the thematic-break separator; this is the focusable window-splitter variant of the role, which has no element form. */}
          <div
            aria-label="Resize devtools panel"
            aria-orientation={isHorizontal ? 'vertical' : 'horizontal'}
            aria-valuemax={Math.round(maxSize)}
            aria-valuemin={MIN_SIZE}
            aria-valuenow={Math.round(size)}
            className={cn(
              'absolute z-10 bg-transparent transition-colors hover:bg-primary/40 focus-visible:bg-primary/60 focus-visible:outline-none',
              HANDLE_CLASS[dock],
            )}
            onKeyDown={onResizeKeyDown}
            onPointerCancel={onPointerUp}
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            role="separator"
            tabIndex={0}
          />

          <TooltipProvider delayDuration={300}>
            <header className="flex h-11 shrink-0 items-center gap-2 border-border border-b bg-card px-3">
              <ShieldCheck aria-hidden className="size-4 text-primary" />
              <span className="font-semibold text-sm" id={titleId}>
                duck-iam
              </span>
              <Badge className="font-normal" size="sm" variant="secondary">
                devtools v2
              </Badge>
              <Separator className="h-4" orientation="vertical" />
              <IamV2Chip className="rounded-full uppercase tracking-wider" mono={false} tone="allow">
                <span aria-hidden className="size-1.5 animate-pulse rounded-full bg-emerald-500" />
                live
              </IamV2Chip>
              <div className="ms-auto flex items-center gap-1">
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button className="h-7 gap-1.5 px-2 text-xs" onClick={cycleDock} size="sm" variant="ghost">
                      <LayoutPanelLeft size={12} />
                      {dock}
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent className="px-2 py-1 text-xs">{`Docked ${dock} — click to move`}</TooltipContent>
                </Tooltip>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      aria-label="Close devtools"
                      className="size-7"
                      onClick={() => {
                        setOpen(false)
                        launcherRef.current?.focus()
                      }}
                      size="icon-sm"
                      variant="ghost">
                      <X size={13} />
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent className="flex items-center gap-1.5 px-2 py-1 text-xs">
                    Close
                    <Kbd className="h-4 px-1 text-[0.625rem]">Esc</Kbd>
                  </TooltipContent>
                </Tooltip>
              </div>
            </header>
          </TooltipProvider>

          <div className="flex min-h-0 flex-1 flex-col">
            <IamDevtoolsInnerV2 {...inner} embedded />
          </div>
        </div>
      )}
    </>
  )
}
