import React from 'react'
import { Close } from './components/icons'
import { Button } from './components/ui'
import { IamDevtoolsInner, type IIamDevtoolsInnerProps } from './iam-devtools'
import { cn } from './lib/cn'
import { type IamDockPosition, useIamDockablePanel } from './lib/dockable-panel'
import { isDevtoolsAllowed } from './lib/guard'
import { GENTLEDUCK_LOGO_DATA_URL } from './lib/logo'
import { iamDevtoolsThemeAttr, useIamDevtoolsStyles } from './lib/styles'

/** Where the floating launcher sits; `'relative'` renders it in normal flow, e.g. inside your own toolbar. */
export type ButtonPosition = 'bottom-right' | 'bottom-left' | 'top-right' | 'top-left' | 'relative'
/** Which edge the panel docks to. Cycled through by the dock button in dock order. */
export type PanelPosition = IamDockPosition

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

  const {
    cycleDock,
    isHorizontal,
    launcherRef,
    maxSize,
    onDragEnd,
    onDragMove,
    onDragStart,
    onResizeKeyDown,
    open,
    panelRef: dockRef,
    position,
    setOpen,
    size,
  } = useIamDockablePanel({
    defaultSize: DEFAULT_SIZE,
    initialIsOpen,
    keyResizeStep: KEY_RESIZE_STEP,
    maxSizeFraction: MAX_SIZE_VW,
    minSize: MIN_SIZE,
    positionKeySuffix: '_POSITION',
    positionProp,
    storagePrefix,
  })

  const [mounted, setMounted] = React.useState<boolean>(open)
  const [animateIn, setAnimateIn] = React.useState<boolean>(false)
  const titleId = React.useId()

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

  // Opening moves focus into the panel, so the next Tab lands on the dock and
  // close controls rather than back at the top of the host page.
  React.useEffect(() => {
    if (open && mounted) dockRef.current?.focus()
  }, [open, mounted, dockRef])

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
